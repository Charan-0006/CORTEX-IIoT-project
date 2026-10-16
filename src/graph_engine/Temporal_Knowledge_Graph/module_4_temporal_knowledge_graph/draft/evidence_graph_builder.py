"""Build an evidence-grounded event graph from processed ToN_IoT CSV files.

This module replaces the legacy positional schema-edge builder.
Each graph node represents a verified source record with exact provenance.
Edges are created only from:
  1) explicit network endpoint continuity (earlier dst_ip == later src_ip within same file),
  2) an exact shared identifier value within the same source CSV, ordered in time.

No LLM is used to create nodes or edges.
All relationships are candidate associations, not causal proofs.
"""
from __future__ import annotations

import hashlib
import json
import math
import re
from pathlib import Path
from typing import Any, Iterable

import pandas as pd

TIME_ALIASES = {
    "timestamp", "time", "ts", "datetime", "date", "event_time",
    "eventtime", "event_timestamp", "time_stamp"
}
SRC_IP_ALIASES = {
    "src_ip", "source_ip", "ip_src", "orig_h", "sourceip", "srcip",
    "srcipaddr", "source_address", "src_addr"
}
DST_IP_ALIASES = {
    "dst_ip", "dest_ip", "destination_ip", "ip_dst", "resp_h", "destinationip",
    "dstip", "dstipaddr", "destination_address", "dst_addr"
}
LABEL_ALIASES = {
    "label", "attack", "attack_label", "attack_type", "type", "class",
    "category", "malicious", "is_attack", "event_label"
}
IDENTIFIER_GROUPS = {
    "host": {"host", "hostname", "host_name", "machine", "machine_name", "asset", "asset_id", "computer"},
    "pid": {"pid", "process_id", "processid", "process_identifier", "id_process"},
    "user": {"user", "username", "user_name", "account", "account_name", "uid", "user_id"},
    "session": {"session", "session_id", "sessionid", "flow_id", "conn_id"},
    "device": {"device", "device_id", "deviceid", "thing_id", "sensor_id"},
    "command": {"cmd", "command", "process_name", "image"},
}
INVALID_VALUES = {"", "nan", "none", "null", "n/a", "na", "unknown", "-"}


def norm_col(value: Any) -> str:
    """Normalize a column label without losing its original spelling elsewhere."""
    return re.sub(r"[^a-z0-9]+", "_", str(value).strip().lower()).strip("_")


def find_column(columns: Iterable[str], aliases: set[str], contains: tuple[str, ...] = ()) -> str | None:
    pairs = [(str(c), norm_col(c)) for c in columns]
    for original, normalized in pairs:
        if normalized in aliases:
            return original
    for original, normalized in pairs:
        if any(term in normalized for term in contains):
            return original
    return None


def parse_time(value: Any) -> tuple[float | None, str | None]:
    """Parse common ToN_IoT timestamp formats; return UTC epoch and ISO string."""
    if value is None or (isinstance(value, float) and math.isnan(value)):
        return None, None
    raw = str(value).strip()
    if raw.lower() in INVALID_VALUES:
        return None, None
    try:
        number = float(raw)
        if number > 1e11:  # epoch milliseconds
            number /= 1000.0
        # Avoid interpreting short numeric IDs or 0/1 as epoch timestamps
        if number >= 1e8:
            ts = pd.to_datetime(number, unit="s", utc=True, errors="coerce")
            if not pd.isna(ts):
                return float(ts.timestamp()), ts.isoformat().replace("+00:00", "Z")
    except (ValueError, TypeError, OverflowError):
        pass

    # Try standard datetime strings
    ts = pd.to_datetime(raw, utc=True, errors="coerce", dayfirst=False)
    if pd.isna(ts):
        # ToN_IoT IoT date strings may use e.g. 02-Apr-19 or 31-Mar-19 12:36:52
        ts = pd.to_datetime(raw, utc=True, errors="coerce", dayfirst=True)
    if pd.isna(ts):
        # Specific custom fallback for DD-Mon-YY and DD-Mon-YY HH:MM:SS
        for fmt in ("%d-%b-%y %H:%M:%S", "%d-%b-%y", "%d-%b-%Y %H:%M:%S", "%d-%b-%Y"):
            try:
                dt = pd.to_datetime(raw, format=fmt, utc=True)
                return float(dt.timestamp()), dt.isoformat().replace("+00:00", "Z")
            except (ValueError, TypeError):
                continue
        return None, None
    return float(ts.timestamp()), ts.isoformat().replace("+00:00", "Z")


def clean_value(value: Any) -> str | None:
    if value is None:
        return None
    text = str(value).strip()
    if text.lower() in INVALID_VALUES:
        return None
    return text


def detect_columns(columns: Iterable[str]) -> dict[str, Any]:
    cols = list(columns)
    normalized_map = {norm_col(c): c for c in cols}

    # IoT datasets have separate 'date' and 'time' columns
    date_col = normalized_map.get("date")
    time_col_only = normalized_map.get("time")
    has_date_and_time = (date_col is not None and time_col_only is not None and date_col != time_col_only)

    if has_date_and_time:
        time_col = f"{date_col}+{time_col_only}"
    else:
        # Standard search for timestamp column
        time_col = find_column(cols, TIME_ALIASES, ("timestamp", "datetime"))

    src_col = find_column(cols, SRC_IP_ALIASES, ("src_ip", "source_ip", "orig_h"))
    dst_col = find_column(cols, DST_IP_ALIASES, ("dst_ip", "dest_ip", "resp_h"))

    # In ToN_IoT, 'type' gives the attack name (e.g. ddos, scanning), while 'label' gives 0/1.
    type_col = normalized_map.get("type")
    binary_label_col = normalized_map.get("label")
    label_col = type_col if type_col else (binary_label_col if binary_label_col else find_column(cols, LABEL_ALIASES))

    ids = {}
    reserved = {src_col, dst_col, label_col, binary_label_col, type_col, date_col, time_col_only}
    for group, aliases in IDENTIFIER_GROUPS.items():
        col = find_column(cols, aliases, (("process",) if group == "pid" else ()))
        if col and col not in reserved:
            ids[group] = col

    return {
        "time_col": time_col,
        "date_col": date_col,
        "time_col_only": time_col_only,
        "has_date_and_time": has_date_and_time,
        "src_ip_col": src_col,
        "dst_ip_col": dst_col,
        "label_col": label_col,
        "binary_label_col": binary_label_col,
        "type_col": type_col,
        "identifier_cols": ids,
    }


def _stable_event_id(relative_file: str, source_row: int) -> str:
    digest = hashlib.sha1(f"{relative_file}|{source_row}".encode("utf-8")).hexdigest()[:14]
    return f"evt_{digest}"


def load_events(data_root: Path, max_rows_per_file: int = 2000) -> tuple[pd.DataFrame, pd.DataFrame]:
    """Load a bounded prefix from each CSV and retain only useful event fields.

    max_rows_per_file=0 reads all rows. For this 31.8M-record dataset, start with
    the default bounded run; it is a smoke-test slice, not a full-corpus census.
    The manifest explicitly records the sampling policy.
    """
    data_root = Path(data_root)
    if not data_root.exists():
        raise FileNotFoundError(f"Dataset directory does not exist: {data_root}")
    csv_files = sorted(data_root.rglob("*.csv"))
    if not csv_files:
        raise FileNotFoundError(f"No CSV files found under: {data_root}")

    events: list[dict[str, Any]] = []
    file_stats: list[dict[str, Any]] = []
    for file_path in csv_files:
        try:
            relative = file_path.relative_to(data_root).as_posix()
            frame = pd.read_csv(file_path, nrows=max_rows_per_file if max_rows_per_file > 0 else None, low_memory=False)
            cols = detect_columns(frame.columns)
            loaded = len(frame)
            parsed_times = 0
            label_values: dict[str, int] = {}

            for offset, row in enumerate(frame.to_dict(orient="records"), start=2):
                if cols["has_date_and_time"]:
                    raw_date = clean_value(row.get(cols["date_col"]))
                    raw_time = clean_value(row.get(cols["time_col_only"]))
                    raw_ts = f"{raw_date} {raw_time}".strip() if (raw_date or raw_time) else None
                else:
                    raw_ts = row.get(cols["time_col"]) if cols["time_col"] else None

                epoch, iso = parse_time(raw_ts)
                parsed_times += int(epoch is not None)

                # Prioritize informative attack type, fallback to binary label
                label = None
                if cols["type_col"]:
                    type_val = clean_value(row.get(cols["type_col"]))
                    if type_val and type_val.lower() != "normal":
                        label = type_val
                    elif type_val:
                        label = "normal"
                if not label and cols["label_col"]:
                    lbl_val = clean_value(row.get(cols["label_col"]))
                    label = lbl_val

                if label:
                    label_values[label] = label_values.get(label, 0) + 1

                src_ip = clean_value(row.get(cols["src_ip_col"])) if cols["src_ip_col"] else None
                dst_ip = clean_value(row.get(cols["dst_ip_col"])) if cols["dst_ip_col"] else None
                identifiers = {}
                for group, col in cols["identifier_cols"].items():
                    value = clean_value(row.get(col))
                    if value:
                        identifiers[group] = value

                events.append({
                    "event_id": _stable_event_id(relative, offset),
                    "source_file": relative,
                    "source_dataset": file_path.parent.name,
                    "source_row_number": offset,
                    "timestamp_raw": clean_value(raw_ts),
                    "timestamp_epoch": epoch,
                    "timestamp_utc": iso,
                    "src_ip": src_ip,
                    "dst_ip": dst_ip,
                    "label": label,
                    "identifiers_json": json.dumps(identifiers, sort_keys=True),
                    "identifier_count": len(identifiers),
                })

            file_stats.append({
                "source_file": relative,
                "file_size_bytes": file_path.stat().st_size,
                "rows_loaded": loaded,
                "timestamp_column": cols["time_col"],
                "timestamps_parsed": parsed_times,
                "timestamp_parse_rate": round(parsed_times / loaded, 6) if loaded else None,
                "src_ip_column": cols["src_ip_col"],
                "dst_ip_column": cols["dst_ip_col"],
                "label_column": cols["label_col"],
                "identifier_columns_json": json.dumps(cols["identifier_cols"], sort_keys=True),
                "label_counts_json": json.dumps(label_values, sort_keys=True),
                "load_status": "ok",
                "error": "",
            })
        except Exception as exc:
            file_stats.append({
                "source_file": str(file_path.relative_to(data_root)).replace("\\", "/"),
                "file_size_bytes": file_path.stat().st_size,
                "rows_loaded": 0,
                "timestamp_column": None, "timestamps_parsed": 0,
                "timestamp_parse_rate": None, "src_ip_column": None,
                "dst_ip_column": None, "label_column": None,
                "identifier_columns_json": "{}", "label_counts_json": "{}",
                "load_status": "error", "error": f"{type(exc).__name__}: {exc}",
            })

    return pd.DataFrame(events), pd.DataFrame(file_stats)


EDGE_COLUMNS = [
    "edge_id", "source_event_id", "target_event_id", "relationship_type",
    "evidence_type", "source_file", "matched_field", "matched_value",
    "source_timestamp_utc", "target_timestamp_utc", "delta_seconds",
    "temporal_order_valid", "causal_claim"
]


def build_evidence_edges(events: pd.DataFrame, max_successors_per_key: int = 3) -> pd.DataFrame:
    """Create time-ordered edges supported by exact field matches within each CSV."""
    if events.empty:
        return pd.DataFrame(columns=EDGE_COLUMNS)
    frame = events.copy()
    frame["_sort_epoch"] = pd.to_numeric(frame["timestamp_epoch"], errors="coerce")
    frame["_sort_row"] = pd.to_numeric(frame["source_row_number"], errors="coerce")
    frame = frame.sort_values(["source_file", "_sort_epoch", "_sort_row"], na_position="last", kind="stable")
    edges: list[dict[str, Any]] = []
    seen: set[tuple[str, str, str, str]] = set()

    def add_edge(a: dict[str, Any], b: dict[str, Any], rel: str, ev_type: str,
                 field: str, value: str, delta: float | None, order_valid: bool) -> None:
        key = (a["event_id"], b["event_id"], rel, field)
        if key in seen:
            return
        seen.add(key)
        edges.append({
            "edge_id": f"edge_{len(edges)+1:08d}",
            "source_event_id": a["event_id"],
            "target_event_id": b["event_id"],
            "relationship_type": rel,
            "evidence_type": ev_type,
            "source_file": a["source_file"],
            "matched_field": field,
            "matched_value": value,
            "source_timestamp_utc": a.get("timestamp_utc"),
            "target_timestamp_utc": b.get("timestamp_utc"),
            "delta_seconds": delta,
            "temporal_order_valid": order_valid,
            "causal_claim": False,
        })

    for file_name, group in frame.groupby("source_file", sort=False):
        records = group.to_dict(orient="records")

        # Network endpoint continuity: event A destination equals event B source.
        src_index: dict[str, list[dict[str, Any]]] = {}
        for rec in records:
            src = clean_value(rec.get("src_ip"))
            if src:
                src_index.setdefault(src, []).append(rec)

        for a in records:
            dst = clean_value(a.get("dst_ip"))
            ta = a.get("_sort_epoch")
            if not dst or pd.isna(ta):
                continue
            candidates = src_index.get(dst, [])
            count = 0
            for b in candidates:
                tb = b.get("_sort_epoch")
                if pd.isna(tb):
                    continue
                # Enforce strict chronological progression
                if (tb, b.get("_sort_row")) <= (ta, a.get("_sort_row")):
                    continue
                delta = float(tb - ta)
                order_valid = (tb >= ta)
                add_edge(a, b, "NETWORK_HOP_CANDIDATE", "exact_destination_to_source_ip_match",
                         "dst_ip==src_ip", dst, delta, order_valid)
                count += 1
                if count >= max_successors_per_key:
                    break

        # Generic shared identifier association, within this file only.
        for group_name in ("host", "pid", "user", "session", "device", "command"):
            key_to_records: dict[str, list[dict[str, Any]]] = {}
            for rec in records:
                try:
                    identifiers = json.loads(rec.get("identifiers_json") or "{}")
                except (ValueError, TypeError):
                    identifiers = {}
                value = clean_value(identifiers.get(group_name))
                if value:
                    key_to_records.setdefault(value, []).append(rec)

            for value, observations in key_to_records.items():
                observations.sort(key=lambda r: (
                    float("inf") if pd.isna(r.get("_sort_epoch")) else float(r["_sort_epoch"]),
                    float("inf") if pd.isna(r.get("_sort_row")) else float(r["_sort_row"])
                ))
                for a, b in zip(observations, observations[1:]):
                    ta, tb = a.get("_sort_epoch"), b.get("_sort_epoch")
                    if not pd.isna(ta) and not pd.isna(tb):
                        delta = float(tb - ta)
                        order_valid = (tb >= ta)
                    else:
                        delta = None
                        order_valid = False  # Missing timestamps cannot be chronologically verified

                    add_edge(a, b, "TEMPORAL_SHARED_IDENTIFIER_ASSOCIATION",
                             "exact_shared_identifier_within_source_file",
                             group_name, value, delta, order_valid)

    return pd.DataFrame(edges, columns=EDGE_COLUMNS) if edges else pd.DataFrame(columns=EDGE_COLUMNS)
