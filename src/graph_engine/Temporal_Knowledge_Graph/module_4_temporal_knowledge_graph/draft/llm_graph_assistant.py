"""Optional local Ollama explanation helper. It cannot add or modify graph edges."""
from __future__ import annotations

import json
import re
import urllib.error
import urllib.request
from typing import Any


def check_ollama_status(endpoint: str = "http://localhost:11434/api/tags") -> bool:
    """Check if the local Ollama daemon is reachable."""
    try:
        req = urllib.request.Request(endpoint, method="GET")
        with urllib.request.urlopen(req, timeout=3) as resp:
            return resp.status == 200
    except Exception:
        return False


def explain_candidate_paths(paths: list[dict[str, Any]], model: str = "qwen3.5:9b",
                            endpoint: str = "http://localhost:11434/api/chat",
                            timeout_seconds: int = 120) -> dict[str, Any]:
    """Ask a local Ollama model to explain supplied path records in constrained JSON."""
    if not paths:
        return {"status": "skipped", "model": model, "reason": "No candidate paths provided for explanation."}

    compact_paths = []
    for path in paths[:5]:  # Bounded to top 5 paths to keep prompt bounded for 16 GB CPU inference
        compact_paths.append({
            "path_id": path.get("path_id"),
            "start_event_id": path.get("start_event_id"),
            "end_event_id": path.get("end_event_id"),
            "hop_count": path.get("hop_count"),
            "start_timestamp_utc": path.get("start_timestamp_utc"),
            "end_timestamp_utc": path.get("end_timestamp_utc"),
            "duration_seconds": path.get("duration_seconds"),
            "attack_label": path.get("attack_label"),
            "relationship_types": path.get("relationship_types"),
            "source_files": path.get("source_files"),
            "interpretation": path.get("interpretation"),
        })

    prompt = (
        "You are an evidence-constrained cybersecurity graph analyst. Explain only the "
        "provided candidate paths. Do not invent entities, edges, timestamps, or facts. "
        "A path is not proof of causality or compromise. Return JSON with keys: "
        "summary (string), path_assessments (array of objects with path_id, evidence_summary, "
        "limitations, suggested_followup_event_ids). Any suggested event ID must be copied "
        "from the supplied paths. If evidence is insufficient, say so. Input paths:\n"
        + json.dumps(compact_paths, ensure_ascii=False)
    )

    payload = {
        "model": model,
        "stream": False,
        "format": "json",
        "messages": [
            {"role": "system", "content": "Return valid JSON only. Never claim causal certainty. Only cite supplied event IDs."},
            {"role": "user", "content": prompt},
        ],
        "options": {"temperature": 0.1, "num_ctx": 4096},
    }

    request = urllib.request.Request(
        endpoint,
        data=json.dumps(payload).encode("utf-8"),
        headers={"Content-Type": "application/json"},
        method="POST"
    )

    try:
        with urllib.request.urlopen(request, timeout=timeout_seconds) as response:
            body = json.loads(response.read().decode("utf-8"))

        content = body.get("message", {}).get("content", "").strip()

        # Strip optional markdown code fences if output by LLM
        if content.startswith("```"):
            content = re.sub(r"^```[a-zA-Z]*\s*", "", content)
            content = re.sub(r"\s*```$", "", content).strip()

        parsed = json.loads(content)

        # Enforce that suggested event IDs only reference authentic input events
        valid_event_ids = {
            str(p.get("start_event_id")) for p in compact_paths
        } | {
            str(p.get("end_event_id")) for p in compact_paths
        }

        for item in parsed.get("path_assessments", []):
            item["suggested_followup_event_ids"] = [
                event_id for event_id in item.get("suggested_followup_event_ids", [])
                if str(event_id) in valid_event_ids
            ]

        return {"status": "ok", "model": model, "response": parsed}
    except (urllib.error.URLError, TimeoutError, json.JSONDecodeError, KeyError, TypeError) as exc:
        return {"status": "error", "model": model, "error": f"{type(exc).__name__}: {exc}"}
