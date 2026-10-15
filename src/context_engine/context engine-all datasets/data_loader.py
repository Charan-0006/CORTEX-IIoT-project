"""Memory-efficient data loader for CORTEX.

This module provides classes and utilities to load and stream records from
large CSV telemetry files of the TON-IoT dataset in a chunked, streaming fashion.
"""

import os
import logging
from typing import Generator, Dict, Any, Optional
import pandas as pd

logger = logging.getLogger("CORTEX.DataLoader")


class CSVDataLoader:
    """A data loader designed to stream records from large CSV files efficiently.

    Utilizes pandas chunking to avoid loading entire datasets into memory,
    which is critical for handling large TON-IoT network and OS logs.
    """

    def __init__(self, file_path: str) -> None:
        """Initializes the CSVDataLoader with a target file path.

        Args:
            file_path: Absolute or relative path to the target CSV file.

        Raises:
            FileNotFoundError: If the specified file does not exist.
        """
        if not os.path.exists(file_path):
            logger.error("File not found: %s", file_path)
            raise FileNotFoundError(f"The dataset file was not found: {file_path}")

        self.file_path = os.path.abspath(file_path)
        logger.info("Initialized CSVDataLoader for target file: %s", self.file_path)

    def stream_records(
        self, chunk_size: int = 10000, max_rows: Optional[int] = None
    ) -> Generator[Dict[str, Any], None, None]:
        """Streams records from the CSV file as individual dictionaries.

        Reads the CSV file in chunks, processes column names by stripping
        whitespace, and yields each row as a dictionary.

        Args:
            chunk_size: Number of rows to read per pandas chunk.
            max_rows: Optional upper limit on total rows to stream (useful for testing).

        Yields:
            A dictionary containing column names as keys and row entries as values.

        Raises:
            ValueError: If the file is empty or cannot be parsed.
        """
        logger.debug(
            "Starting streaming from %s (chunk_size=%d, max_rows=%s)",
            self.file_path,
            chunk_size,
            str(max_rows),
        )

        rows_yielded = 0
        try:
            chunks = pd.read_csv(self.file_path, chunksize=chunk_size, low_memory=False)

            for chunk in chunks:
                # Clean up column names: remove leading/trailing whitespaces
                chunk.columns = [str(col).strip() for col in chunk.columns]

                if chunk.empty:
                    continue

                for _, row in chunk.iterrows():
                    row_dict = row.to_dict()
                    cleaned_dict = {}
                    for k, v in row_dict.items():
                        if pd.isna(v):
                            cleaned_dict[k] = None
                        elif isinstance(v, str):
                            cleaned_dict[k] = v.strip()
                        else:
                            cleaned_dict[k] = v

                    yield cleaned_dict
                    rows_yielded += 1

                    if max_rows is not None and rows_yielded >= max_rows:
                        logger.info(
                            "Reached max_rows limit of %d. Terminating stream.", max_rows
                        )
                        return

        except Exception as e:
            logger.error("Failed to stream records from %s: %s", self.file_path, e)
            raise ValueError(f"Error reading CSV file at {self.file_path}: {e}") from e

        logger.info("Successfully finished streaming %d records.", rows_yielded)
