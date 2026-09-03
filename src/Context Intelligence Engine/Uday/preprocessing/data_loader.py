"""Memory-efficient data loader for CORTEX (Backward compatibility module).

This module re-exports CSVDataLoader from context_engine.data_loader for legacy imports.
"""

from context_engine.data_loader import CSVDataLoader

__all__ = ["CSVDataLoader"]
