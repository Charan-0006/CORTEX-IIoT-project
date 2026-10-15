"""Contextual Intelligence Engine package for CORTEX.

Provides multi-source context extraction, standardized attribute mapping,
and dynamic context profile generation for security telemetry.
"""

from context_engine.context_attribute_repository import (
    ContextAttributeRepository,
    ContextDimension,
    ContextAttribute,
)
from context_engine.context_extraction import (
    StructuredContext,
    BaseContextExtractor,
    NetworkContextExtractor,
    IoTContextExtractor,
    LinuxContextExtractor,
    WindowsContextExtractor,
    MultiSourceContextExtractor,
)
from context_engine.context_profile import (
    DynamicContextProfile,
    DeviationReport,
    ProfileStorageInterface,
    InMemoryProfileStorage,
    DynamicContextProfileGenerator,
    derive_profile_key,
    derive_profile_entity_type,
)
from context_engine.data_loader import CSVDataLoader

__all__ = [
    "ContextAttributeRepository",
    "ContextDimension",
    "ContextAttribute",
    "StructuredContext",
    "BaseContextExtractor",
    "NetworkContextExtractor",
    "IoTContextExtractor",
    "LinuxContextExtractor",
    "WindowsContextExtractor",
    "MultiSourceContextExtractor",
    "DynamicContextProfile",
    "DeviationReport",
    "ProfileStorageInterface",
    "InMemoryProfileStorage",
    "DynamicContextProfileGenerator",
    "derive_profile_key",
    "derive_profile_entity_type",
    "CSVDataLoader",
]
