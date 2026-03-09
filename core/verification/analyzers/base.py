"""
BaseAnalyzer: Abstract interface for all forensic sub-analyzers.

Every sub-analyzer MUST inherit from this and implement `analyze()`.
This enables the compositor to treat all analyzers uniformly,
and makes it trivial to register new analyzers at runtime.
"""
import logging
from abc import ABC, abstractmethod
from typing import Any, Dict, List, Optional

from core.verification.models import LayerResult


class BaseAnalyzer(ABC):
    """
    Abstract base for forensic sub-analyzers.

    Each analyzer:
    - Has a unique `name` (used in LayerResult.layer_name)
    - Declares which file types it `supports`
    - Declares its `dependencies` (e.g., numpy, Pillow)
    - Implements `analyze()` to produce a LayerResult
    - Can report whether it's `available` (deps installed)
    """

    def __init__(self) -> None:
        self.logger = logging.getLogger(self.__class__.__name__)

    @property
    @abstractmethod
    def name(self) -> str:
        """Unique identifier for this analyzer (used in LayerResult)."""
        ...

    @property
    @abstractmethod
    def supported_types(self) -> List[str]:
        """File extensions this analyzer can process (e.g., ['jpg', 'png'])."""
        ...

    @property
    @abstractmethod
    def dependencies(self) -> List[str]:
        """Python packages this analyzer requires (e.g., ['numpy', 'Pillow'])."""
        ...

    @property
    def available(self) -> bool:
        """Whether all required dependencies are installed."""
        for dep in self.dependencies:
            try:
                __import__(dep.lower().replace("-", "_").replace("pillow", "PIL"))
            except ImportError:
                return False
        return True

    def supports(self, file_type: str) -> bool:
        """Whether this analyzer supports the given file type."""
        return file_type.lower().strip(".") in self.supported_types

    @abstractmethod
    async def analyze(
        self,
        file_bytes: bytes,
        file_type: str,
        image: Optional[Any] = None,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> LayerResult:
        """
        Run this analyzer on the given file.

        Args:
            file_bytes: Raw document bytes
            file_type: File extension (without dot)
            image: Pre-loaded PIL.Image (passed by compositor to avoid reloading)
            metadata: Optional externally provided metadata

        Returns: LayerResult with score, evidence, and warnings
        """
        ...

    def _unavailable_result(self, reason: str) -> LayerResult:
        """Returns a neutral result when deps are missing."""
        return LayerResult(
            layer_name=self.name,
            score=0.5,
            warnings=[f"{self.name}: {reason}"],
        )
