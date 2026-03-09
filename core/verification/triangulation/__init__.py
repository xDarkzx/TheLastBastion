"""
Logic Triangulation base classes and strategy interface.

Each triangulation strategy implements BaseTriangulator:
- Domain Logic: checks claims against real-world rules
- Temporal Consistency: checks against historical patterns
- Cross-Reference: checks against our own verified data
- API Verification: checks against authoritative APIs
- Web Corroboration: checks against live web sources
"""
import logging
from abc import ABC, abstractmethod
from typing import Any, Dict, List, Optional

from core.verification.models import DataClaim, Evidence, LayerResult


class BaseTriangulator(ABC):
    """
    Abstract interface for logic triangulation strategies.

    Each strategy attempts to verify or disprove a DataClaim
    by checking it against a different type of knowledge source.
    """

    def __init__(self) -> None:
        self.logger = logging.getLogger(self.__class__.__name__)

    @property
    @abstractmethod
    def name(self) -> str:
        """Unique identifier for this strategy."""
        ...

    @property
    @abstractmethod
    def description(self) -> str:
        """Human-readable description of what this strategy checks."""
        ...

    @abstractmethod
    async def check(
        self,
        claims: List[DataClaim],
        context: Optional[Dict[str, Any]] = None,
    ) -> LayerResult:
        """
        Runs this triangulation strategy against all claims.

        Args:
            claims: Data claims to verify
            context: Domain context (industry, region, etc.)

        Returns: LayerResult with verification evidence
        """
        ...
