"""
Logic Triangulation Engine (Pillar 2 Compositor).

Orchestrates all triangulation strategies and produces a composite
PillarResult. Same pattern as ForensicIntegrityAnalyzer — each
strategy is independently testable and registered at runtime.
"""
import logging
from typing import Any, Dict, List, Optional

from core.verification.models import (
    DataClaim, Evidence, LayerResult, PillarResult,
)
from core.verification.triangulation import BaseTriangulator
from core.verification.triangulation.cross_reference import (
    CrossReferenceTriangulator,
)
from core.verification.triangulation.domain_logic import (
    DomainLogicTriangulator,
)
from core.verification.triangulation.temporal import (
    TemporalConsistencyTriangulator,
)

logger = logging.getLogger("LogicTriangulation")


class LogicTriangulationEngine:
    """
    Compositor that orchestrates all triangulation strategies.

    Routes DataClaims through registered strategies, collects
    evidence, and produces a composite PillarResult.

    Scoring follows the triangulation rules:
    - 0 sources confirm -> UNVERIFIABLE (0.0)
    - 1 source confirms, 0 contradict -> WEAK (0.40)
    - 2 sources confirm, 0 contradict -> STRONG (0.75)
    - 3+ sources confirm, 0 contradict -> VERY STRONG (0.90)
    - Any active contradiction -> caps score
    """

    def __init__(self) -> None:
        self._strategies: List[BaseTriangulator] = []
        self._register_defaults()

    def _register_defaults(self) -> None:
        """Registers all built-in triangulation strategies."""
        defaults = [
            DomainLogicTriangulator(),
            TemporalConsistencyTriangulator(),
            CrossReferenceTriangulator(),
        ]
        for strategy in defaults:
            self.register(strategy)

    def register(self, strategy: BaseTriangulator) -> None:
        """Registers a new triangulation strategy."""
        if not isinstance(strategy, BaseTriangulator):
            raise TypeError(
                f"Strategy must implement BaseTriangulator, "
                f"got {type(strategy).__name__}"
            )
        self._strategies.append(strategy)
        logger.debug(f"Registered strategy: {strategy.name}")

    @property
    def registered_strategies(self) -> List[str]:
        """Returns names of all registered strategies."""
        return [s.name for s in self._strategies]

    async def triangulate(
        self,
        claims: List[DataClaim],
        context: Optional[Dict[str, Any]] = None,
    ) -> PillarResult:
        """
        Runs all triangulation strategies on the given claims.

        Args:
            claims: Data claims to verify
            context: Domain context (region, domain name, etc.)

        Returns: PillarResult with triangulation evidence
        """
        if not claims:
            return PillarResult(
                pillar_name="logic_triangulation",
                score=0.5,
                layer_results=[LayerResult(
                    layer_name="no_claims",
                    score=0.5,
                    warnings=["No data claims to triangulate"],
                )],
            )

        layer_results: List[LayerResult] = []
        evidence_chain: List[Evidence] = []

        for strategy in self._strategies:
            try:
                result = await strategy.check(claims, context)
                layer_results.append(result)
                evidence_chain.extend(result.evidence)
            except Exception as e:
                logger.warning(f"Strategy '{strategy.name}' failed: {e}")
                layer_results.append(LayerResult(
                    layer_name=strategy.name,
                    score=0.5,
                    warnings=[f"Strategy error: {str(e)}"],
                ))

        # Compute composite score using corroboration logic
        total_confirmations = 0
        total_contradictions = 0
        for ev in evidence_chain:
            if ev.confirms:
                total_confirmations += 1
            else:
                total_contradictions += 1

        # Apply triangulation scoring rules
        score = self._compute_triangulation_score(
            total_confirmations, total_contradictions
        )

        # Layer average as secondary signal
        if layer_results:
            layer_avg = sum(lr.score for lr in layer_results) / len(layer_results)
            # Blend: 60% corroboration rules, 40% layer average
            score = score * 0.6 + layer_avg * 0.4

        is_veto = any(lr.is_veto for lr in layer_results)
        veto_reason = next(
            (lr.veto_reason for lr in layer_results if lr.is_veto), ""
        )
        if is_veto:
            score = min(score, 0.1)

        logger.info(
            f"TRIANGULATION: {total_confirmations} confirmations, "
            f"{total_contradictions} contradictions, "
            f"score={score:.2f}"
        )

        return PillarResult(
            pillar_name="logic_triangulation",
            score=round(score, 4),
            layer_results=layer_results,
            evidence_chain=evidence_chain,
            is_veto=is_veto,
            veto_reason=veto_reason,
        )

    def _compute_triangulation_score(
        self, confirmations: int, contradictions: int
    ) -> float:
        """Applies the triangulation scoring rules from the design."""
        if contradictions > 0 and confirmations > 0:
            return 0.20  # CONTESTED — quarantine
        elif contradictions > 0:
            return 0.00  # DISPROVED
        elif confirmations >= 3:
            return 0.90  # VERY STRONG
        elif confirmations == 2:
            return 0.75  # STRONG
        elif confirmations == 1:
            return 0.40  # WEAK
        else:
            return 0.00  # UNVERIFIABLE
