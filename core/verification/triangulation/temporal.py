"""
Temporal Consistency Triangulator (Step 7).

Verifies data by comparing it against historical patterns.
If we've seen data for this domain before, we can check if
the new data is consistent with historical trends.

Examples:
- Price 5% different from last month -> Normal
- Price 500% different from last month -> Suspicious
- First submission for this domain -> Neutral (no history)
- Matches seasonal pattern -> Confidence boost
"""
import logging
import math
from datetime import datetime, timedelta
from typing import Any, Dict, List, Optional

from core.verification.models import DataClaim, Evidence, EvidenceType, LayerResult
from core.verification.triangulation import BaseTriangulator

logger = logging.getLogger("TemporalConsistency")


class TemporalConsistencyTriangulator(BaseTriangulator):
    """
    Checks submitted claims against historical data patterns.

    Uses an in-memory history store (injectable) to compare
    new values against known previous values for the same domain.
    """

    # Maximum percentage change before flagging (per field type)
    CHANGE_THRESHOLDS = {
        "price": 0.50,       # 50% change is suspicious
        "rate": 0.30,        # 30% rate change is suspicious
        "quantity": 1.00,    # 100% quantity change is borderline
        "default": 0.80,     # 80% change for unknown fields
    }

    def __init__(
        self,
        history_store: Optional[Dict[str, List[Dict[str, Any]]]] = None,
    ) -> None:
        super().__init__()
        # History store: domain -> list of {field, value, timestamp}
        self._history = history_store or {}

    @property
    def name(self) -> str:
        return "temporal_consistency"

    @property
    def description(self) -> str:
        return "Compares claims against historical submission patterns"

    def record_history(
        self, domain: str, field: str, value: float, timestamp: Optional[datetime] = None
    ) -> None:
        """Records a verified value for future temporal comparisons."""
        ts = timestamp or datetime.utcnow()
        if domain not in self._history:
            self._history[domain] = []
        self._history[domain].append({
            "field": field,
            "value": value,
            "timestamp": ts.isoformat(),
        })

    async def check(
        self,
        claims: List[DataClaim],
        context: Optional[Dict[str, Any]] = None,
    ) -> LayerResult:
        evidence: List[Evidence] = []
        warnings: List[str] = []
        ctx = context or {}
        domain = ctx.get("domain", "unknown")

        history = self._history.get(domain, [])

        if not history:
            self.logger.info(
                f"TEMPORAL: No history for domain '{domain}' — neutral"
            )
            return LayerResult(
                layer_name=self.name,
                score=0.5,
                evidence=[Evidence(
                    source="temporal_consistency",
                    source_type=EvidenceType.TEMPORAL,
                    claim_field="all",
                    confirms=True,
                    reasoning=(
                        f"No historical data for domain '{domain}' — "
                        f"first submission, no comparison available"
                    ),
                    confidence=0.3,
                )],
                metadata={"historical_records": 0, "domain": domain},
            )

        confirmations = 0
        contradictions = 0

        for claim in claims:
            if claim.value is None:
                continue

            try:
                current_value = float(claim.value)
            except (ValueError, TypeError):
                continue

            # Find most recent historical value for this field
            field_history = [
                h for h in history
                if h["field"] == claim.field_name
            ]

            if not field_history:
                continue

            # Sort by timestamp descending
            field_history.sort(key=lambda h: h["timestamp"], reverse=True)
            latest = field_history[0]
            prev_value = float(latest["value"])

            if prev_value == 0:
                continue

            # Calculate percentage change
            pct_change = abs(current_value - prev_value) / abs(prev_value)

            # Get threshold for this field type
            threshold = self.CHANGE_THRESHOLDS.get("default", 0.80)
            for key, thresh in self.CHANGE_THRESHOLDS.items():
                if key in claim.field_name.lower():
                    threshold = thresh
                    break

            if pct_change <= threshold:
                confirmations += 1
                evidence.append(Evidence(
                    source="temporal_consistency",
                    source_type=EvidenceType.TEMPORAL,
                    claim_field=claim.field_name,
                    confirms=True,
                    expected_value=str(prev_value),
                    found_value=str(current_value),
                    reasoning=(
                        f"{claim.field_name}: {pct_change:.1%} change from "
                        f"previous ({prev_value} -> {current_value}) — "
                        f"within normal range"
                    ),
                    confidence=0.7,
                ))
            else:
                contradictions += 1
                evidence.append(Evidence(
                    source="temporal_consistency",
                    source_type=EvidenceType.TEMPORAL,
                    claim_field=claim.field_name,
                    confirms=False,
                    expected_value=str(prev_value),
                    found_value=str(current_value),
                    reasoning=(
                        f"TEMPORAL ANOMALY: {claim.field_name} changed "
                        f"{pct_change:.1%} ({prev_value} -> {current_value}) — "
                        f"exceeds {threshold:.0%} threshold"
                    ),
                    confidence=min(0.9, 0.5 + pct_change * 0.2),
                ))
                warnings.append(
                    f"{claim.field_name}: {pct_change:.1%} change from "
                    f"previous value"
                )

        # Scoring
        total = confirmations + contradictions
        if total == 0:
            score = 0.5
        else:
            score = confirmations / total
            if contradictions > 0:
                score = min(score, 0.4)

        self.logger.info(
            f"TEMPORAL: {confirmations} stable, {contradictions} anomalies, "
            f"domain='{domain}', score={score:.2f}"
        )

        return LayerResult(
            layer_name=self.name,
            score=round(score, 4),
            evidence=evidence,
            warnings=warnings,
            metadata={
                "historical_records": len(history),
                "confirmations": confirmations,
                "contradictions": contradictions,
                "domain": domain,
            },
        )
