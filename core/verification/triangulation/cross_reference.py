"""
Cross-Reference Triangulator (Step 7).

Checks submitted claims against our OWN verified data store.
If multiple independent sources have already confirmed the same value,
that's strong corroboration. If the new value contradicts existing
verified data, that's a red flag.

Scoring:
- 0 matches -> No corroboration (neutral)
- 1 match -> Weak corroboration
- 2 matches -> Strong corroboration
- 3+ matches -> Very strong
- Any contradiction with verified data -> Quarantine
"""
import logging
from typing import Any, Dict, List, Optional

from core.verification.models import DataClaim, Evidence, EvidenceType, LayerResult
from core.verification.triangulation import BaseTriangulator

logger = logging.getLogger("CrossReference")


class CrossReferenceTriangulator(BaseTriangulator):
    """
    Checks claims against our internal verified data store.

    The store is injectable — in production, this would query the
    database for previously verified data points.
    """

    def __init__(
        self,
        verified_store: Optional[Dict[str, List[Dict[str, Any]]]] = None,
    ) -> None:
        super().__init__()
        # Verified store: domain -> list of {field, value, source, confidence}
        self._verified = verified_store or {}

    @property
    def name(self) -> str:
        return "cross_reference"

    @property
    def description(self) -> str:
        return "Checks claims against previously verified internal data"

    def add_verified(
        self,
        domain: str,
        field: str,
        value: Any,
        source: str,
        confidence: float,
    ) -> None:
        """Adds a verified data point to the store."""
        if domain not in self._verified:
            self._verified[domain] = []
        self._verified[domain].append({
            "field": field,
            "value": value,
            "source": source,
            "confidence": confidence,
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

        verified = self._verified.get(domain, [])

        if not verified:
            return LayerResult(
                layer_name=self.name,
                score=0.5,
                evidence=[Evidence(
                    source="cross_reference",
                    source_type=EvidenceType.CROSS_REFERENCE,
                    claim_field="all",
                    confirms=True,
                    reasoning=(
                        f"No verified data for domain '{domain}' — "
                        f"first ingestion, no cross-references available"
                    ),
                    confidence=0.3,
                )],
                metadata={"verified_records": 0, "domain": domain},
            )

        confirmations = 0
        contradictions = 0

        for claim in claims:
            if claim.value is None:
                continue

            # Find matching verified records for this field
            matches = [
                v for v in verified
                if v["field"] == claim.field_name
            ]

            for match in matches:
                # Compare values
                try:
                    claim_val = float(claim.value)
                    match_val = float(match["value"])
                    tolerance = abs(match_val * 0.05)  # 5% tolerance

                    if abs(claim_val - match_val) <= tolerance:
                        confirmations += 1
                        evidence.append(Evidence(
                            source="cross_reference",
                            source_type=EvidenceType.CROSS_REFERENCE,
                            claim_field=claim.field_name,
                            confirms=True,
                            expected_value=str(match_val),
                            found_value=str(claim_val),
                            reasoning=(
                                f"Cross-ref MATCH: {claim.field_name}="
                                f"{claim_val} matches verified value "
                                f"{match_val} (source: {match['source']})"
                            ),
                            confidence=match["confidence"],
                        ))
                    else:
                        contradictions += 1
                        evidence.append(Evidence(
                            source="cross_reference",
                            source_type=EvidenceType.CROSS_REFERENCE,
                            claim_field=claim.field_name,
                            confirms=False,
                            expected_value=str(match_val),
                            found_value=str(claim_val),
                            reasoning=(
                                f"Cross-ref CONFLICT: {claim.field_name}="
                                f"{claim_val} contradicts verified value "
                                f"{match_val} (source: {match['source']})"
                            ),
                            confidence=match["confidence"],
                        ))
                        warnings.append(
                            f"{claim.field_name}: contradicts verified "
                            f"value from {match['source']}"
                        )

                except (ValueError, TypeError):
                    # String comparison
                    if str(claim.value).lower() == str(match["value"]).lower():
                        confirmations += 1
                        evidence.append(Evidence(
                            source="cross_reference",
                            source_type=EvidenceType.CROSS_REFERENCE,
                            claim_field=claim.field_name,
                            confirms=True,
                            reasoning=(
                                f"Cross-ref MATCH: {claim.field_name}="
                                f"'{claim.value}' matches verified "
                                f"(source: {match['source']})"
                            ),
                            confidence=match["confidence"],
                        ))

        # Scoring based on corroboration rules
        if contradictions > 0 and confirmations > 0:
            score = 0.2  # Contested — quarantine
        elif contradictions > 0:
            score = 0.1  # Contradicts verified data
        elif confirmations >= 3:
            score = 0.9  # Very strong corroboration
        elif confirmations == 2:
            score = 0.75  # Strong
        elif confirmations == 1:
            score = 0.6  # Weak but positive
        else:
            score = 0.5  # No matches found

        self.logger.info(
            f"XREF: {confirmations} confirmed, {contradictions} conflicted, "
            f"domain='{domain}', score={score:.2f}"
        )

        return LayerResult(
            layer_name=self.name,
            score=round(score, 4),
            evidence=evidence,
            warnings=warnings,
            metadata={
                "verified_records": len(verified),
                "confirmations": confirmations,
                "contradictions": contradictions,
                "domain": domain,
            },
        )
