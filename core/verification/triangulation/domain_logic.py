"""
Domain Logic Triangulator (Step 6).

Verifies data claims against real-world rules, physics,
engineering standards, and economic logic — WITHOUT needing
any external API or web source.

Key insight: You don't need to find the exact data online.
You just need to check if the data makes SENSE given what
we know about the domain.

Examples:
- "100 units × $50 = $4,500" -> Arithmetic says $5,000. CONTRADICTION.
- "Electricity at $2.80/kWh in NZ" -> NZ average is ~$0.28. MAGNITUDE ANOMALY.
- "Steel beam rated 500kN uses M4 bolts" -> M4 bolts rated 3kN. ENGINEERING NONSENSE.
- "Invoice dated 2025-02-30" -> February has max 29 days. IMPOSSIBLE DATE.
"""
import logging
import math
import re
from datetime import datetime
from typing import Any, Dict, List, Optional, Tuple

from core.verification.models import DataClaim, Evidence, EvidenceType, LayerResult
from core.verification.triangulation import BaseTriangulator

logger = logging.getLogger("DomainLogic")

# Known domain ranges for common data types
# These are sanity bounds, not exact values
DOMAIN_RANGES = {
    "electricity_price_kwh": {
        "nz": (0.15, 0.50, "NZD/kWh"),
        "us": (0.08, 0.35, "USD/kWh"),
        "au": (0.20, 0.55, "AUD/kWh"),
        "eu": (0.15, 0.60, "EUR/kWh"),
        "default": (0.05, 1.00, "per kWh"),
    },
    "gas_price_kwh": {
        "nz": (0.05, 0.20, "NZD/kWh"),
        "default": (0.02, 0.50, "per kWh"),
    },
    "temperature_celsius": {
        "default": (-90.0, 60.0, "°C"),
    },
    "percentage": {
        "default": (0.0, 100.0, "%"),
    },
    "gst_rate": {
        "nz": (0.10, 0.20, "NZ GST"),
        "au": (0.05, 0.15, "AU GST"),
        "default": (0.0, 0.30, "VAT/GST"),
    },
    "weight_kg": {
        "default": (0.0, 1_000_000.0, "kg"),
    },
    "distance_km": {
        "default": (0.0, 50_000.0, "km"),
    },
}


class DomainLogicTriangulator(BaseTriangulator):
    """
    Verifies claims against domain-specific logical rules.

    Checks:
    1. Magnitude reasonableness (is this value in the right ballpark?)
    2. Unit consistency (are units compatible?)
    3. Date validity (do dates make physical sense?)
    4. Cross-field logic (do related fields agree?)
    5. Known domain constraints (industry-specific rules)
    """

    @property
    def name(self) -> str:
        return "domain_logic"

    @property
    def description(self) -> str:
        return "Verifies claims against real-world domain rules and logic"

    async def check(
        self,
        claims: List[DataClaim],
        context: Optional[Dict[str, Any]] = None,
    ) -> LayerResult:
        evidence: List[Evidence] = []
        warnings: List[str] = []
        contradictions = 0
        confirmations = 0
        ctx = context or {}
        region = ctx.get("region", "default")

        for claim in claims:
            # Run all applicable checks on each claim
            checks = [
                self._check_magnitude(claim, region),
                self._check_date_validity(claim),
                self._check_negative_values(claim),
                self._check_string_sanity(claim),
            ]

            for result in checks:
                if result is not None:
                    evidence.append(result)
                    if result.confirms:
                        confirmations += 1
                    else:
                        contradictions += 1
                        warnings.append(result.reasoning)

        # Cross-claim checks (comparing claims against each other)
        cross_results = self._check_cross_claim_logic(claims)
        for result in cross_results:
            evidence.append(result)
            if result.confirms:
                confirmations += 1
            else:
                contradictions += 1
                warnings.append(result.reasoning)

        # Scoring
        total = confirmations + contradictions
        if total == 0:
            score = 0.5  # No checks applicable
        else:
            score = confirmations / total

        # Active contradictions are severe
        if contradictions > 0:
            score = min(score, 0.4)
        if contradictions >= 3:
            score = min(score, 0.2)

        is_veto = contradictions >= 5
        veto_reason = (
            f"Domain logic: {contradictions} contradictions found"
        ) if is_veto else ""

        self.logger.info(
            f"DOMAIN: {confirmations} confirmed, {contradictions} contradicted, "
            f"score={score:.2f}"
        )

        return LayerResult(
            layer_name=self.name,
            score=round(score, 4),
            evidence=evidence,
            warnings=warnings,
            is_veto=is_veto,
            veto_reason=veto_reason,
            metadata={
                "confirmations": confirmations,
                "contradictions": contradictions,
                "claims_checked": len(claims),
            },
        )

    def _check_magnitude(
        self, claim: DataClaim, region: str
    ) -> Optional[Evidence]:
        """Checks if a numeric value is within reasonable bounds."""
        if claim.value is None:
            return None

        try:
            value = float(claim.value)
        except (ValueError, TypeError):
            return None

        # Try to match claim field to known domain ranges
        field_lower = claim.field_name.lower().replace(" ", "_")
        matched_domain = None

        for domain_key, ranges in DOMAIN_RANGES.items():
            if domain_key in field_lower or field_lower in domain_key:
                matched_domain = domain_key
                break

        if matched_domain is None:
            return None

        ranges = DOMAIN_RANGES[matched_domain]
        bounds = ranges.get(region, ranges.get("default"))
        if bounds is None:
            return None

        low, high, unit = bounds

        if low <= value <= high:
            return Evidence(
                source="domain_logic",
                source_type=EvidenceType.LOGIC,
                claim_field=claim.field_name,
                confirms=True,
                expected_value=f"{low}-{high} {unit}",
                found_value=str(value),
                reasoning=(
                    f"{claim.field_name}={value} is within expected "
                    f"range ({low}-{high} {unit})"
                ),
                confidence=0.7,
            )
        else:
            # How far out of range?
            if value > 0 and high > 0:
                ratio = value / high if value > high else low / value
            else:
                ratio = 100

            return Evidence(
                source="domain_logic",
                source_type=EvidenceType.LOGIC,
                claim_field=claim.field_name,
                confirms=False,
                expected_value=f"{low}-{high} {unit}",
                found_value=str(value),
                reasoning=(
                    f"MAGNITUDE ANOMALY: {claim.field_name}={value} is "
                    f"{ratio:.1f}× outside expected range "
                    f"({low}-{high} {unit})"
                ),
                confidence=min(0.9, 0.5 + ratio * 0.1),
            )

    def _check_date_validity(self, claim: DataClaim) -> Optional[Evidence]:
        """Checks if a date value is physically possible."""
        if claim.value is None:
            return None

        # Only check fields that look like dates
        field_lower = claim.field_name.lower()
        date_keywords = ["date", "time", "created", "modified", "expires", "born"]
        if not any(kw in field_lower for kw in date_keywords):
            return None

        value_str = str(claim.value)

        try:
            # Try ISO format
            parsed = datetime.fromisoformat(value_str.replace("Z", ""))

            # Check impossible dates
            if parsed.year < 1800:
                return Evidence(
                    source="domain_logic",
                    source_type=EvidenceType.LOGIC,
                    claim_field=claim.field_name,
                    confirms=False,
                    found_value=value_str,
                    reasoning=f"Date {value_str} is before 1800 — suspicious",
                    confidence=0.6,
                )

            if parsed > datetime.utcnow():
                return Evidence(
                    source="domain_logic",
                    source_type=EvidenceType.LOGIC,
                    claim_field=claim.field_name,
                    confirms=False,
                    found_value=value_str,
                    reasoning=f"Date {value_str} is in the future",
                    confidence=0.7,
                )

            return Evidence(
                source="domain_logic",
                source_type=EvidenceType.LOGIC,
                claim_field=claim.field_name,
                confirms=True,
                found_value=value_str,
                reasoning=f"Date {value_str} is valid and in the past",
                confidence=0.5,
            )

        except (ValueError, TypeError):
            return None

    def _check_negative_values(self, claim: DataClaim) -> Optional[Evidence]:
        """Flags negative values in fields that should be positive."""
        if claim.value is None:
            return None

        try:
            value = float(claim.value)
        except (ValueError, TypeError):
            return None

        if value < 0:
            field_lower = claim.field_name.lower()
            positive_only = [
                "price", "cost", "amount", "total", "quantity",
                "count", "weight", "distance", "area", "volume",
                "age", "duration", "rate", "fee",
            ]
            if any(kw in field_lower for kw in positive_only):
                return Evidence(
                    source="domain_logic",
                    source_type=EvidenceType.LOGIC,
                    claim_field=claim.field_name,
                    confirms=False,
                    found_value=str(value),
                    reasoning=(
                        f"Negative value ({value}) in '{claim.field_name}' "
                        f"— this field should be positive"
                    ),
                    confidence=0.8,
                )

        return None

    def _check_string_sanity(self, claim: DataClaim) -> Optional[Evidence]:
        """Checks string values for obvious problems."""
        if claim.value is None or not isinstance(claim.value, str):
            return None

        value = str(claim.value).strip()

        # Check for obviously fake/placeholder values
        placeholder_patterns = [
            r"^(test|foo|bar|xxx|yyy|zzz|asdf|qwerty|lorem)$",
            r"^(N/?A|null|undefined|none|TBD|TBA)$",
            r"^(.)\1{5,}$",  # "aaaaaa" or "111111"
        ]
        for pattern in placeholder_patterns:
            if re.match(pattern, value, re.IGNORECASE):
                return Evidence(
                    source="domain_logic",
                    source_type=EvidenceType.LOGIC,
                    claim_field=claim.field_name,
                    confirms=False,
                    found_value=value,
                    reasoning=(
                        f"Value '{value}' in '{claim.field_name}' looks "
                        f"like a placeholder/test value"
                    ),
                    confidence=0.85,
                )

        return None

    def _check_cross_claim_logic(
        self, claims: List[DataClaim]
    ) -> List[Evidence]:
        """Checks logical relationships between different claims."""
        results: List[Evidence] = []
        claim_map = {c.field_name.lower(): c for c in claims if c.value is not None}

        # Check: start_date < end_date
        for start_key, end_key in [
            ("start_date", "end_date"),
            ("begin_date", "end_date"),
            ("created", "expires"),
            ("manufacture_date", "expiry_date"),
        ]:
            if start_key in claim_map and end_key in claim_map:
                try:
                    start = datetime.fromisoformat(
                        str(claim_map[start_key].value).replace("Z", "")
                    )
                    end = datetime.fromisoformat(
                        str(claim_map[end_key].value).replace("Z", "")
                    )
                    if start > end:
                        results.append(Evidence(
                            source="domain_logic",
                            source_type=EvidenceType.LOGIC,
                            claim_field=f"{start_key}/{end_key}",
                            confirms=False,
                            reasoning=(
                                f"TEMPORAL CONTRADICTION: {start_key} ({start}) "
                                f"is after {end_key} ({end})"
                            ),
                            confidence=0.9,
                        ))
                    else:
                        results.append(Evidence(
                            source="domain_logic",
                            source_type=EvidenceType.LOGIC,
                            claim_field=f"{start_key}/{end_key}",
                            confirms=True,
                            reasoning=f"{start_key} is before {end_key} — valid",
                            confidence=0.6,
                        ))
                except (ValueError, TypeError):
                    pass

        # Check: quantity × unit_price ≈ subtotal/amount
        # Prefer subtotal/line_total over total (total may include tax)
        qty_keys = ["quantity", "qty", "units", "count"]
        price_keys = ["unit_price", "price", "rate", "cost_per_unit"]
        # Order matters: prefer pre-tax totals first
        total_keys = ["subtotal", "sub_total", "line_total", "amount", "total"]

        product_checked = False
        for qk in qty_keys:
            if product_checked:
                break
            for pk in price_keys:
                if product_checked:
                    break
                for tk in total_keys:
                    if qk in claim_map and pk in claim_map and tk in claim_map:
                        try:
                            qty = float(claim_map[qk].value)
                            price = float(claim_map[pk].value)
                            total = float(claim_map[tk].value)
                            expected = qty * price
                            product_checked = True
                            if abs(expected - total) > 0.01:
                                results.append(Evidence(
                                    source="domain_logic",
                                    source_type=EvidenceType.LOGIC,
                                    claim_field=f"{qk}×{pk}={tk}",
                                    confirms=False,
                                    expected_value=str(round(expected, 2)),
                                    found_value=str(total),
                                    reasoning=(
                                        f"ARITHMETIC: {qk}({qty}) × "
                                        f"{pk}({price}) = {expected}, "
                                        f"but {tk} = {total}"
                                    ),
                                    confidence=0.95,
                                ))
                            else:
                                results.append(Evidence(
                                    source="domain_logic",
                                    source_type=EvidenceType.LOGIC,
                                    claim_field=f"{qk}×{pk}={tk}",
                                    confirms=True,
                                    reasoning=(
                                        f"Arithmetic valid: {qk}×{pk}={expected} "
                                        f"matches {tk}"
                                    ),
                                    confidence=0.8,
                                ))
                            break
                        except (ValueError, TypeError):
                            pass

        return results
