"""
Internal Consistency Analyzer (Step 2): Verifies data makes sense internally.

Checks if the numbers add up, cross-field relationships are logical,
and values are statistically plausible — WITHOUT external sources.

This layer answers: "Does this data contradict itself?"
"""
import logging
import math
from datetime import datetime
from typing import Any, Dict, List, Optional, Tuple

from core.verification.models import (
    DataSchema, Evidence, EvidenceType, FieldSpec,
    FieldType, LayerResult
)

logger = logging.getLogger("ConsistencyAnalyzer")


class ConsistencyAnalyzer:
    """
    Analyzes internal consistency of data:
    - Mathematical relationships (subtotal + tax = total)
    - Cross-field logic (start < end, quantity * price = amount)
    - Statistical anomaly detection (magnitude reasonableness)
    - Unit consistency (all same currency, all same format)
    """

    def check(
        self,
        data: Dict[str, Any],
        schema: DataSchema,
        known_distributions: Optional[Dict[str, Dict[str, float]]] = None,
    ) -> LayerResult:
        """
        Runs all consistency checks.

        Args:
            data: The data to verify
            schema: Expected schema
            known_distributions: Optional dict of field_name -> {mean, std}
                for statistical anomaly detection

        Returns: LayerResult with consistency score
        """
        evidence: List[Evidence] = []
        warnings: List[str] = []
        anomalies: List[str] = []

        total_checks = 0
        passed_checks = 0

        # --- Check 1: Arithmetic Relationships ---
        arith_results = self._check_arithmetic(data)
        for ok, field_name, msg in arith_results:
            total_checks += 1
            if ok:
                passed_checks += 1
                evidence.append(Evidence(
                    source="consistency_analyzer",
                    source_type=EvidenceType.COMPUTATION,
                    claim_field=field_name,
                    confirms=True,
                    reasoning=f"Arithmetic check passed: {msg}",
                ))
            else:
                anomalies.append(msg)
                evidence.append(Evidence(
                    source="consistency_analyzer",
                    source_type=EvidenceType.COMPUTATION,
                    claim_field=field_name,
                    confirms=False,
                    reasoning=f"Arithmetic conflict: {msg}",
                ))

        # --- Check 2: Cross-Field Logic ---
        logic_results = self._check_cross_field_logic(data)
        for ok, field_name, msg in logic_results:
            total_checks += 1
            if ok:
                passed_checks += 1
            else:
                anomalies.append(msg)
                evidence.append(Evidence(
                    source="consistency_analyzer",
                    source_type=EvidenceType.COMPUTATION,
                    claim_field=field_name,
                    confirms=False,
                    reasoning=f"Logic conflict: {msg}",
                ))

        # --- Check 3: Statistical Anomaly Detection ---
        if known_distributions:
            stat_results = self._check_statistical_anomalies(
                data, known_distributions
            )
            for ok, field_name, msg, z_score in stat_results:
                total_checks += 1
                if ok:
                    passed_checks += 1
                else:
                    anomalies.append(msg)
                    evidence.append(Evidence(
                        source="consistency_analyzer",
                        source_type=EvidenceType.COMPUTATION,
                        claim_field=field_name,
                        confirms=False,
                        found_value=data.get(field_name),
                        reasoning=f"Statistical anomaly (z={z_score:.1f}): {msg}",
                    ))

        # --- Check 4: Magnitude Reasonableness ---
        magnitude_results = self._check_magnitude_reasonableness(data, schema)
        for ok, field_name, msg in magnitude_results:
            total_checks += 1
            if ok:
                passed_checks += 1
            else:
                warnings.append(msg)
                evidence.append(Evidence(
                    source="consistency_analyzer",
                    source_type=EvidenceType.COMPUTATION,
                    claim_field=field_name,
                    confirms=False,
                    found_value=data.get(field_name),
                    reasoning=f"Magnitude warning: {msg}",
                ))

        # --- Check 5: Duplicate Field Detection ---
        dup_results = self._check_duplicate_values(data)
        for ok, field_name, msg in dup_results:
            total_checks += 1
            if ok:
                passed_checks += 1
            else:
                warnings.append(msg)

        # --- Compute Score ---
        if total_checks == 0:
            # No consistency checks applicable — neutral score
            score = 0.5
            warnings.append("No consistency checks were applicable to this data")
        else:
            score = passed_checks / total_checks

        # Hard arithmetic failures are very bad
        has_arithmetic_failure = any(
            not ok for ok, _, msg in arith_results
            if "arithmetic" in msg.lower() or "math" in msg.lower()
        )
        if has_arithmetic_failure and score > 0.3:
            score = min(score, 0.3)
            anomalies.append("Arithmetic failure detected — score capped at 0.3")

        logger.info(
            f"CONSISTENCY: {passed_checks}/{total_checks} checks passed "
            f"(score={score:.2f}, anomalies={len(anomalies)})"
        )

        return LayerResult(
            layer_name="consistency_analyzer",
            score=round(score, 4),
            evidence=evidence,
            warnings=warnings,
            anomalies=anomalies,
            metadata={
                "total_checks": total_checks,
                "passed_checks": passed_checks,
                "arithmetic_checks": len(arith_results),
                "logic_checks": len(logic_results),
            },
        )

    # --- Arithmetic Checks ---

    def _check_arithmetic(
        self, data: Dict[str, Any]
    ) -> List[Tuple[bool, str, str]]:
        """
        Detects and validates arithmetic relationships in data.

        Looks for common patterns:
        - subtotal + tax = total
        - quantity * unit_price = line_total
        - sum of parts = whole
        """
        results: List[Tuple[bool, str, str]] = []

        # Pattern: subtotal + tax = total
        results.extend(self._check_sum_pattern(
            data,
            parts_fields=["subtotal", "sub_total"],
            addend_fields=["tax", "gst", "vat", "tax_amount"],
            total_fields=["total", "grand_total", "total_amount"],
            tolerance=0.01,  # 1 cent tolerance for rounding
        ))

        # Pattern: quantity * unit_price = amount/line_total
        # Prefer subtotal/amount/line_total over total (total may include tax)
        results.extend(self._check_product_pattern(
            data,
            factor_a_fields=["quantity", "qty", "units", "count"],
            factor_b_fields=["unit_price", "price", "rate", "price_per_unit"],
            product_fields=["amount", "line_total", "subtotal", "sub_total"],
            tolerance=0.01,
        ))

        # Pattern: discount applied correctly
        results.extend(self._check_discount_pattern(data))

        return results

    def _check_sum_pattern(
        self,
        data: Dict[str, Any],
        parts_fields: List[str],
        addend_fields: List[str],
        total_fields: List[str],
        tolerance: float = 0.01,
    ) -> List[Tuple[bool, str, str]]:
        """Checks if parts + addend = total (within tolerance)."""
        results = []

        parts_val = self._find_numeric(data, parts_fields)
        addend_val = self._find_numeric(data, addend_fields)
        total_val = self._find_numeric(data, total_fields)

        if parts_val is not None and addend_val is not None and total_val is not None:
            expected = parts_val + addend_val
            diff = abs(expected - total_val)
            if diff <= tolerance:
                results.append((
                    True, "total",
                    f"Arithmetic valid: {parts_val} + {addend_val} = "
                    f"{total_val} (diff={diff:.2f})"
                ))
            else:
                results.append((
                    False, "total",
                    f"Arithmetic CONFLICT: {parts_val} + {addend_val} = "
                    f"{expected}, but total says {total_val} (diff={diff:.2f})"
                ))

        return results

    def _check_product_pattern(
        self,
        data: Dict[str, Any],
        factor_a_fields: List[str],
        factor_b_fields: List[str],
        product_fields: List[str],
        tolerance: float = 0.01,
    ) -> List[Tuple[bool, str, str]]:
        """Checks if factor_a * factor_b = product (within tolerance)."""
        results = []

        factor_a = self._find_numeric(data, factor_a_fields)
        factor_b = self._find_numeric(data, factor_b_fields)
        product = self._find_numeric(data, product_fields)

        if factor_a is not None and factor_b is not None and product is not None:
            expected = factor_a * factor_b
            diff = abs(expected - product)
            if diff <= tolerance:
                results.append((
                    True, "amount",
                    f"Product valid: {factor_a} × {factor_b} = "
                    f"{product} (diff={diff:.2f})"
                ))
            else:
                results.append((
                    False, "amount",
                    f"Product CONFLICT: {factor_a} × {factor_b} = "
                    f"{expected}, but amount says {product} (diff={diff:.2f})"
                ))

        return results

    def _check_discount_pattern(
        self, data: Dict[str, Any]
    ) -> List[Tuple[bool, str, str]]:
        """Checks discount percentage against original and discounted prices."""
        results = []

        original = self._find_numeric(data, ["original_price", "list_price", "rrp"])
        discount_pct = self._find_numeric(data, [
            "discount", "discount_percent", "discount_pct"
        ])
        final = self._find_numeric(data, [
            "final_price", "sale_price", "discounted_price", "price"
        ])

        if original is not None and discount_pct is not None and final is not None:
            if 0 < discount_pct <= 1:
                discount_pct *= 100  # Normalize 0.15 -> 15%

            expected_final = original * (1 - discount_pct / 100)
            diff = abs(expected_final - final)
            if diff <= 0.01:
                results.append((
                    True, "final_price",
                    f"Discount valid: {original} - {discount_pct}% = {final}"
                ))
            else:
                results.append((
                    False, "final_price",
                    f"Discount CONFLICT: {original} - {discount_pct}% = "
                    f"{expected_final:.2f}, but says {final}"
                ))

        return results

    # --- Cross-Field Logic ---

    def _check_cross_field_logic(
        self, data: Dict[str, Any]
    ) -> List[Tuple[bool, str, str]]:
        """Checks logical relationships between fields."""
        results = []

        # Date ordering: start_date < end_date
        start = self._find_date(data, [
            "start_date", "from_date", "begin_date", "effective_date"
        ])
        end = self._find_date(data, [
            "end_date", "to_date", "expiry_date", "until_date"
        ])

        if start is not None and end is not None:
            if start <= end:
                results.append((True, "end_date", "Date order valid: start <= end"))
            else:
                results.append((
                    False, "end_date",
                    f"Date order CONFLICT: start ({start}) is after end ({end})"
                ))

        # Date not in future (for historical documents)
        for field_name in [
            "invoice_date", "document_date", "created_date", "issue_date"
        ]:
            if field_name in data:
                doc_date = self._parse_date(data[field_name])
                if doc_date and doc_date > datetime.utcnow():
                    results.append((
                        False, field_name,
                        f"Future date CONFLICT: '{field_name}' is in the future"
                    ))

        # Percentage fields should be 0-100
        for field_name, value in data.items():
            if isinstance(value, (int, float)) and not isinstance(value, bool):
                if "percent" in field_name.lower() or "pct" in field_name.lower():
                    if 0 <= value <= 100:
                        results.append((
                            True, field_name,
                            f"Percentage range valid: {value}%"
                        ))
                    else:
                        results.append((
                            False, field_name,
                            f"Percentage CONFLICT: {field_name}={value} "
                            f"(expected 0-100)"
                        ))

        return results

    # --- Statistical Anomaly Detection ---

    def _check_statistical_anomalies(
        self,
        data: Dict[str, Any],
        distributions: Dict[str, Dict[str, float]],
    ) -> List[Tuple[bool, str, str, float]]:
        """
        Checks if numeric values are statistically plausible given
        known distributions.

        A z-score > 3 means the value is more than 3 standard deviations
        from the mean — highly suspicious.
        """
        results = []

        for field_name, dist in distributions.items():
            if field_name not in data:
                continue

            value = data[field_name]
            if not isinstance(value, (int, float)) or isinstance(value, bool):
                continue

            mean = dist.get("mean", 0)
            std = dist.get("std", 1)

            if std == 0:
                continue

            z_score = abs(value - mean) / std

            if z_score <= 2:
                results.append((
                    True, field_name,
                    f"Within normal range (z={z_score:.1f})", z_score
                ))
            elif z_score <= 3:
                results.append((
                    True, field_name,
                    f"Slightly unusual but plausible (z={z_score:.1f})", z_score
                ))
            else:
                results.append((
                    False, field_name,
                    f"Statistical ANOMALY: {field_name}={value} is "
                    f"{z_score:.1f} std devs from mean {mean} (z>{3})",
                    z_score
                ))

        return results

    # --- Magnitude Reasonableness ---

    def _check_magnitude_reasonableness(
        self,
        data: Dict[str, Any],
        schema: DataSchema,
    ) -> List[Tuple[bool, str, str]]:
        """
        Checks for obvious magnitude errors:
        - Negative prices
        - Zero quantities where non-zero expected
        - Unreasonable orders of magnitude
        """
        results = []

        for field_name, value in data.items():
            if not isinstance(value, (int, float)) or isinstance(value, bool):
                continue

            spec = schema.get_field(field_name)

            # Negative currency values
            if spec and spec.field_type == FieldType.CURRENCY:
                if value < 0:
                    results.append((
                        False, field_name,
                        f"Negative currency: {field_name}={value}"
                    ))
                elif value == 0:
                    results.append((
                        True, field_name,
                        f"Zero currency (plausible but noted): {field_name}=0"
                    ))
                else:
                    results.append((True, field_name, "Currency value positive"))

            # Negative values for fields that should be positive
            name_lower = field_name.lower()
            monetary_keywords = [
                "price", "cost", "amount", "total", "fee", "charge",
                "subtotal", "tax", "rate", "quantity", "qty", "count",
                "weight", "distance", "area", "volume",
            ]
            if any(kw in name_lower for kw in monetary_keywords):
                if value < 0:
                    results.append((
                        False, field_name,
                        f"Negative value for {field_name}={value} — "
                        f"should be positive"
                    ))

            # Very large numbers (potential decimal shift)
            if "price" in name_lower or "rate" in name_lower:
                if isinstance(value, (int, float)) and value > 10000:
                    results.append((
                        False, field_name,
                        f"Magnitude warning: {field_name}={value} seems "
                        f"unusually high — possible decimal error?"
                    ))

        return results

    # --- Duplicate Detection ---

    def _check_duplicate_values(
        self, data: Dict[str, Any]
    ) -> List[Tuple[bool, str, str]]:
        """Checks for suspicious duplicate values across unrelated fields."""
        results = []
        numeric_values: Dict[float, List[str]] = {}

        for field_name, value in data.items():
            if isinstance(value, (int, float)) and not isinstance(value, bool):
                key = float(value)
                if key not in numeric_values:
                    numeric_values[key] = []
                numeric_values[key].append(field_name)

        for val, fields in numeric_values.items():
            if len(fields) > 2 and val != 0:
                results.append((
                    False, fields[0],
                    f"Suspicious: {len(fields)} fields have identical "
                    f"value {val}: {fields}"
                ))

        return results

    # --- Utility Methods ---

    def _find_numeric(
        self, data: Dict[str, Any], field_names: List[str]
    ) -> Optional[float]:
        """Finds the first matching numeric field."""
        for name in field_names:
            if name in data and isinstance(data[name], (int, float)):
                if not isinstance(data[name], bool):
                    return float(data[name])
        return None

    def _find_date(
        self, data: Dict[str, Any], field_names: List[str]
    ) -> Optional[datetime]:
        """Finds the first matching date field."""
        for name in field_names:
            if name in data:
                parsed = self._parse_date(data[name])
                if parsed:
                    return parsed
        return None

    def _parse_date(self, value: Any) -> Optional[datetime]:
        """Attempts to parse a date from various formats."""
        if not isinstance(value, str):
            return None

        formats = [
            "%Y-%m-%d",
            "%Y-%m-%dT%H:%M:%S",
            "%Y-%m-%dT%H:%M:%SZ",
            "%d/%m/%Y",
            "%m/%d/%Y",
            "%d-%m-%Y",
        ]
        for fmt in formats:
            try:
                return datetime.strptime(value, fmt)
            except (ValueError, TypeError):
                continue
        return None
