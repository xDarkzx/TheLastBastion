"""
Schema Gatekeeper (Step 1): Structural validation of incoming data.

The first line of defense — catches garbage, malformed data, injection attempts,
and type mismatches before any expensive verification layers run.

This layer answers: "Is this data even well-formed?"
"""
import logging
import re
from datetime import datetime
from typing import Any, Dict, List, Optional, Tuple

from core.verification.models import (
    DataSchema, Evidence, EvidenceType, FieldSpec,
    FieldType, LayerResult
)

logger = logging.getLogger("SchemaGatekeeper")

# Patterns that indicate injection/attack attempts
INJECTION_PATTERNS = [
    re.compile(r"<script", re.IGNORECASE),                          # 0: script tag
    re.compile(r"javascript:", re.IGNORECASE),                      # 1: JS protocol
    re.compile(r"on\w+\s*=", re.IGNORECASE),                       # 2: event handlers (onclick=, onerror=)
    re.compile(r"(UNION|SELECT|INSERT|UPDATE|DELETE|DROP)\s", re.IGNORECASE),  # 3: SQL keywords
    re.compile(r";\s*(DROP|DELETE|UPDATE|INSERT)", re.IGNORECASE),  # 4: chained SQL
    re.compile(r"\{\{.*\}\}"),                                      # 5: template injection
    re.compile(r"\$\{.*\}"),                                        # 6: expression injection
    re.compile(r"__(import|class|builtins)__"),                     # 7: Python injection
    # --- v2: proven bypass countermeasures (Think Tank findings) ---
    re.compile(r"<(iframe|frame|frameset)\b", re.IGNORECASE),       # 8: iframe injection
    re.compile(r"<(object|embed|applet)\b", re.IGNORECASE),         # 9: plugin embedding
    re.compile(r"<(form|input|button|textarea)\b", re.IGNORECASE),  # 10: phishing form injection
    re.compile(r"<(style|link)\b", re.IGNORECASE),                  # 11: CSS injection / exfil
    re.compile(r"<(svg|math)\b", re.IGNORECASE),                    # 12: SVG/MathML XSS wrapper
    re.compile(r"<meta\b", re.IGNORECASE),                          # 13: meta redirect / CSP bypass
    re.compile(r"data\s*:", re.IGNORECASE),                         # 14: data: URI (base64 XSS)
    re.compile(r"base64\s*,", re.IGNORECASE),                       # 15: base64 encoded payloads
    re.compile(r"&#\d+;|&#x[0-9a-f]+;", re.IGNORECASE),            # 16: HTML entity encoding
    re.compile(r"%3[cCeE]|%2[fF]|%253[cCeE]|%252[fF]", re.IGNORECASE),  # 17: URL-encoded + double-encoded < > /
    re.compile(r"<[a-z][a-z0-9]*[\s/>]", re.IGNORECASE),           # 18: HTML tag opening (requires tag name + delimiter, avoids "price<50")
]

# Standard value ranges for common field types
DEFAULT_RANGES = {
    FieldType.PERCENTAGE: (0.0, 100.0),
    FieldType.CURRENCY: (0.0, 1e9),  # Up to 1 billion
}


_dynamic_patterns: List[re.Pattern] = []
_dynamic_patterns_loaded_at: float = 0.0


def _load_dynamic_patterns():
    """Load bypass patterns discovered by the Think Tank from KnowledgeYield.

    Extracts patterns from two sources:
    1. Lines starting with "PATTERN:" in data_quality (evaluator-proposed regexes)
    2. Suspicious string values found in bypass attack payloads (fact_value)
    """
    global _dynamic_patterns, _dynamic_patterns_loaded_at
    import time
    now = time.monotonic()
    # Refresh at most every 5 minutes
    if now - _dynamic_patterns_loaded_at < 300 and _dynamic_patterns_loaded_at > 0:
        return
    _dynamic_patterns_loaded_at = now
    try:
        from core.database import SessionLocal, KnowledgeYield
        db = SessionLocal()
        try:
            discoveries = db.query(KnowledgeYield).filter(
                KnowledgeYield.company == "research_loop",
                KnowledgeYield.data_type == "bypass",
            ).all()
            new_patterns = []
            seen = set()
            for d in discoveries:
                # Source 1: Explicit PATTERN: lines in defense proposals
                raw = ""
                if isinstance(d.context_data, dict):
                    raw = d.context_data.get("defense_patterns", "") or ""
                if isinstance(raw, str):
                    for line in raw.split("\n"):
                        line = line.strip()
                        if line.startswith("PATTERN:"):
                            regex_str = line[8:].strip()
                            if regex_str and regex_str not in seen:
                                seen.add(regex_str)
                                try:
                                    new_patterns.append(re.compile(regex_str, re.IGNORECASE))
                                except re.error:
                                    pass

                # Source 2: Extract suspicious strings from bypass payloads
                payload_str = d.fact_value or ""
                if isinstance(payload_str, str) and len(payload_str) > 10:
                    try:
                        import json as _json
                        payload = _json.loads(payload_str)
                        if isinstance(payload, dict):
                            for v in payload.values():
                                if isinstance(v, str) and len(v) > 5:
                                    # Check if this string contains injection-like content
                                    for indicator in ["<", "script", "SELECT", "DROP", "{{", "${", "__"]:
                                        if indicator.lower() in v.lower():
                                            # Escape the value and add as literal pattern
                                            escaped = re.escape(v[:100])
                                            if escaped not in seen:
                                                seen.add(escaped)
                                                try:
                                                    new_patterns.append(re.compile(escaped, re.IGNORECASE))
                                                except re.error:
                                                    pass
                                            break
                    except (ValueError, TypeError):
                        pass
            # Source 3: Load deployed countermeasures from Countermeasure table
            try:
                from core.database import Countermeasure
                cms = db.query(Countermeasure).filter(
                    Countermeasure.status == "DEPLOYED",
                    Countermeasure.pattern_type == "regex",
                ).all()
                for cm in cms:
                    pv = cm.pattern_value or ""
                    if pv and pv not in seen:
                        seen.add(pv)
                        try:
                            new_patterns.append(re.compile(pv, re.IGNORECASE))
                        except re.error:
                            pass
            except Exception:
                pass  # Countermeasure table may not exist yet

            _dynamic_patterns = new_patterns
        finally:
            db.close()
    except Exception:
        pass  # DB not available — use existing patterns


class SchemaGatekeeper:
    """
    Validates incoming data against a defined schema.

    Checks field presence, types, ranges, patterns,
    and scans for injection/attack patterns.

    Dynamic patterns from Think Tank bypass discoveries are loaded
    from KnowledgeYield and checked alongside static INJECTION_PATTERNS.
    """

    def check(
        self,
        data: Dict[str, Any],
        schema: DataSchema,
    ) -> LayerResult:
        """
        Runs all schema validation checks on the provided data
        against the expected schema.

        Returns a LayerResult with a score from 0.0 to 1.0
        and detailed evidence of what passed or failed.
        """
        if not data or not isinstance(data, dict):
            return LayerResult(
                layer_name="schema_gatekeeper",
                score=0.0,
                warnings=["Data is empty or not a dictionary"],
                is_veto=True,
                veto_reason="Empty or invalid data structure",
            )

        evidence: List[Evidence] = []
        warnings: List[str] = []
        anomalies: List[str] = []

        total_checks = 0
        passed_checks = 0

        # --- Check 1: Required Fields ---
        required_names = schema.required_fields()
        for field_name in required_names:
            total_checks += 1
            if field_name in data and data[field_name] is not None:
                passed_checks += 1
                evidence.append(Evidence(
                    source="schema_gatekeeper",
                    source_type=EvidenceType.COMPUTATION,
                    claim_field=field_name,
                    confirms=True,
                    reasoning=f"Required field '{field_name}' is present",
                ))
            else:
                warnings.append(f"Missing required field: '{field_name}'")
                evidence.append(Evidence(
                    source="schema_gatekeeper",
                    source_type=EvidenceType.COMPUTATION,
                    claim_field=field_name,
                    confirms=False,
                    reasoning=f"Required field '{field_name}' is missing",
                ))

        # --- Check 2: Type Validation ---
        for field_name, value in data.items():
            spec = schema.get_field(field_name)
            if spec is None:
                # Unknown field — not necessarily bad, just note it
                warnings.append(f"Unexpected field: '{field_name}' (not in schema)")
                continue

            total_checks += 1
            type_ok, type_msg = self._validate_type(value, spec.field_type)
            if type_ok:
                passed_checks += 1
                evidence.append(Evidence(
                    source="schema_gatekeeper",
                    source_type=EvidenceType.COMPUTATION,
                    claim_field=field_name,
                    confirms=True,
                    found_value=type(value).__name__,
                    claimed_value=spec.field_type.value,
                    reasoning=f"Type valid: {type_msg}",
                ))
            else:
                warnings.append(
                    f"Type mismatch for '{field_name}': "
                    f"expected {spec.field_type.value}, got {type(value).__name__}"
                )
                evidence.append(Evidence(
                    source="schema_gatekeeper",
                    source_type=EvidenceType.COMPUTATION,
                    claim_field=field_name,
                    confirms=False,
                    found_value=type(value).__name__,
                    claimed_value=spec.field_type.value,
                    reasoning=f"Type invalid: {type_msg}",
                ))

        # --- Check 3: Range Validation ---
        for field_name, value in data.items():
            spec = schema.get_field(field_name)
            if spec is None:
                continue

            range_result = self._validate_range(value, spec)
            if range_result is not None:
                total_checks += 1
                ok, msg = range_result
                if ok:
                    passed_checks += 1
                else:
                    anomalies.append(msg)
                    evidence.append(Evidence(
                        source="schema_gatekeeper",
                        source_type=EvidenceType.COMPUTATION,
                        claim_field=field_name,
                        confirms=False,
                        found_value=value,
                        reasoning=f"Range violation: {msg}",
                    ))

        # --- Check 4: Allowed Values ---
        for field_name, value in data.items():
            spec = schema.get_field(field_name)
            if spec and spec.allowed_values:
                total_checks += 1
                if value in spec.allowed_values:
                    passed_checks += 1
                else:
                    warnings.append(
                        f"Value '{value}' for '{field_name}' not in allowed: "
                        f"{spec.allowed_values}"
                    )

        # --- Check 5: Injection Detection ---
        injection_found = False
        for field_name, value in data.items():
            if isinstance(value, str):
                total_checks += 1
                is_clean, pattern = self._check_injection(value)
                if is_clean:
                    passed_checks += 1
                else:
                    injection_found = True
                    anomalies.append(
                        f"INJECTION DETECTED in '{field_name}': "
                        f"pattern '{pattern}' matched"
                    )
                    evidence.append(Evidence(
                        source="schema_gatekeeper",
                        source_type=EvidenceType.FORENSIC,
                        claim_field=field_name,
                        confirms=False,
                        found_value=value[:50],
                        reasoning=f"Injection pattern detected: {pattern}",
                    ))

        # --- Check 6: String Length Validation ---
        for field_name, value in data.items():
            spec = schema.get_field(field_name)
            if spec and isinstance(value, str):
                length_result = self._validate_string_length(value, spec)
                if length_result is not None:
                    total_checks += 1
                    ok, msg = length_result
                    if ok:
                        passed_checks += 1
                    else:
                        warnings.append(msg)

        # --- Compute Score ---
        if total_checks == 0:
            score = 0.0
        else:
            score = passed_checks / total_checks

        # Apply failure penalty: each failure reduces score more aggressively
        # so a single type mismatch or missing required field has real impact
        failed_checks = total_checks - passed_checks
        if failed_checks > 0 and total_checks > 0:
            # Cap score based on failure count
            if failed_checks >= 3:
                score = min(score, 0.2)
            elif failed_checks >= 2:
                score = min(score, 0.35)
            elif failed_checks >= 1:
                score = min(score, 0.5)

        # Injection is an automatic veto
        is_veto = injection_found
        veto_reason = "Injection attack detected" if injection_found else ""

        # Missing ALL required fields is also a veto
        if required_names and all(
            f not in data or data[f] is None for f in required_names
        ):
            is_veto = True
            veto_reason = "All required fields missing"
            score = 0.0

        logger.info(
            f"SCHEMA: Checked {total_checks} constraints, "
            f"{passed_checks} passed (score={score:.2f})"
        )

        return LayerResult(
            layer_name="schema_gatekeeper",
            score=round(score, 4),
            evidence=evidence,
            warnings=warnings,
            anomalies=anomalies,
            is_veto=is_veto,
            veto_reason=veto_reason,
            metadata={
                "total_checks": total_checks,
                "passed_checks": passed_checks,
                "fields_checked": list(data.keys()),
            },
        )

    # --- Private Helpers ---

    def _validate_type(
        self, value: Any, expected: FieldType
    ) -> Tuple[bool, str]:
        """Validates a value against an expected FieldType."""
        if value is None:
            return False, "Value is None"

        if expected == FieldType.STRING:
            return isinstance(value, str), f"{'is' if isinstance(value, str) else 'not'} string"

        if expected == FieldType.INTEGER:
            if isinstance(value, bool):
                return False, "Boolean is not integer"
            return isinstance(value, int), f"{'is' if isinstance(value, int) else 'not'} integer"

        if expected == FieldType.FLOAT:
            return isinstance(value, (int, float)) and not isinstance(value, bool), \
                f"{'is' if isinstance(value, (int, float)) else 'not'} numeric"

        if expected == FieldType.BOOLEAN:
            return isinstance(value, bool), f"{'is' if isinstance(value, bool) else 'not'} boolean"

        if expected == FieldType.CURRENCY:
            if not isinstance(value, (int, float)) or isinstance(value, bool):
                return False, "not numeric"
            return True, "is numeric (currency)"

        if expected == FieldType.PERCENTAGE:
            if not isinstance(value, (int, float)) or isinstance(value, bool):
                return False, "not numeric"
            return True, "is numeric (percentage)"

        if expected == FieldType.DATE:
            if not isinstance(value, str):
                return False, "not a date string"
            return self._is_valid_date(value), \
                f"{'valid' if self._is_valid_date(value) else 'invalid'} date format"

        if expected == FieldType.DATETIME:
            if not isinstance(value, str):
                return False, "not a datetime string"
            return self._is_valid_datetime(value), \
                f"{'valid' if self._is_valid_datetime(value) else 'invalid'} datetime format"

        if expected == FieldType.EMAIL:
            if not isinstance(value, str):
                return False, "not a string"
            pattern = r"^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$"
            is_email = bool(re.match(pattern, value))
            return is_email, f"{'valid' if is_email else 'invalid'} email"

        if expected == FieldType.URL:
            if not isinstance(value, str):
                return False, "not a string"
            is_url = value.startswith(("http://", "https://"))
            return is_url, f"{'valid' if is_url else 'invalid'} URL"

        if expected == FieldType.LIST:
            return isinstance(value, list), f"{'is' if isinstance(value, list) else 'not'} list"

        if expected == FieldType.DICT:
            return isinstance(value, dict), f"{'is' if isinstance(value, dict) else 'not'} dict"

        return True, "unknown type — accepted"

    def _validate_range(
        self, value: Any, spec: FieldSpec
    ) -> Optional[Tuple[bool, str]]:
        """Validates numeric range constraints. Returns None if not applicable."""
        if not isinstance(value, (int, float)) or isinstance(value, bool):
            return None

        # Check spec-defined ranges
        if spec.min_value is not None and value < spec.min_value:
            return False, (
                f"'{spec.name}' value {value} below minimum {spec.min_value}"
            )
        if spec.max_value is not None and value > spec.max_value:
            return False, (
                f"'{spec.name}' value {value} above maximum {spec.max_value}"
            )

        # Check default ranges for known types
        if spec.field_type in DEFAULT_RANGES:
            low, high = DEFAULT_RANGES[spec.field_type]
            if value < low or value > high:
                return False, (
                    f"'{spec.name}' value {value} outside default "
                    f"{spec.field_type.value} range [{low}, {high}]"
                )

        return True, "within range"

    def _validate_string_length(
        self, value: str, spec: FieldSpec
    ) -> Optional[Tuple[bool, str]]:
        """Validates string length constraints. Returns None if not applicable."""
        if spec.min_length is not None and len(value) < spec.min_length:
            return False, (
                f"'{spec.name}' length {len(value)} below minimum {spec.min_length}"
            )
        if spec.max_length is not None and len(value) > spec.max_length:
            return False, (
                f"'{spec.name}' length {len(value)} above maximum {spec.max_length}"
            )
        return None

    def _check_injection(self, value: str) -> Tuple[bool, str]:
        """Checks a string for injection patterns. Returns (is_clean, pattern)."""
        for pattern in INJECTION_PATTERNS:
            if pattern.search(value):
                return False, pattern.pattern
        # Check dynamic patterns from Think Tank discoveries
        _load_dynamic_patterns()
        for pattern in _dynamic_patterns:
            if pattern.search(value):
                return False, f"[DYNAMIC] {pattern.pattern}"
        return True, ""

    def _is_valid_date(self, value: str) -> bool:
        """Checks if a string is a valid ISO date (YYYY-MM-DD)."""
        try:
            datetime.strptime(value, "%Y-%m-%d")
            return True
        except (ValueError, TypeError):
            return False

    def _is_valid_datetime(self, value: str) -> bool:
        """Checks if a string is a valid ISO datetime."""
        formats = [
            "%Y-%m-%dT%H:%M:%S",
            "%Y-%m-%dT%H:%M:%SZ",
            "%Y-%m-%dT%H:%M:%S.%f",
            "%Y-%m-%d %H:%M:%S",
        ]
        for fmt in formats:
            try:
                datetime.strptime(value, fmt)
                return True
            except (ValueError, TypeError):
                continue
        return False
