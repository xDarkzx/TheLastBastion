"""Prompt Injection Attack — tests if the verification stack detects injected payloads."""

import time
from core.attacks.base import BaseAttack, AttackResult


# Injection patterns from SchemaGatekeeper
INJECTION_PAYLOADS = [
    {"name": "SQL injection", "value": "'; DROP TABLE missions; --"},
    {"name": "XSS script tag", "value": "<script>alert('xss')</script>"},
    {"name": "XSS event handler", "value": '<img onerror="fetch(\'http://evil.com\')" src=x>'},
    {"name": "Template injection", "value": "{{7*7}}"},
    {"name": "Jinja injection", "value": "{% import os %}{{ os.system('id') }}"},
    {"name": "Python eval", "value": "__import__('os').system('cat /etc/passwd')"},
    {"name": "SQL UNION", "value": "1 UNION SELECT * FROM users"},
    {"name": "Nested encoding", "value": "%3Cscript%3Ealert(1)%3C/script%3E"},
    {"name": "JSON field escape", "value": '{"__proto__": {"admin": true}}'},
    {"name": "Command injection", "value": "; rm -rf / #"},
]


class PromptInjectionAttack(BaseAttack):
    """Submits payloads with various injection patterns in field values."""

    attack_type = "prompt_injection"
    severity = "critical"

    async def execute(self, agent_id: str, context: dict = None) -> AttackResult:
        start = time.time()
        vulnerabilities = []
        detected = 0
        total = len(INJECTION_PAYLOADS)

        try:
            from core.verification.schema_gatekeeper import SchemaGatekeeper
            from core.verification.models import DataSchema, FieldSpec, FieldType

            gatekeeper = SchemaGatekeeper()

            schema = DataSchema(
                name="injection_test",
                fields=[
                    FieldSpec(name="product", field_type=FieldType.STRING, required=True),
                    FieldSpec(name="price", field_type=FieldType.FLOAT, required=True),
                    FieldSpec(name="quantity", field_type=FieldType.INTEGER, required=False),
                ],
            )

            for payload_info in INJECTION_PAYLOADS:
                test_data = {
                    "product": payload_info["value"],
                    "price": 9.99,
                    "quantity": 1,
                }
                result = gatekeeper.check(test_data, schema)

                # Check if injection was flagged via evidence or veto
                evidence_str = " ".join(
                    str(getattr(e, 'reasoning', '')) for e in (result.evidence or [])
                )
                injection_found = (
                    "injection" in evidence_str.lower()
                    or result.is_veto
                    or result.score < 0.5
                )
                if injection_found:
                    detected += 1
                else:
                    vulnerabilities.append({
                        "payload_name": payload_info["name"],
                        "payload_value": payload_info["value"][:100],
                        "issue": "Injection not detected by SchemaGatekeeper",
                    })
        except Exception as e:
            return self._timed_result(
                start, False,
                details={"error": str(e), "note": "SchemaGatekeeper unavailable"},
                vulnerabilities=[{"issue": f"Could not run injection tests: {e}"}],
            )

        passed = detected == total
        return self._timed_result(
            start, passed,
            details={
                "total_payloads": total,
                "detected": detected,
                "missed": total - detected,
                "detection_rate": detected / total if total > 0 else 0,
            },
            vulnerabilities=vulnerabilities,
        )
