"""Data Exfiltration Attack — submits payloads with encoded URLs and external references."""

import time
from core.attacks.base import BaseAttack, AttackResult


EXFILTRATION_PAYLOADS = [
    {"name": "Plain URL in value", "data": {"notes": "See http://evil.com/steal?data=secret"}},
    {"name": "Base64 encoded URL", "data": {"config": "aHR0cDovL2V2aWwuY29tL2V4ZmlsdHJhdGU="}},
    {"name": "Webhook callback", "data": {"callback_url": "https://attacker.ngrok.io/callback"}},
    {"name": "DNS exfil pattern", "data": {"subdomain": "data.secret.attacker.com"}},
    {"name": "Embedded iframe", "data": {"description": '<iframe src="http://evil.com"></iframe>'}},
]


class DataExfiltrationAttack(BaseAttack):
    """Submits payloads containing encoded URLs and external references."""

    attack_type = "data_exfiltration"
    severity = "high"

    async def execute(self, agent_id: str, context: dict = None) -> AttackResult:
        start = time.time()
        vulnerabilities = []
        detected = 0
        total = len(EXFILTRATION_PAYLOADS)

        try:
            from core.verification.schema_gatekeeper import SchemaGatekeeper
            from core.verification.models import DataSchema, FieldSpec, FieldType

            gatekeeper = SchemaGatekeeper()

            for payload_info in EXFILTRATION_PAYLOADS:
                # Build schema from payload keys — all string fields
                fields = [
                    FieldSpec(name=k, field_type=FieldType.STRING, required=True)
                    for k in payload_info["data"]
                ]
                schema = DataSchema(name="exfiltration_test", fields=fields)

                result = gatekeeper.check(payload_info["data"], schema)

                # Check if injection/suspicious content was flagged
                evidence_str = " ".join(
                    str(getattr(e, 'reasoning', '')) for e in (result.evidence or [])
                )
                flagged = (
                    "injection" in evidence_str.lower()
                    or "suspicious" in evidence_str.lower()
                    or "url" in evidence_str.lower()
                    or result.is_veto
                    or result.score < 0.5
                )
                if flagged:
                    detected += 1
                else:
                    vulnerabilities.append({
                        "payload_name": payload_info["name"],
                        "issue": "Exfiltration payload not flagged",
                    })
        except Exception as e:
            return self._timed_result(
                start, False,
                details={"error": str(e)},
                vulnerabilities=[{"issue": f"Exfiltration test failed: {e}"}],
            )

        passed = detected >= total * 0.6  # 60% detection threshold
        return self._timed_result(
            start, passed,
            details={
                "total_payloads": total,
                "detected": detected,
                "detection_rate": detected / total if total > 0 else 0,
            },
            vulnerabilities=vulnerabilities,
        )
