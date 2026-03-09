"""Payload Poisoning Attack — submits gradually degrading data with subtle corruption."""

import time
from core.attacks.base import BaseAttack, AttackResult


POISONED_PAYLOADS = [
    {
        "name": "Arithmetic mismatch",
        "data": {"product": "Widget A", "quantity": 10, "unit_price": 5.00, "total": 99.99},
        "desc": "total != quantity * unit_price",
    },
    {
        "name": "Negative quantity",
        "data": {"product": "Widget B", "quantity": -5, "unit_price": 10.00, "total": -50.00},
        "desc": "Negative quantity is unusual for a purchase",
    },
    {
        "name": "Future date",
        "data": {"product": "Widget C", "date": "2099-01-01", "quantity": 1, "total": 10.00},
        "desc": "Date far in the future",
    },
    {
        "name": "Extreme outlier price",
        "data": {"product": "Widget D", "quantity": 1, "unit_price": 999999.99, "total": 999999.99},
        "desc": "Price is a statistical outlier",
    },
    {
        "name": "Empty required field",
        "data": {"product": "", "quantity": 5, "unit_price": 10.00, "total": 50.00},
        "desc": "Product name is empty string",
    },
]


class PayloadPoisoningAttack(BaseAttack):
    """Submits payloads with subtle data corruption to test consistency checks."""

    attack_type = "payload_poisoning"
    severity = "medium"

    async def execute(self, agent_id: str, context: dict = None) -> AttackResult:
        start = time.time()
        vulnerabilities = []
        detected = 0
        total = len(POISONED_PAYLOADS)

        try:
            from core.verification.consistency import ConsistencyAnalyzer
            from core.verification.models import DataSchema, FieldSpec, FieldType

            analyzer = ConsistencyAnalyzer()

            # Schema matching the common fields
            schema = DataSchema(
                name="poisoning_test",
                fields=[
                    FieldSpec(name="product", field_type=FieldType.STRING, required=True),
                    FieldSpec(name="quantity", field_type=FieldType.INTEGER, required=True),
                    FieldSpec(name="unit_price", field_type=FieldType.FLOAT, required=False),
                    FieldSpec(name="total", field_type=FieldType.FLOAT, required=True),
                    FieldSpec(name="date", field_type=FieldType.STRING, required=False),
                ],
            )

            for payload_info in POISONED_PAYLOADS:
                result = analyzer.check(payload_info["data"], schema)

                # Check if anomaly/issue was detected
                flagged = (
                    result.score < 0.8
                    or len(result.evidence or []) > 0
                )
                if flagged:
                    detected += 1
                else:
                    vulnerabilities.append({
                        "payload_name": payload_info["name"],
                        "description": payload_info["desc"],
                        "issue": "Poisoned data not flagged by ConsistencyAnalyzer",
                    })
        except Exception as e:
            return self._timed_result(
                start, False,
                details={"error": str(e)},
                vulnerabilities=[{"issue": f"Payload poisoning test failed: {e}"}],
            )

        passed = detected >= total * 0.6
        return self._timed_result(
            start, passed,
            details={
                "total_payloads": total,
                "detected": detected,
                "detection_rate": detected / total if total > 0 else 0,
            },
            vulnerabilities=vulnerabilities,
        )
