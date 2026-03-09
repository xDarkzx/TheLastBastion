"""
Attack Test — Deliberately send bad payloads to demonstrate rejection.

Demonstrates:
- Clean data → VERIFIED/GOLD
- Injection attempt → REJECTED (SchemaGatekeeper catches it)
- Poisoned data → QUARANTINE or REJECTED
- Impossible data → REJECTED (ConsistencyAnalyzer catches it)

Prerequisites:
    pip install lastbastion pynacl
    # Start the backend: uvicorn regional_core:app --port 8000

Usage:
    python attack_test.py
"""

import asyncio
from lastbastion import LastBastionClient


PAYLOADS = [
    {
        "name": "Clean Invoice",
        "data": {
            "invoice_id": "INV-2026-001",
            "vendor": "Honest Suppliers Ltd",
            "amount": 5000.00,
            "currency": "NZD",
            "items": [
                {"name": "Steel beams", "qty": 50, "unit_price": 100.00},
            ],
            "total": 5000.00,
        },
        "expect": "VERIFIED or GOLD",
    },
    {
        "name": "SQL Injection in Field",
        "data": {
            "invoice_id": "INV-2026-002",
            "vendor": "'; DROP TABLE invoices; --",
            "amount": 1000.00,
            "items": [{"name": "Widget", "qty": 1, "unit_price": 1000.00}],
        },
        "expect": "REJECTED (injection detected)",
    },
    {
        "name": "Script Injection",
        "data": {
            "invoice_id": "INV-2026-003",
            "vendor": '<script>alert("xss")</script>',
            "amount": 500.00,
        },
        "expect": "REJECTED (injection detected)",
    },
    {
        "name": "Arithmetic Mismatch",
        "data": {
            "invoice_id": "INV-2026-004",
            "vendor": "Mismatch Corp",
            "items": [
                {"name": "Item A", "qty": 10, "unit_price": 50.00},
                {"name": "Item B", "qty": 5, "unit_price": 100.00},
            ],
            "total": 99999.99,  # Should be 1000.00
        },
        "expect": "QUARANTINE or REJECTED (arithmetic mismatch)",
    },
    {
        "name": "Empty Payload",
        "data": {},
        "expect": "REJECTED (no meaningful data)",
    },
]


async def main():
    pub, priv = LastBastionClient.generate_keypair()

    async with LastBastionClient(base_url="http://localhost:8000") as client:
        # Register first
        await client.register_with_keypair(
            agent_id="attack-tester",
            public_key=pub,
            private_key=priv,
            role="DATA_PROVIDER",
        )

        print("=== Attack Test Suite ===\n")

        for i, test in enumerate(PAYLOADS, 1):
            print(f"[{i}/{len(PAYLOADS)}] {test['name']}")
            print(f"  Expected: {test['expect']}")

            try:
                result = await client.submit_payload(
                    payload=test["data"],
                    source_agent_id="attack-tester",
                )
                verdict = result.get("verdict", "UNKNOWN")
                score = result.get("score", 0)
                print(f"  Result:   {verdict} (score: {score:.2f})")
            except Exception as e:
                print(f"  Error:    {e}")
            print()

    print("=== Complete ===")
    print("Review: clean data should pass, injections should be caught.")


if __name__ == "__main__":
    asyncio.run(main())
