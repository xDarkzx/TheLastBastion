"""
Quickstart — Register an agent, submit a payload, check the verdict.

Prerequisites:
    pip install lastbastion pynacl
    # Start the backend: uvicorn regional_core:app --port 8000

Usage:
    python quickstart.py
"""

import asyncio
from lastbastion import LastBastionClient


async def main():
    # 1. Generate Ed25519 keypair
    public_key, private_key = LastBastionClient.generate_keypair()
    print(f"Generated keypair:")
    print(f"  Public:  {public_key[:16]}...")
    print(f"  Private: {private_key[:16]}...")

    async with LastBastionClient(base_url="http://localhost:8000") as client:
        # 2. Register with automatic challenge-response
        print("\n--- Registering agent ---")
        reg = await client.register_with_keypair(
            agent_id="quickstart-agent",
            public_key=public_key,
            private_key=private_key,
            role="DATA_PROVIDER",
            capabilities=["data_submission"],
            display_name="Quickstart Agent",
        )
        print(f"Registered: {reg.get('status', 'OK')}")
        print(f"Trust score: {reg.get('trust_score', 'N/A')}")
        print(f"Credits: {reg.get('credits', 'N/A')}")

        # 3. Submit a payload for verification
        print("\n--- Submitting payload ---")
        result = await client.submit_payload(
            payload={
                "invoice": {
                    "vendor": "Acme Corp",
                    "amount": 1500.00,
                    "currency": "USD",
                    "items": [
                        {"name": "Widget A", "qty": 10, "price": 100.00},
                        {"name": "Widget B", "qty": 5, "price": 100.00},
                    ],
                },
            },
            source_agent_id="quickstart-agent",
        )
        print(f"Verdict: {result.get('verdict', 'N/A')}")
        print(f"Score:   {result.get('score', 'N/A')}")
        print(f"Proof:   {result.get('proof_hash', 'N/A')[:32]}...")

        # 4. Check trust status
        print("\n--- Trust status ---")
        trust = await client.get_trust_status("quickstart-agent")
        print(f"Trust level: {trust.get('trust_level', 'N/A')}")
        print(f"Trust score: {trust.get('trust_score', 'N/A')}")


if __name__ == "__main__":
    asyncio.run(main())
