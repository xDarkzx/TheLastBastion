"""
Multi-Agent — Two agents register and exchange verified data.

Demonstrates:
- Two independent agents registering with their own keypairs
- Agent A submits data, Agent B verifies the proof
- Trust scores tracked independently

Prerequisites:
    pip install lastbastion pynacl
    # Start the backend: uvicorn regional_core:app --port 8000

Usage:
    python multi_agent.py
"""

import asyncio
from lastbastion import LastBastionClient


async def register_agent(name: str, role: str) -> tuple:
    """Register an agent and return (client, api_key_info)."""
    pub, priv = LastBastionClient.generate_keypair()
    client = LastBastionClient(base_url="http://localhost:8000")

    reg = await client.register_with_keypair(
        agent_id=name,
        public_key=pub,
        private_key=priv,
        role=role,
        display_name=name.replace("-", " ").title(),
    )
    print(f"[{name}] Registered — trust: {reg.get('trust_score', 'N/A')}")
    return client, reg


async def main():
    print("=== Multi-Agent Demo ===\n")

    # Register two agents
    producer_client, producer_reg = await register_agent(
        "producer-agent", "DATA_PROVIDER"
    )
    consumer_client, consumer_reg = await register_agent(
        "consumer-agent", "DATA_CONSUMER"
    )

    try:
        # Producer submits batch data
        print("\n--- Producer submits batch data ---")
        batch = {
            "batch_id": "BATCH-2026-001",
            "product": "Manuka Honey",
            "quantity_kg": 500,
            "grade": "UMF 15+",
            "origin": "Waikato, New Zealand",
            "harvest_date": "2026-02-15",
            "lab_results": {
                "methylglyoxal_mg_kg": 514,
                "dha_mg_kg": 1200,
                "hme_mg_kg": 3,
            },
        }
        result = await producer_client.submit_payload(
            payload=batch,
            source_agent_id="producer-agent",
        )
        proof_hash = result.get("proof_hash", "")
        print(f"Verdict: {result.get('verdict')}")
        print(f"Score:   {result.get('score')}")
        print(f"Proof:   {proof_hash[:32]}...")

        # Consumer checks the producer's trust
        print("\n--- Consumer checks producer trust ---")
        trust = await consumer_client.get_trust_status("producer-agent")
        print(f"Producer trust: {trust.get('trust_level', 'UNKNOWN')} ({trust.get('trust_score', 0):.2f})")

        # Consumer submits their own data
        print("\n--- Consumer submits purchase order ---")
        po = {
            "po_number": "PO-2026-0042",
            "buyer": "European Foods Ltd",
            "product": "Manuka Honey UMF 15+",
            "quantity_kg": 500,
            "unit_price_nzd": 85.00,
            "total_nzd": 42500.00,
            "delivery_port": "Rotterdam",
        }
        result2 = await consumer_client.submit_payload(
            payload=po,
            source_agent_id="consumer-agent",
        )
        print(f"Verdict: {result2.get('verdict')}")
        print(f"Score:   {result2.get('score')}")

    finally:
        await producer_client.close()
        await consumer_client.close()

    print("\n=== Done ===")


if __name__ == "__main__":
    asyncio.run(main())
