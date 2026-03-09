"""
Challenge Me — Get test payloads from the Challenge Agent and verify them.

Demonstrates:
1. Fetch challenge payloads from the Challenge Agent
2. Submit each through the refinery pipeline
3. Compare actual verdict against expected verdict

Prerequisites:
    pip install lastbastion pynacl httpx
    # Start the backend: uvicorn regional_core:app --port 8000
    # Start Challenge Agent: python -m agents.a2a.challenge_agent

Usage:
    python challenge_me.py
"""

import asyncio
import json
import uuid

import httpx
from lastbastion import LastBastionClient


CHALLENGE_AGENT_URL = "http://localhost:9011"
REGISTRY_URL = "http://localhost:8000"


async def main():
    print("=== Challenge Me ===\n")

    # 1. Register ourselves
    pub, priv = LastBastionClient.generate_keypair()
    async with LastBastionClient(base_url=REGISTRY_URL) as client:
        reg = await client.register_with_keypair(
            agent_id="challenge-tester",
            public_key=pub,
            private_key=priv,
            role="DATA_PROVIDER",
        )
        print(f"Registered as challenge-tester (trust: {reg.get('trust_score', 'N/A')})\n")

        # 2. Fetch challenges from Challenge Agent
        print("Fetching challenges from Challenge Agent...")
        async with httpx.AsyncClient(timeout=30.0) as http:
            rpc_request = {
                "jsonrpc": "2.0",
                "id": str(uuid.uuid4()),
                "method": "message/send",
                "params": {
                    "message": {
                        "messageId": str(uuid.uuid4()),
                        "role": "user",
                        "parts": [{"kind": "text", "text": "all"}],
                    },
                },
            }
            resp = await http.post(CHALLENGE_AGENT_URL, json=rpc_request)
            result = resp.json()

        # Extract challenges from response
        challenges = []
        if "result" in result:
            task = result["result"]
            for msg in task.get("history", []):
                for part in msg.get("parts", []):
                    if part.get("kind") == "data":
                        challenges = part["data"].get("challenges", [])

        if not challenges:
            print("No challenges received. Is the Challenge Agent running?")
            return

        print(f"Received {len(challenges)} challenges\n")

        # 3. Submit each challenge through verification
        passed = 0
        for i, ch in enumerate(challenges, 1):
            print(f"[{i}/{len(challenges)}] {ch['id']} — {ch['description']}")
            print(f"  Category: {ch['category']}")
            print(f"  Expected: {ch['expected_verdict']}")

            try:
                result = await client.submit_payload(
                    payload=ch["payload"],
                    source_agent_id="challenge-tester",
                )
                actual = result.get("verdict", "UNKNOWN")
                score = result.get("score", 0)
                match = "PASS" if actual == ch["expected_verdict"] else "MISMATCH"
                if match == "PASS":
                    passed += 1
                print(f"  Actual:   {actual} (score: {score:.2f}) [{match}]")
            except Exception as e:
                print(f"  Error:    {e}")
            print()

        print(f"=== Results: {passed}/{len(challenges)} matched expected verdict ===")


if __name__ == "__main__":
    asyncio.run(main())
