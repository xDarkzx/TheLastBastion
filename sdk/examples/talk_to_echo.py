"""
Talk to Echo Agent — Send a payload to the Echo Agent and get a verified response.

Demonstrates:
1. Discover the Echo Agent via its A2A Agent Card
2. Send a JSON payload
3. Receive the echoed data + verification verdict

Prerequisites:
    pip install lastbastion pynacl httpx
    # Start the backend: uvicorn regional_core:app --port 8000
    # Start Echo Agent: python -m agents.a2a.echo_agent

Usage:
    python talk_to_echo.py
"""

import asyncio
import json
import uuid

import httpx


ECHO_AGENT_URL = "http://localhost:9010"


async def main():
    print("=== Talk to Echo Agent ===\n")

    async with httpx.AsyncClient(timeout=30.0) as client:
        # 1. Discover the agent
        print("1. Discovering Echo Agent...")
        resp = await client.get(f"{ECHO_AGENT_URL}/.well-known/agent-card.json")
        card = resp.json()
        print(f"   Name: {card['name']}")
        print(f"   Skills: {[s['name'] for s in card.get('skills', [])]}")

        # 2. Send a payload via A2A JSON-RPC
        print("\n2. Sending test payload...")
        payload = {
            "batch_id": "BATCH-ECHO-001",
            "product": "Organic Avocados",
            "quantity_kg": 200,
            "origin": "Bay of Plenty, NZ",
            "grade": "Premium",
        }

        rpc_request = {
            "jsonrpc": "2.0",
            "id": str(uuid.uuid4()),
            "method": "message/send",
            "params": {
                "message": {
                    "messageId": str(uuid.uuid4()),
                    "role": "user",
                    "parts": [{"kind": "data", "data": payload}],
                },
            },
        }

        resp = await client.post(ECHO_AGENT_URL, json=rpc_request)
        result = resp.json()

        # 3. Parse the response
        print("\n3. Response:")
        if "result" in result:
            task = result["result"]
            if "history" in task:
                for msg in task["history"]:
                    for part in msg.get("parts", []):
                        if part.get("kind") == "data":
                            data = part["data"]
                            print(f"   Echo: {json.dumps(data.get('echo', {}), indent=2)[:200]}")
                            v = data.get("verification", {})
                            print(f"   Verdict: {v.get('verdict', 'N/A')}")
                            print(f"   Score:   {v.get('score', 'N/A')}")
                            print(f"   Proof:   {v.get('proof_hash', 'N/A')[:32]}...")
        else:
            print(f"   Raw: {json.dumps(result, indent=2)[:500]}")

    print("\n=== Done ===")


if __name__ == "__main__":
    asyncio.run(main())
