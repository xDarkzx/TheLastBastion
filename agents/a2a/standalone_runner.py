"""
Standalone Agent Runner — Run a single A2A agent independently.

For real-world deployment where each agent is a separate service.
Registers with The Last Bastion on startup, sends heartbeats,
and routes all data through Bastion for verification.

Usage:
    python agents/a2a/standalone_runner.py --agent producer --port 9001
    python agents/a2a/standalone_runner.py --agent compliance --port 9002
    python agents/a2a/standalone_runner.py --agent logistics --port 9003
    python agents/a2a/standalone_runner.py --agent buyer --port 9004

Environment variables:
    BASTION_URL  — The Last Bastion API URL (default: http://localhost:8000)
"""
import argparse
import asyncio
import logging
import os
import sys

import uvicorn

# Add project root to path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))

from agents.a2a.producer_agent import create_producer_agent
from agents.a2a.compliance_agent import create_compliance_agent
from agents.a2a.logistics_agent import create_logistics_agent
from agents.a2a.buyer_agent import create_buyer_agent

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(name)s] %(message)s",
)
logger = logging.getLogger("A2A.Standalone")

AGENT_FACTORIES = {
    "producer": (create_producer_agent, 9001),
    "compliance": (create_compliance_agent, 9002),
    "logistics": (create_logistics_agent, 9003),
    "buyer": (create_buyer_agent, 9004),
}

AGENT_M2M_IDS = {
    "producer": "producer-nz-001",
    "compliance": "compliance-mpi-001",
    "logistics": "logistics-maersk-001",
    "buyer": "buyer-sg-001",
}


async def register_with_bastion(bastion_url: str, agent_name: str, port: int):
    """Register this agent with The Last Bastion on startup."""
    import httpx

    m2m_id = AGENT_M2M_IDS.get(agent_name, agent_name)
    agent_labels = {
        "producer": "ProducerBot",
        "compliance": "ComplianceBot",
        "logistics": "LogisticsBot",
        "buyer": "BuyerBot",
    }

    async with httpx.AsyncClient(timeout=10.0) as client:
        # Wait for Bastion to be ready
        for attempt in range(15):
            try:
                resp = await client.get(f"{bastion_url}/health")
                if resp.status_code == 200:
                    break
            except Exception:
                pass
            logger.info(f"Waiting for Bastion at {bastion_url}... (attempt {attempt + 1})")
            await asyncio.sleep(2)
        else:
            logger.warning(f"Could not reach Bastion at {bastion_url} — running standalone")
            return

        # Register on M2M
        try:
            resp = await client.post(f"{bastion_url}/m2m/register", json={
                "agent_id": m2m_id,
                "public_key": f"ed25519_pub_{m2m_id}",
                "role": "DATA_PROVIDER",
                "display_name": agent_labels.get(agent_name, agent_name),
                "capabilities": [],
            })
            if resp.status_code == 200:
                logger.info(f"Registered {m2m_id} with Bastion")
            else:
                logger.warning(f"Registration response: {resp.status_code}")
        except Exception as e:
            logger.warning(f"Registration failed: {e}")


async def heartbeat_loop(bastion_url: str, agent_name: str, interval: float = 30.0):
    """Send periodic heartbeats to Bastion."""
    import httpx

    m2m_id = AGENT_M2M_IDS.get(agent_name, agent_name)
    while True:
        await asyncio.sleep(interval)
        try:
            async with httpx.AsyncClient(timeout=5.0) as client:
                await client.post(f"{bastion_url}/m2m/activity", json={
                    "phase": "heartbeat",
                    "from_agent": m2m_id,
                    "to_agent": "bastion",
                    "action": f"Heartbeat — {agent_name} online",
                    "status": "complete",
                })
        except Exception:
            pass


async def run_agent(agent_name: str, port: int, bastion_url: str):
    """Run a single agent with Bastion registration and heartbeats."""
    factory, default_port = AGENT_FACTORIES[agent_name]
    port = port or default_port

    print()
    print("=" * 60)
    print(f"  THE LAST BASTION — Standalone Agent")
    print(f"  Agent:   {agent_name}")
    print(f"  Port:    {port}")
    print(f"  Bastion: {bastion_url}")
    print("=" * 60)
    print()

    # Register with Bastion
    await register_with_bastion(bastion_url, agent_name, port)

    # Start heartbeat loop in background
    heartbeat_task = asyncio.create_task(
        heartbeat_loop(bastion_url, agent_name)
    )

    # Start the agent server
    app = factory()
    config = uvicorn.Config(
        app.build(),
        host="0.0.0.0",
        port=port,
        log_level="info",
    )
    server = uvicorn.Server(config)

    logger.info(f"{agent_name} agent running on port {port}")

    try:
        await server.serve()
    finally:
        heartbeat_task.cancel()


def main():
    parser = argparse.ArgumentParser(
        description="Run a single A2A agent independently"
    )
    parser.add_argument(
        "--agent",
        required=True,
        choices=list(AGENT_FACTORIES.keys()),
        help="Which agent to run",
    )
    parser.add_argument(
        "--port",
        type=int,
        default=0,
        help="Port to listen on (default: agent's standard port)",
    )
    parser.add_argument(
        "--bastion-url",
        default=os.getenv("BASTION_URL", "http://localhost:8000"),
        help="The Last Bastion API URL",
    )
    args = parser.parse_args()

    asyncio.run(run_agent(args.agent, args.port, args.bastion_url))


if __name__ == "__main__":
    main()
