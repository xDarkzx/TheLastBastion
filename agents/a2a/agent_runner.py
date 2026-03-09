"""
A2A Agent Runner — Starts all 4 supply chain agents in a single process.

Each agent runs on its own port:
  - ProducerBot:   9001  (NZ farm/processor)
  - ComplianceBot: 9002  (MPI export certification)
  - LogisticsBot:  9003  (Freight & cold chain)
  - BuyerBot:      9004  (International buyer verification)

All agents are standards-compliant A2A servers with Agent Cards
at /.well-known/agent-card.json and JSON-RPC endpoints at /.

Usage:
    python agents/a2a/agent_runner.py
"""
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
logger = logging.getLogger("A2A.Runner")


async def start_agent(app, port: int, name: str):
    """Starts a single A2A agent server as an async task."""
    config = uvicorn.Config(
        app.build(),
        host="0.0.0.0",
        port=port,
        log_level="warning",
    )
    server = uvicorn.Server(config)
    logger.info(f"  {name:.<40} port {port}")
    await server.serve()


async def main():
    print()
    print("=" * 60)
    print("  THE REGISTRY BASE A2A AGENT NETWORK")
    print("  NZ Food Export Supply Chain")
    print("=" * 60)
    print()
    logger.info("Starting 4 supply chain agents...")
    print()

    producer_app, producer_card = create_producer_agent()
    compliance_app, compliance_card = create_compliance_agent()
    logistics_app, logistics_card = create_logistics_agent()
    buyer_app, buyer_card = create_buyer_agent()

    agents = [
        (producer_app, 9001, producer_card.name),
        (compliance_app, 9002, compliance_card.name),
        (logistics_app, 9003, logistics_card.name),
        (buyer_app, 9004, buyer_card.name),
    ]

    print("  Agent Cards available at:")
    for _, port, name in agents:
        print(f"    http://localhost:{port}/.well-known/agent-card.json")
    print()
    print("  JSON-RPC endpoints at:")
    for _, port, name in agents:
        print(f"    http://localhost:{port}/  ({name})")
    print()
    print("-" * 60)

    # Start all agents concurrently
    tasks = [
        asyncio.create_task(start_agent(app, port, name))
        for app, port, name in agents
    ]

    try:
        await asyncio.gather(*tasks)
    except KeyboardInterrupt:
        logger.info("Shutting down all agents...")
        for t in tasks:
            t.cancel()


if __name__ == "__main__":
    asyncio.run(main())
