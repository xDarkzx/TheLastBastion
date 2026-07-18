"""
A2A Agent Runner + Bastion Protocol — Starts all 4 supply chain agents
with both HTTP (A2A JSON-RPC) and TCP (Bastion Protocol) endpoints,
PLUS an autonomous lifecycle loop that:

  1. Registers with The Last Bastion backend
  2. Runs 10-check trust verification
  3. Trades encrypted data between agents via Bastion Protocol
  4. Detects trust decay and re-verifies automatically

  HTTP (A2A):       9001-9004
  TCP (Bastion):    9101-9104

Designed to run on Raspberry Pi or any remote host.

Environment:
    BASTION_ISSUER_PUB  — shared issuer public key (hex)
    BASTION_ISSUER_PRIV — shared issuer private key (hex)
    REGISTRY_BASE_URL   — backend address (default http://192.168.87.1:8000)
    DEMO_DECAY_MODE     — 1 = accelerated timers for demo visibility
"""
import asyncio
import logging
import os
import random
import secrets
import sys
import time
from datetime import datetime

import httpx
import uvicorn

# Add project root to path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))

from agents.a2a.producer_agent import create_producer_agent
from agents.a2a.compliance_agent import create_compliance_agent
from agents.a2a.logistics_agent import create_logistics_agent
from agents.a2a.buyer_agent import create_buyer_agent
from lastbastion.crypto import load_or_create_keypair, load_or_create_issuer_keypair

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(name)s] %(message)s",
)
logger = logging.getLogger("A2A.BastionRunner")

# Anchored to the project root, not the process's CWD — a bare relative path
# would silently regenerate "persistent" keys every time this script is
# launched from a different working directory (it's explicitly designed to
# run standalone on a separate host, so this matters more here than anywhere).
_PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

# ───────────────────────────────────────────────────────────────
# Configuration
# ───────────────────────────────────────────────────────────────
REGISTRY_BASE_URL = os.environ.get("REGISTRY_BASE_URL", "http://192.168.87.1:8000")
DEMO_MODE = os.environ.get("DEMO_DECAY_MODE", "0") == "1"

# Timers (seconds)
LOOP_INTERVAL = (5, 15) if DEMO_MODE else (20, 40)
DECAY_CHECK_INTERVAL = 300 if DEMO_MODE else 3600  # 5 min demo / 1 hr live
VERIFY_EXPIRY = 600 if DEMO_MODE else 7776000       # 10 min demo / 90 days live
TRUST_FLOOR = 0.60  # Below this → re-verify

AGENT_CONFIGS = [
    {"name": "producer", "label": "ProducerBot", "a2a_port": 9001, "bastion_port": 9101, "m2m_id": "producer-nz-001",
     "role": "DATA_PROVIDER", "capabilities": ["data_extraction", "batch_generation", "provenance"]},
    {"name": "compliance", "label": "ComplianceBot", "a2a_port": 9002, "bastion_port": 9102, "m2m_id": "compliance-mpi-001",
     "role": "VERIFIER", "capabilities": ["export_compliance", "certification", "regulation_check"]},
    {"name": "logistics", "label": "LogisticsBot", "a2a_port": 9003, "bastion_port": 9103, "m2m_id": "logistics-maersk-001",
     "role": "DATA_PROVIDER", "capabilities": ["container_tracking", "cold_chain", "shipping"]},
    {"name": "buyer", "label": "BuyerBot", "a2a_port": 9004, "bastion_port": 9104, "m2m_id": "buyer-sg-001",
     "role": "DATA_CONSUMER", "capabilities": ["purchase_verification", "cross_document_audit", "payment"]},
]


# ───────────────────────────────────────────────────────────────
# AutonomousAgent — tracks one agent's trust lifecycle
# ───────────────────────────────────────────────────────────────
class AutonomousAgent:
    def __init__(self, cfg: dict):
        self.cfg = cfg
        self.name = cfg["name"]
        self.label = cfg["label"]
        self.m2m_id = cfg["m2m_id"]
        self.bastion_port = cfg["bastion_port"]
        self.role = cfg["role"]
        self.capabilities = cfg["capabilities"]

        # Persistent Ed25519 identity — same key every run, same key used for
        # both register() and verify() (previously these each sent a fresh
        # secrets.token_hex(32) throwaway key, so the agent never actually had
        # a stable, private-key-backed identity).
        self.public_key, self.private_key = load_or_create_keypair(
            os.path.join(_PROJECT_ROOT, ".agent_keys", f"{self.name}.keys.json")
        )

        # State — populated after registration/verification
        self.api_key_id: str = ""
        self.api_secret: str = ""
        self.trust_score: float = 0.0
        self.trust_verdict: str = "PENDING"
        self.verified_at: float = 0.0  # time.time()
        self.registered: bool = False

    @property
    def needs_reverify(self) -> bool:
        if self.trust_score < TRUST_FLOOR:
            return True
        if self.verified_at == 0:
            return True
        elapsed = time.time() - self.verified_at
        return elapsed > VERIFY_EXPIRY

    async def register(self, client: httpx.AsyncClient):
        """Register with the backend M2M protocol."""
        try:
            resp = await client.post(f"{REGISTRY_BASE_URL}/m2m/register", json={
                "agent_id": self.m2m_id,
                "public_key": self.public_key,
                "role": self.role,
                "display_name": self.label,
                "capabilities": self.capabilities,
            })
            if resp.status_code == 200:
                data = resp.json()
                api_key = data.get("api_key", {})
                self.api_key_id = api_key.get("key_id", "")
                self.api_secret = api_key.get("secret", "")
                self.registered = True
                logger.info(f"REGISTER: {self.label} → key={self.api_key_id[:12]}...")
                return True
            else:
                logger.warning(f"REGISTER: {self.label} failed: {resp.status_code} {resp.text[:200]}")
        except Exception as e:
            logger.error(f"REGISTER: {self.label} error: {e}")
        return False

    async def verify(self, client: httpx.AsyncClient):
        """Run 10-check trust verification pipeline."""
        try:
            resp = await client.post(
                f"{REGISTRY_BASE_URL}/m2m/verify-agent",
                json={
                    "agent_id": self.m2m_id,
                    "agent_name": self.label,
                    "agent_url": f"http://localhost:{self.cfg['a2a_port']}",
                    "public_key": self.public_key,
                    "capabilities": self.capabilities,
                },
                headers={
                    "x-api-key-id": self.api_key_id,
                    "x-api-secret": self.api_secret,
                },
            )
            if resp.status_code == 200:
                data = resp.json()
                self.trust_score = data.get("trust_score", 0.0)
                self.trust_verdict = data.get("verdict", "UNKNOWN")
                self.verified_at = time.time()
                logger.info(f"VERIFY: {self.label} → score={self.trust_score:.2f} verdict={self.trust_verdict}")
                return True
            else:
                logger.warning(f"VERIFY: {self.label} failed: {resp.status_code} {resp.text[:200]}")
        except Exception as e:
            logger.error(f"VERIFY: {self.label} error: {e}")
        return False

    async def heartbeat(self, client: httpx.AsyncClient):
        """Send heartbeat to dashboard."""
        try:
            await client.post(f"{REGISTRY_BASE_URL}/m2m/activity", json={
                "phase": "heartbeat",
                "from_agent": self.label,
                "to_agent": "The Last Bastion",
                "action": f"Heartbeat: trust={self.trust_score:.2f}, verdict={self.trust_verdict}",
                "data_summary": {
                    "trust_score": self.trust_score,
                    "verdict": self.trust_verdict,
                    "uptime_s": int(time.time() - self.verified_at) if self.verified_at else 0,
                },
                "status": "complete",
            })
        except Exception:
            pass


# ───────────────────────────────────────────────────────────────
# Bastion Trade — encrypted data exchange between two agents
# ───────────────────────────────────────────────────────────────
async def _do_bastion_trade(agents: list, client: httpx.AsyncClient, issuer_pub: str, issuer_priv: str):
    """Pick 2 random agents and trade data via Bastion TCP on localhost."""
    if len(agents) < 2:
        return

    sender, receiver = random.sample(agents, 2)
    batch_id = f"BATCH-{secrets.token_hex(4).upper()}"
    product = random.choice(["lamb", "butter", "milk_powder", "honey", "wine", "kiwifruit"])
    quantity = random.randint(500, 5000)

    try:
        from lastbastion.protocol import AgentSocket
        from lastbastion.passport import AgentPassport

        # Create a passport for the sender — public_key is the SENDER's own
        # persistent identity key, not the issuer key.
        passport = AgentPassport(
            agent_id=sender.m2m_id,
            agent_name=sender.label,
            public_key=sender.public_key,
            trust_score=sender.trust_score,
            trust_level="VERIFIED" if sender.trust_score >= 0.70 else "BASIC",
            verdict=sender.trust_verdict,
            company_name="The Last Bastion",
            issuer="the-last-bastion",
            issuer_public_key=issuer_pub,
        ).seal()

        # Connect to receiver's Bastion TCP server on localhost
        conn = await AgentSocket.connect(
            host="localhost",
            port=receiver.bastion_port,
            passport=passport,
            signing_key=issuer_priv,
            verify_key=issuer_pub,
        )

        payload = {
            "batch_id": batch_id,
            "product": product,
            "quantity_kg": quantity,
            "sender": sender.m2m_id,
            "timestamp": datetime.utcnow().isoformat(),
        }
        await conn.send(payload)
        response = await conn.recv()
        await conn.close()

        logger.info(f"TRADE: {sender.label} → {receiver.label} | {product} {quantity}kg | batch={batch_id}")

        # Report trade to dashboard
        await client.post(f"{REGISTRY_BASE_URL}/m2m/activity", json={
            "phase": "bastion_trade",
            "from_agent": sender.label,
            "to_agent": receiver.label,
            "action": f"Encrypted Bastion trade: {product} {quantity}kg",
            "data_summary": {
                "batch_id": batch_id,
                "product": product,
                "quantity_kg": quantity,
                "sender_trust": sender.trust_score,
                "receiver_trust": receiver.trust_score,
                "protocol": "bastion_tcp",
                "encrypted": True,
            },
            "status": "complete",
        })

    except Exception as e:
        logger.warning(f"TRADE: {sender.label} → {receiver.label} failed: {e}")


# ───────────────────────────────────────────────────────────────
# Trust Check — detect decay and re-verify
# ───────────────────────────────────────────────────────────────
async def _check_and_reverify(agents: list, client: httpx.AsyncClient):
    """Check each agent's trust at the backend. Re-verify if decayed."""
    for agent in agents:
        if not agent.registered:
            continue
        try:
            resp = await client.get(f"{REGISTRY_BASE_URL}/m2m/verify-agent/{agent.m2m_id}")
            if resp.status_code == 200:
                data = resp.json()
                backend_score = data.get("trust_score", agent.trust_score)
                backend_status = data.get("status", "UNKNOWN")

                if backend_status == "EXPIRED" or backend_score < TRUST_FLOOR:
                    logger.warning(
                        f"DECAY: {agent.label} score={backend_score:.2f} status={backend_status} → re-verifying"
                    )
                    # Report decay to dashboard
                    await client.post(f"{REGISTRY_BASE_URL}/m2m/activity", json={
                        "phase": "trust_decay",
                        "from_agent": agent.label,
                        "to_agent": "The Last Bastion",
                        "action": f"Trust decayed: score={backend_score:.2f}, status={backend_status}. Initiating re-verification.",
                        "data_summary": {
                            "old_score": backend_score,
                            "old_status": backend_status,
                            "threshold": TRUST_FLOOR,
                        },
                        "status": "warning",
                    })

                    # Re-verify
                    success = await agent.verify(client)
                    if success:
                        await client.post(f"{REGISTRY_BASE_URL}/m2m/activity", json={
                            "phase": "re_verification",
                            "from_agent": agent.label,
                            "to_agent": "The Last Bastion",
                            "action": f"Re-verified: new score={agent.trust_score:.2f}, verdict={agent.trust_verdict}",
                            "data_summary": {
                                "old_score": backend_score,
                                "new_score": agent.trust_score,
                                "verdict": agent.trust_verdict,
                            },
                            "status": "complete",
                        })
                else:
                    # Update local state from backend
                    agent.trust_score = backend_score
        except Exception as e:
            logger.warning(f"TRUST_CHECK: {agent.label} error: {e}")


# ───────────────────────────────────────────────────────────────
# Autonomous Lifecycle Loop
# ───────────────────────────────────────────────────────────────
async def run_autonomous_lifecycle(agents: list, issuer_pub: str, issuer_priv: str):
    """
    Main autonomous loop:
    1. Wait for backend
    2. Register all agents
    3. Verify all agents
    4. Continuous: trade / heartbeat / trust check
    """
    mode_label = "DEMO" if DEMO_MODE else "LIVE"
    logger.info(f"LIFECYCLE: Starting autonomous loop ({mode_label} mode)")
    logger.info(f"LIFECYCLE: Backend URL: {REGISTRY_BASE_URL}")
    logger.info(f"LIFECYCLE: Loop interval: {LOOP_INTERVAL[0]}-{LOOP_INTERVAL[1]}s")
    logger.info(f"LIFECYCLE: Decay check every {DECAY_CHECK_INTERVAL}s")
    logger.info(f"LIFECYCLE: Verify expiry: {VERIFY_EXPIRY}s")

    async with httpx.AsyncClient(timeout=15.0) as client:

        # Phase 1: Wait for backend
        logger.info("LIFECYCLE [1/4]: Waiting for backend...")
        for attempt in range(30):
            try:
                resp = await client.get(f"{REGISTRY_BASE_URL}/health")
                if resp.status_code == 200:
                    logger.info(f"LIFECYCLE [1/4]: Backend reachable (attempt {attempt + 1})")
                    break
            except Exception:
                pass
            if attempt < 29:
                logger.info(f"LIFECYCLE [1/4]: Backend not ready, retrying in 10s (attempt {attempt + 1}/30)")
                await asyncio.sleep(10)
        else:
            logger.error("LIFECYCLE [1/4]: Backend unreachable after 30 attempts. Continuing anyway...")

        # Phase 2: Register all agents
        logger.info("LIFECYCLE [2/4]: Registering agents...")
        for agent in agents:
            await agent.register(client)
            await asyncio.sleep(1)

        registered = [a for a in agents if a.registered]
        logger.info(f"LIFECYCLE [2/4]: {len(registered)}/{len(agents)} agents registered")

        # Phase 3: Verify all agents
        logger.info("LIFECYCLE [3/4]: Running trust verification...")
        for agent in registered:
            await agent.verify(client)
            await asyncio.sleep(1)

        verified = [a for a in registered if a.trust_verdict != "PENDING"]
        logger.info(f"LIFECYCLE [3/4]: {len(verified)}/{len(registered)} agents verified")

        # Phase 4: Continuous loop
        logger.info("LIFECYCLE [4/4]: Entering continuous operation loop")
        last_decay_check = time.time()
        cycle = 0

        while True:
            try:
                cycle += 1
                interval = random.uniform(*LOOP_INTERVAL)
                await asyncio.sleep(interval)

                active_agents = [a for a in agents if a.registered]
                if not active_agents:
                    logger.warning("LIFECYCLE: No registered agents, waiting...")
                    await asyncio.sleep(30)
                    continue

                # Roll the dice
                roll = random.random()

                if roll < 0.40:
                    # 40%: Bastion trade
                    await _do_bastion_trade(active_agents, client, issuer_pub, issuer_priv)

                elif roll < 0.65:
                    # 25%: Heartbeat
                    agent = random.choice(active_agents)
                    await agent.heartbeat(client)
                    if cycle % 10 == 0:
                        logger.info(f"HEARTBEAT: {agent.label} cycle={cycle}")

                else:
                    # 35%: Trust check on a random agent
                    agent = random.choice(active_agents)
                    await _check_and_reverify([agent], client)

                # Periodic full decay check
                now = time.time()
                if now - last_decay_check > DECAY_CHECK_INTERVAL:
                    logger.info("LIFECYCLE: Periodic full trust check on all agents")
                    await _check_and_reverify(active_agents, client)
                    last_decay_check = now

            except asyncio.CancelledError:
                logger.info("LIFECYCLE: Shutdown requested")
                break
            except Exception as e:
                logger.error(f"LIFECYCLE: Loop error: {e}")
                await asyncio.sleep(10)


# ───────────────────────────────────────────────────────────────
# A2A + Bastion servers
# ───────────────────────────────────────────────────────────────
async def start_a2a_agent(app, port: int, name: str):
    """Start a single A2A HTTP agent server."""
    config = uvicorn.Config(app.build(), host="0.0.0.0", port=port, log_level="warning")
    server = uvicorn.Server(config)
    logger.info(f"  A2A   {name:.<35} port {port}")
    await server.serve()


async def start_bastion_servers(issuer_pub: str, issuer_priv: str):
    """Start Bastion Protocol TCP servers for all agents."""
    try:
        from lastbastion.crypto import generate_keypair
        from lastbastion.passport import AgentPassport
        from lastbastion.protocol import AgentSocket, FrameType
    except ImportError as e:
        logger.error(f"Cannot import Bastion Protocol SDK: {e}")
        logger.error("Install: pip install -e sdk/")
        return []

    servers = []
    for cfg in AGENT_CONFIGS:
        try:
            agent_public_key, _agent_private_key = load_or_create_keypair(
                os.path.join(_PROJECT_ROOT, ".agent_keys", f"{cfg['name']}.keys.json")
            )
            passport = AgentPassport(
                agent_id=cfg["m2m_id"],
                agent_name=cfg["label"],
                public_key=agent_public_key,
                trust_score=0.92,
                trust_level="VERIFIED",
                verdict="TRUSTED",
                company_name="The Last Bastion",
                issuer="the-last-bastion",
                issuer_public_key=issuer_pub,
            ).seal()

            async def make_handler(agent_cfg):
                async def handle(conn):
                    try:
                        msg = await conn.recv()
                        # Meaningful response instead of raw echo
                        batch_id = msg.get("batch_id", "unknown") if isinstance(msg, dict) else "unknown"
                        await conn.send({
                            "status": "accepted",
                            "agent": agent_cfg["name"],
                            "agent_name": agent_cfg["label"],
                            "batch_id": batch_id,
                            "trust_ack": True,
                            "processed_at": datetime.utcnow().isoformat(),
                            "host": os.environ.get("HOSTNAME", "unknown"),
                        })
                        await conn.close()
                    except Exception as e:
                        logger.warning(f"Bastion handler error ({agent_cfg['name']}): {e}")
                return handle

            handler = await make_handler(cfg)
            server = AgentSocket.listen(
                passport=passport,
                signing_key=issuer_priv,
                verify_key=issuer_pub,
                host="0.0.0.0",
                port=cfg["bastion_port"],
            )
            server.on_connect(handler)
            await server.start_background()
            servers.append(server)
            logger.info(f"  TCP   {cfg['label']:.<35} port {cfg['bastion_port']}")

        except Exception as e:
            logger.error(f"Failed to start Bastion server for {cfg['name']}: {e}")

    return servers


# ───────────────────────────────────────────────────────────────
# Main
# ───────────────────────────────────────────────────────────────
async def main():
    print()
    print("=" * 60)
    print("  THE LAST BASTION — AGENT NETWORK")
    print("  NZ Food Export Supply Chain")
    print("  A2A (HTTP) + Bastion Protocol (TCP)")
    mode_label = "DEMO" if DEMO_MODE else "LIVE"
    print(f"  Mode: {mode_label} | Backend: {REGISTRY_BASE_URL}")
    print("=" * 60)
    print()

    # Issuer keypair — env vars first, then the shared local file (read AND
    # written, unlike the old version of this block which only ever wrote the
    # file and never read it back, so it minted a brand new issuer identity —
    # invalidating every previously-issued passport — on every single restart).
    keys_file = os.path.join(_PROJECT_ROOT, ".bastion_keys.json")
    issuer_pub, issuer_priv = load_or_create_issuer_keypair(keys_file)
    logger.info(f"Issuer keypair: pub={issuer_pub[:16]}...")

    print()
    logger.info("Starting A2A HTTP servers...")
    print()

    # Create A2A agents
    producer_app, producer_card = create_producer_agent()
    compliance_app, compliance_card = create_compliance_agent()
    logistics_app, logistics_card = create_logistics_agent()
    buyer_app, buyer_card = create_buyer_agent()

    a2a_agents = [
        (producer_app, 9001, producer_card.name),
        (compliance_app, 9002, compliance_card.name),
        (logistics_app, 9003, logistics_card.name),
        (buyer_app, 9004, buyer_card.name),
    ]

    # Start A2A HTTP servers as tasks
    a2a_tasks = [
        asyncio.create_task(start_a2a_agent(app, port, name))
        for app, port, name in a2a_agents
    ]

    # Wait for A2A servers to bind
    await asyncio.sleep(1)

    # Start Bastion Protocol TCP servers
    print()
    logger.info("Starting Bastion Protocol TCP servers...")
    print()
    bastion_servers = await start_bastion_servers(issuer_pub, issuer_priv)

    print()
    print("-" * 60)
    print(f"  A2A Agent Cards:")
    for _, port, name in a2a_agents:
        print(f"    http://0.0.0.0:{port}/.well-known/agent-card.json")
    print()
    print(f"  Bastion Protocol:")
    for cfg in AGENT_CONFIGS:
        print(f"    tcp://0.0.0.0:{cfg['bastion_port']}  ({cfg['label']})")
    print()
    print(f"  Issuer Public Key: {issuer_pub[:32]}...")
    print("-" * 60)
    print()

    # Create AutonomousAgent instances and start lifecycle
    autonomous_agents = [AutonomousAgent(cfg) for cfg in AGENT_CONFIGS]
    lifecycle_task = asyncio.create_task(
        run_autonomous_lifecycle(autonomous_agents, issuer_pub, issuer_priv)
    )

    try:
        await asyncio.gather(*a2a_tasks, lifecycle_task)
    except KeyboardInterrupt:
        logger.info("Shutting down...")
        lifecycle_task.cancel()
        for t in a2a_tasks:
            t.cancel()
        for srv in bastion_servers:
            try:
                await srv.stop()
            except Exception:
                pass


if __name__ == "__main__":
    asyncio.run(main())
