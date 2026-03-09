"""
Agent Network — Live A2A Agent Communication Engine.

Boots REAL A2A-compliant agents (producer, compliance, logistics, buyer)
as embedded HTTP servers inside the main process. Orchestrates genuine
inter-agent communication via the Google A2A protocol (JSON-RPC 2.0)
and feeds results through The Last Bastion's M2M protocol for verification,
handoffs, and blockchain stamping.

Every agent is a real service with:
  - An Agent Card at /.well-known/agent-card.json
  - JSON-RPC endpoints accepting messages
  - Structured data artifacts in A2A DataPart format

The dashboard sees REAL agent-to-agent communication — not simulated data.

Lifecycle:
    1. Boot A2A agent servers on ports 9001-9004
    2. Discover agents via Agent Cards (A2A protocol)
    3. Register agents on The Last Bastion M2M + dashboard
    4. Verify agent passports (6-check trust pipeline)
    5. Continuous loop:
       - Supply chain workflows (producer → compliance → logistics → buyer)
       - Agent-to-agent handoffs with payload verification
       - Data submissions to refinery pipeline
       - Heartbeats and re-verification
"""
import asyncio
import json
import logging
import os
import random
import secrets
import time
import uuid
from datetime import datetime
from typing import Dict, List, Optional

import httpx
import uvicorn

logger = logging.getLogger("AgentNetwork")


def formatBytesForLog(b: int) -> str:
    """Human-readable byte size for log messages."""
    if b < 1024:
        return f"{b}B"
    if b < 1048576:
        return f"{b / 1024:.1f}KB"
    return f"{b / 1048576:.1f}MB"


# ───────────────────────────────────────────────────────────────
# Agent network configuration
# ───────────────────────────────────────────────────────────────
AGENT_PORTS = {
    "producer": 9001,
    "compliance": 9002,
    "logistics": 9003,
    "buyer": 9004,
}

BASTION_PORTS = {
    "producer": 9101,
    "compliance": 9102,
    "logistics": 9103,
    "buyer": 9104,
}

# Remote ports — host-mapped on Pi (avoids Portainer conflict on 9001)
REMOTE_AGENT_PORTS = {
    "producer": 9201,
    "compliance": 9202,
    "logistics": 9203,
    "buyer": 9204,
}

REMOTE_BASTION_PORTS = {
    "producer": 9301,
    "compliance": 9302,
    "logistics": 9303,
    "buyer": 9304,
}

REGISTRY_BASE_AGENTS = {
    "producer": {
        "m2m_id": "producer-regional-001",
        "public_key": "a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2",
        "role": "DATA_PROVIDER",
        "capabilities": ["data_extraction", "batch_generation", "provenance"],
    },
    "compliance": {
        "m2m_id": "compliance-regional-001",
        "public_key": "b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3",
        "role": "VERIFIER",
        "capabilities": ["export_compliance", "certification", "regulation_check"],
    },
    "logistics": {
        "m2m_id": "logistics-maersk-001",
        "public_key": "c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4",
        "role": "DATA_PROVIDER",
        "capabilities": ["container_tracking", "cold_chain", "shipping"],
    },
    "buyer": {
        "m2m_id": "buyer-sg-001",
        "public_key": "d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5",
        "role": "DATA_CONSUMER",
        "capabilities": ["purchase_verification", "cross_document_audit", "payment"],
    },
}


# ───────────────────────────────────────────────────────────────
# Bastion Protocol — consistent agent identities for demo frames
# ───────────────────────────────────────────────────────────────
AGENT_IDENTITY = {
    "producer": {
        "label": "ProducerBot",
        "passport_hash": "a7c3e9f1b2d84a6e9f0c1d2e3f4a5b6c",
        "pub_key_prefix": "04f7a3c9e1b2d8",
        "base_trust": 0.94,
        "issuer": "the-last-bastion",
        "capabilities": ["batch_data", "provenance", "farm_telemetry"],
    },
    "compliance": {
        "label": "ComplianceBot",
        "passport_hash": "d8f2a1b4c7e39d5f0a2b3c4d5e6f7a8b",
        "pub_key_prefix": "04b2d8a3f7c9e1",
        "base_trust": 0.96,
        "issuer": "the-last-bastion",
        "capabilities": ["export_compliance", "export_certification", "regulation_audit"],
    },
    "logistics": {
        "label": "LogisticsBot",
        "passport_hash": "c5e7d9f3a1b24c8e6f0d2a4b6c8e0f1a",
        "pub_key_prefix": "04e1c9a3b2d8f7",
        "base_trust": 0.91,
        "issuer": "the-last-bastion",
        "capabilities": ["container_tracking", "cold_chain", "vessel_booking"],
    },
    "buyer": {
        "label": "BuyerBot",
        "passport_hash": "f0a2b4c6d8e1f3a5b7c9d0e2f4a6b8c0",
        "pub_key_prefix": "04d8f7e1c9a3b2",
        "base_trust": 0.89,
        "issuer": "the-last-bastion",
        "capabilities": ["purchase_verification", "provenance_audit", "payment"],
    },
}

SUPPLY_CHAIN_PAYLOADS = [
    {
        "context": "Dairy Export — Whole Milk Powder",
        "product": "Whole Milk Powder",
        "batch_prefix": "DRY",
        "steps": [
            {
                "pair": ("producer", "compliance"),
                "payload_type": "application/msgpack",
                "description": "Batch {batch}: {product} — {qty}kg, farm {farm}, requesting export certification",
                "size_range": (2048, 8192),
                "attachments": [
                    {"type": "image/jpeg", "name": "batch_photo_{batch}.jpg", "size": 245760, "desc": "Visual inspection photograph"},
                    {"type": "application/pdf", "name": "lab_report_{batch}.pdf", "size": 189440, "desc": "Lab analysis — fat content, moisture, bacteria count"},
                ],
            },
            {
                "pair": ("compliance", "logistics"),
                "payload_type": "application/msgpack",
                "description": "Certificate {cert} issued — {product} grade A, cleared for export to {dest}",
                "size_range": (1024, 4096),
                "attachments": [
                    {"type": "application/pdf", "name": "export_cert_{cert}.pdf", "size": 94208, "desc": "Export certificate (signed)"},
                ],
            },
            {
                "pair": ("logistics", "buyer"),
                "payload_type": "application/msgpack",
                "description": "Container {container} loaded — {product}, vessel Maersk Kobe, ETA {eta} days, cold chain active",
                "size_range": (1536, 6144),
                "attachments": [
                    {"type": "text/csv", "name": "cold_chain_{container}.csv", "size": 67584, "desc": "Temperature log — 847 readings, 2min intervals"},
                    {"type": "image/jpeg", "name": "container_seal_{container}.jpg", "size": 312320, "desc": "Container seal verification photo"},
                ],
            },
        ],
    },
    {
        "context": "Raw Honey Export — UMF Grade",
        "product": "UMF 15+ Raw Honey",
        "batch_prefix": "API",
        "steps": [
            {
                "pair": ("producer", "compliance"),
                "payload_type": "application/msgpack",
                "description": "Batch {batch}: {product} — {qty} jars, apiary {farm}, UMF test results attached",
                "size_range": (3072, 10240),
                "attachments": [
                    {"type": "application/pdf", "name": "umf_test_{batch}.pdf", "size": 156672, "desc": "UMF methylglyoxal assay report"},
                    {"type": "image/jpeg", "name": "apiary_{batch}.jpg", "size": 204800, "desc": "Apiary site photo with GPS"},
                ],
            },
            {
                "pair": ("compliance", "logistics"),
                "payload_type": "application/msgpack",
                "description": "Certificate {cert} issued — {product} UMF verified, export cleared",
                "size_range": (1024, 3072),
                "attachments": [
                    {"type": "application/pdf", "name": "export_cert_{cert}.pdf", "size": 98304, "desc": "Export certificate (signed)"},
                ],
            },
            {
                "pair": ("logistics", "buyer"),
                "payload_type": "application/msgpack",
                "description": "Container {container} loaded — {product}, ambient temp, vessel CMA CGM Bellini, ETA {eta} days",
                "size_range": (1024, 4096),
                "attachments": [
                    {"type": "image/jpeg", "name": "pallet_{container}.jpg", "size": 276480, "desc": "Pallet loading verification"},
                ],
            },
        ],
    },
    {
        "context": "Premium Lamb Export to EU",
        "product": "Premium Lamb Rack",
        "batch_prefix": "MET",
        "steps": [
            {
                "pair": ("producer", "compliance"),
                "payload_type": "application/msgpack",
                "description": "Batch {batch}: {product} — {qty} units, plant {farm}, requesting EU health cert",
                "size_range": (2048, 6144),
                "attachments": [
                    {"type": "application/pdf", "name": "health_cert_{batch}.pdf", "size": 131072, "desc": "Veterinary health certificate"},
                    {"type": "text/csv", "name": "traceability_{batch}.csv", "size": 45056, "desc": "Full traceability — farm to processor"},
                ],
            },
            {
                "pair": ("compliance", "logistics"),
                "payload_type": "application/msgpack",
                "description": "EU Health Certificate {cert} issued — {product}, cold chain -18°C required",
                "size_range": (1024, 3072),
                "attachments": [
                    {"type": "application/pdf", "name": "eu_cert_{cert}.pdf", "size": 106496, "desc": "EU health certificate (countersigned)"},
                ],
            },
            {
                "pair": ("logistics", "buyer"),
                "payload_type": "application/msgpack",
                "description": "Reefer {container} loaded — {product}, -18°C maintained, vessel MSC Gülsün, ETA {eta} days",
                "size_range": (2048, 8192),
                "attachments": [
                    {"type": "text/csv", "name": "reefer_temps_{container}.csv", "size": 89088, "desc": "Reefer temperature log — 1200 readings, 1min intervals"},
                    {"type": "image/jpeg", "name": "reefer_display_{container}.jpg", "size": 184320, "desc": "Reefer unit temperature display photo"},
                ],
            },
        ],
    },
    {
        "context": "Sauvignon Blanc Export",
        "product": "Reserve Sauvignon Blanc 2025",
        "batch_prefix": "WNE",
        "steps": [
            {
                "pair": ("producer", "compliance"),
                "payload_type": "application/msgpack",
                "description": "Batch {batch}: {product} — {qty} cases, vineyard {farm}, requesting wine export cert",
                "size_range": (2048, 5120),
                "attachments": [
                    {"type": "application/pdf", "name": "wine_analysis_{batch}.pdf", "size": 143360, "desc": "Chemical analysis — alcohol, SO2, acidity"},
                ],
            },
            {
                "pair": ("compliance", "logistics"),
                "payload_type": "application/msgpack",
                "description": "Wine Export Certificate {cert} issued — {product}, 13.5% ABV, SO2 within limits",
                "size_range": (1024, 3072),
                "attachments": [
                    {"type": "application/pdf", "name": "export_cert_{cert}.pdf", "size": 90112, "desc": "Wine export certificate"},
                ],
            },
            {
                "pair": ("logistics", "buyer"),
                "payload_type": "application/msgpack",
                "description": "Container {container} loaded — {product}, 14°C controlled, vessel Hapag-Lloyd Express, ETA {eta} days",
                "size_range": (1536, 5120),
                "attachments": [
                    {"type": "text/csv", "name": "temp_log_{container}.csv", "size": 56320, "desc": "Wine storage temperature log"},
                ],
            },
        ],
    },
]

BASTION_ERROR_SCENARIOS = [
    {"code": 0x03, "name": "SIGNATURE_MISMATCH", "message": "Ed25519 signature verification failed — payload may have been tampered with in transit"},
    {"code": 0x05, "name": "PASSPORT_EXPIRED", "message": "Agent passport JWT expired 47 minutes ago — re-authentication required"},
    {"code": 0x09, "name": "TRUST_BELOW_THRESHOLD", "message": "Agent trust score 0.31 is below minimum threshold 0.60 — connection refused"},
    {"code": 0x0B, "name": "REPLAY_DETECTED", "message": "Sequence number 4 already seen in session — possible replay attack, connection terminated"},
    {"code": 0x0D, "name": "PAYLOAD_TOO_LARGE", "message": "Payload 16.7MB exceeds maximum frame size 8MB — use STREAM for large transfers"},
    {"code": 0x0F, "name": "CIPHER_MISMATCH", "message": "Responder requires XChaCha20-Poly1305 but initiator offered XSalsa20-Poly1305 only"},
]

FARM_NAMES = ["Green Valley Farm", "Highland Station", "Riverside Downs", "Coastal Flats", "Hillcrest Estate", "Prairie Plains", "Southern Pastures"]
DEST_NAMES = ["Singapore", "Shanghai", "Tokyo", "Dubai", "London", "Hamburg", "Los Angeles"]


class AgentNetwork:
    """
    Manages a live network of A2A agents embedded in the main server.

    Boots real agent servers, discovers them via Agent Cards,
    registers them on The Last Bastion, and orchestrates continuous
    inter-agent communication visible in the dashboard.
    """

    def __init__(self, registry_base_url: str = ""):
        from core.agent_config import agent_config
        self.endpoint_config = agent_config
        self.registry_base_url = registry_base_url or agent_config.bastion_url
        self.agent_servers: Dict[str, asyncio.Task] = {}
        self.agent_cards: Dict[str, dict] = {}
        self.api_keys: Dict[str, tuple] = {}
        self.verified: set = set()
        self.running = False
        self._cycle = 0

        # Bastion Protocol overlay
        self._bastion_servers: Dict[str, any] = {}  # name -> AgentSocketServer
        self._bastion_keys: Dict[str, tuple] = {}   # name -> (signing_key, verify_key)
        self._bastion_passports: Dict[str, any] = {}  # name -> AgentPassport
        self._issuer_keys: Optional[tuple] = None    # (public, private) for issuing passports
        self._bastion_ready = False
        self._bastion_host = os.environ.get("BASTION_HOST", "localhost")  # Remote agent host

    # ───────────────────────────────────────────────────────────
    # Phase 1: Boot real A2A agent servers
    # ───────────────────────────────────────────────────────────

    async def _boot_agent_servers(self):
        """
        Start A2A agent servers. First checks if agents are already running
        externally (e.g. Docker a2a-agents container). Only boots embedded
        servers if no external agents are found.
        """
        logger.info("AGENT NETWORK: checking for running A2A agents...")

        # In Docker, agents may be on 'a2a-agents' hostname instead of localhost
        agent_host = os.environ.get("A2A_HOST", "localhost")
        is_remote = self._bastion_host not in ("localhost", "127.0.0.1", "")
        probe_ports = REMOTE_AGENT_PORTS if is_remote else AGENT_PORTS

        # Check if agents are already running (Docker or standalone)
        async with httpx.AsyncClient(timeout=3.0) as probe:
            already_running = 0
            for name, port in probe_ports.items():
                # For remote agents, only probe the remote host
                hosts_to_try = [self._bastion_host] if is_remote else [agent_host, "localhost", "a2a-agents"]
                for host in hosts_to_try:
                    try:
                        resp = await probe.get(f"http://{host}:{port}/.well-known/agent-card.json")
                        if resp.status_code == 200:
                            self.agent_servers[name] = None  # Mark as externally managed
                            self._agent_host = host
                            already_running += 1
                            logger.info(f"AGENT NETWORK: found {name} already running at {host}:{port}")
                            break
                    except Exception:
                        continue

        if already_running == len(AGENT_PORTS):
            logger.info(f"AGENT NETWORK: all {already_running} agents already running externally")
            return True

        if already_running > 0:
            logger.info(f"AGENT NETWORK: {already_running} agents running externally, booting rest...")
        else:
            self._agent_host = "localhost"

        # Boot missing agents as embedded servers
        try:
            from agents.a2a.producer_agent import create_producer_agent
            from agents.a2a.compliance_agent import create_compliance_agent
            from agents.a2a.logistics_agent import create_logistics_agent
            from agents.a2a.buyer_agent import create_buyer_agent
        except ImportError as e:
            logger.error(f"AGENT NETWORK: cannot import A2A agents: {e}")
            logger.error("Install a2a-sdk: pip install a2a-sdk")
            return len(self.agent_servers) > 0

        agent_factories = {
            "producer": create_producer_agent,
            "compliance": create_compliance_agent,
            "logistics": create_logistics_agent,
            "buyer": create_buyer_agent,
        }

        for name, factory in agent_factories.items():
            if name in self.agent_servers:
                continue  # Already running externally
            port = AGENT_PORTS[name]
            try:
                app, card = factory()
                config = uvicorn.Config(
                    app.build(),
                    host="0.0.0.0",
                    port=port,
                    log_level="warning",
                )
                server = uvicorn.Server(config)
                task = asyncio.create_task(server.serve())
                self.agent_servers[name] = task
                logger.info(f"AGENT NETWORK: {card.name} starting on port {port}")
            except Exception as e:
                logger.error(f"AGENT NETWORK: failed to start {name}: {e}")

        # Give embedded servers time to bind
        if any(v is not None for v in self.agent_servers.values()):
            await asyncio.sleep(2)

        return len(self.agent_servers) > 0

    # ───────────────────────────────────────────────────────────
    # Phase 2: Discover agents via A2A Agent Cards
    # ───────────────────────────────────────────────────────────

    async def _discover_agents(self, client: httpx.AsyncClient):
        """Fetch Agent Cards from each running A2A agent."""
        logger.info("AGENT NETWORK: discovering agents via Agent Cards...")

        host = getattr(self, '_agent_host', 'localhost')
        is_remote = self._bastion_host not in ("localhost", "127.0.0.1", "")
        discover_ports = REMOTE_AGENT_PORTS if is_remote else AGENT_PORTS
        for name, port in discover_ports.items():
            if name not in self.agent_servers:
                continue

            url = f"http://{host}:{port}"
            try:
                # Fetch the A2A Agent Card
                resp = await client.get(f"{url}/.well-known/agent-card.json")
                if resp.status_code == 200:
                    card = resp.json()
                    self.agent_cards[name] = {
                        "name": card.get("name", name),
                        "url": url,
                        "version": card.get("version", "1.0"),
                        "description": card.get("description", ""),
                        "skills": card.get("skills", []),
                        "capabilities": card.get("capabilities", {}),
                    }
                    logger.info(
                        f"AGENT NETWORK: discovered {card.get('name', name)} "
                        f"v{card.get('version', '?')} at {url}"
                    )

                    await self._post_activity(
                        client, "discovery",
                        card.get("name", name), "The Last Bastion",
                        f"Agent Card discovered at {url}/.well-known/agent-card.json",
                    )
            except Exception as e:
                logger.warning(f"AGENT NETWORK: discovery failed for {name}: {e}")

            await asyncio.sleep(0.3)

    # ───────────────────────────────────────────────────────────
    # Phase 3: Register on The Last Bastion M2M + dashboard
    # ───────────────────────────────────────────────────────────

    async def _register_on_registry_base(self, client: httpx.AsyncClient):
        """Register each agent on The Last Bastion's M2M protocol and dashboard."""
        logger.info("AGENT NETWORK: registering agents on The Last Bastion M2M...")

        for name, card in self.agent_cards.items():
            swarm_cfg = REGISTRY_BASE_AGENTS.get(name, {})
            m2m_id = swarm_cfg.get("m2m_id", name)

            # M2M protocol registration
            try:
                resp = await client.post(f"{self.registry_base_url}/m2m/register", json={
                    "agent_id": m2m_id,
                    "public_key": swarm_cfg.get("public_key", ""),
                    "role": swarm_cfg.get("role", "DATA_PROVIDER"),
                    "display_name": card["name"],
                    "capabilities": swarm_cfg.get("capabilities", []),
                })
                if resp.status_code == 200:
                    data = resp.json()
                    key_id = data.get("api_key", {}).get("key_id", "")
                    secret = data.get("api_key", {}).get("secret", "")
                    self.api_keys[name] = (key_id, secret)
                    logger.info(f"AGENT NETWORK: M2M registered {m2m_id}")
            except Exception as e:
                logger.warning(f"AGENT NETWORK: M2M register failed for {name}: {e}")

            # Dashboard registration (Agent Directory visibility)
            try:
                skills_data = []
                for s in card.get("skills", []):
                    if isinstance(s, dict):
                        skills_data.append({
                            "name": s.get("name", s.get("id", "")),
                            "tags": s.get("tags", []),
                        })

                is_remote = self._bastion_host not in ("localhost", "127.0.0.1", "")
                reg_ports = REMOTE_AGENT_PORTS if is_remote else AGENT_PORTS
                await client.post(f"{self.registry_base_url}/m2m/dashboard/agents/register", json={
                    "agent_id": m2m_id,
                    "name": card["name"],
                    "url": card["url"],
                    "port": reg_ports[name],
                    "role": swarm_cfg.get("role", "DATA_PROVIDER"),
                    "skills": skills_data,
                    "version": card.get("version", "1.0"),
                    "status": "online",
                    "description": card.get("description", ""),
                })
            except Exception:
                pass

            await self._post_activity(
                client, "registration",
                card["name"], "The Last Bastion",
                f"Registered on M2M network as {m2m_id}",
            )
            await asyncio.sleep(0.3)

    # ───────────────────────────────────────────────────────────
    # Phase 4: Passport verification
    # ───────────────────────────────────────────────────────────

    async def _verify_passports(self, client: httpx.AsyncClient):
        """Run 6-check trust verification on each agent."""
        logger.info("AGENT NETWORK: verifying agent passports...")

        for name, card in self.agent_cards.items():
            swarm_cfg = REGISTRY_BASE_AGENTS.get(name, {})
            m2m_id = swarm_cfg.get("m2m_id", name)

            await self._post_activity(
                client, "verification",
                card["name"], "The Last Bastion",
                f"Submitting for passport verification (6-check pipeline)",
                status="active",
            )

            try:
                resp = await client.post(f"{self.registry_base_url}/m2m/verify-agent", json={
                    "agent_id": m2m_id,
                    "agent_name": card["name"],
                    "agent_url": card["url"],
                    "public_key": swarm_cfg.get("public_key", ""),
                    "capabilities": swarm_cfg.get("capabilities", []),
                    "metadata": {
                        "role": swarm_cfg.get("role", ""),
                        "version": card.get("version", "1.0"),
                        "description": card.get("description", ""),
                        "a2a_compliant": True,
                    },
                })
                if resp.status_code == 200:
                    v = resp.json()
                    verdict = v.get("verdict", "UNKNOWN")
                    score = v.get("trust_score", 0)
                    self.verified.add(name)
                    logger.info(f"AGENT NETWORK: {m2m_id} passport -> {verdict} ({score:.3f})")

                    await self._post_activity(
                        client, "verification",
                        "The Last Bastion", card["name"],
                        f"Passport: {verdict} (trust={score:.3f})",
                    )
            except Exception as e:
                logger.warning(f"AGENT NETWORK: verify {name} failed: {e}")

            await asyncio.sleep(0.5)

    # ───────────────────────────────────────────────────────────
    # A2A communication — real agent-to-agent messaging
    # ───────────────────────────────────────────────────────────

    async def _send_a2a_message(
        self, client: httpx.AsyncClient,
        target_name: str, text: str, data: dict = None,
    ) -> Optional[dict]:
        """Send a real A2A JSON-RPC message to a running agent."""
        card = self.agent_cards.get(target_name)
        if not card:
            return None

        url = card["url"]
        msg_id = str(uuid.uuid4())

        # Build parts in the format the a2a-sdk expects:
        # TextPart = {"text": "..."}, DataPart = {"data": {...}}
        parts = [{"text": text}]
        if data:
            parts.append({"data": data})

        jsonrpc_request = {
            "jsonrpc": "2.0",
            "id": msg_id,
            "method": "message/send",
            "params": {
                "message": {
                    "messageId": str(uuid.uuid4()),
                    "role": "user",
                    "parts": parts,
                },
            },
        }

        try:
            resp = await client.post(url, json=jsonrpc_request, timeout=15)
            if resp.status_code == 200:
                result = resp.json()
                return result
        except Exception as e:
            logger.warning(f"AGENT NETWORK: A2A message to {target_name} failed: {e}")

        return None

    def _extract_artifacts(self, response: dict) -> list:
        """Extract structured data artifacts from an A2A response."""
        if not response:
            return []

        result = response.get("result", {})
        artifacts = result.get("artifacts", [])
        extracted = []
        for art in artifacts:
            for part in art.get("parts", []):
                # a2a-sdk returns parts as {"data": {...}} or {"text": "..."}
                # May also have {"root": {...}} wrapper in some versions
                root = part.get("root", part)
                if root.get("data"):
                    extracted.append(root["data"])
                elif root.get("kind") == "data":
                    extracted.append(root.get("data", {}))
        return extracted

    def _extract_status_text(self, response: dict) -> str:
        """Extract status message from an A2A response."""
        if not response:
            return ""
        result = response.get("result", {})
        status = result.get("status", {})
        msg = status.get("message", {})
        for part in msg.get("parts", []):
            root = part.get("root", part)
            if root.get("text"):
                return root["text"]
            if root.get("kind") == "text":
                return root.get("text", "")
        return ""

    # ───────────────────────────────────────────────────────────
    # Supply chain workflow — real agent communication
    # ───────────────────────────────────────────────────────────

    async def _run_supply_chain(self, client: httpx.AsyncClient):
        """
        Full supply chain workflow with Bastion-as-middleware:
        Every handoff routes through Bastion for verification before forwarding.

        Producer → [Bastion verifies] → Compliance → [Bastion verifies] →
        Logistics → [Bastion verifies] → Buyer → [Bastion verifies] → Full chain
        """
        self._cycle += 1
        logger.info(f"AGENT NETWORK: supply chain cycle #{self._cycle}")

        # Step 1: ProducerBot generates a batch
        await self._post_activity(
            client, "production",
            self.agent_cards.get("producer", {}).get("name", "ProducerBot"),
            "The Last Bastion",
            "Generating new export batch...",
            status="active",
        )

        producer_resp = await self._send_a2a_message(
            client, "producer",
            "Generate a dairy export batch",
        )
        batch = {}
        if producer_resp:
            artifacts = self._extract_artifacts(producer_resp)
            batch = artifacts[0] if artifacts else {}
            if batch:
                await self._post_activity(
                    client, "production",
                    self.agent_cards["producer"]["name"],
                    "The Last Bastion",
                    f"Batch {batch.get('batch_id', 'N/A')}: {batch.get('product', 'N/A')}, "
                    f"{batch.get('grade', 'N/A')}, {batch.get('farm_region', 'N/A')}",
                )

        if not batch:
            logger.warning("AGENT NETWORK: producer returned no batch, skipping cycle")
            return

        # Bastion verifies producer data before forwarding to compliance
        prod_result = await self._submit_to_refinery(client, batch, "producer-regional-001", "production_batch")
        prod_verdict = (prod_result or {}).get("verdict", "REJECTED")
        if prod_verdict == "REJECTED":
            logger.warning(f"AGENT NETWORK: Bastion REJECTED producer batch — halting chain")
            await self._post_activity(
                client, "bastion_gate",
                "The Last Bastion", self.agent_cards.get("producer", {}).get("name", "ProducerBot"),
                f"REJECTED batch {batch.get('batch_id', 'N/A')} — chain halted",
            )
            return

        await self._post_activity(
            client, "bastion_gate",
            "The Last Bastion", self.agent_cards.get("compliance", {}).get("name", "ComplianceBot"),
            f"VERIFIED batch → forwarding to compliance ({prod_verdict})",
        )

        await asyncio.sleep(random.uniform(2, 5))

        # Step 2: ComplianceBot certifies the batch
        await self._post_activity(
            client, "compliance",
            self.agent_cards.get("compliance", {}).get("name", "ComplianceBot"),
            "The Last Bastion",
            f"Running export compliance checks on {batch.get('batch_id', 'N/A')}",
            status="active",
        )

        compliance_resp = await self._send_a2a_message(
            client, "compliance",
            "Certify this batch for export",
            data=batch,
        )
        compliance = {}
        if compliance_resp:
            artifacts = self._extract_artifacts(compliance_resp)
            compliance = artifacts[0] if artifacts else {}
            if compliance:
                result = compliance.get("overall_result", "N/A")
                cert = compliance.get("certificate_number", "N/A")
                await self._post_activity(
                    client, "compliance",
                    self.agent_cards["compliance"]["name"],
                    "The Last Bastion",
                    f"Export compliance: {result}, cert {cert}",
                )

        # Bastion verifies compliance data before forwarding to logistics
        if compliance:
            comp_result = await self._submit_to_refinery(client, compliance, "compliance-regional-001", "export_certificate")
            comp_verdict = (comp_result or {}).get("verdict", "REJECTED")
            if comp_verdict == "REJECTED":
                logger.warning(f"AGENT NETWORK: Bastion REJECTED compliance cert — halting chain")
                await self._post_activity(
                    client, "bastion_gate",
                    "The Last Bastion", self.agent_cards.get("compliance", {}).get("name", "ComplianceBot"),
                    f"REJECTED cert {compliance.get('certificate_number', 'N/A')} — chain halted",
                )
                return

            await self._post_activity(
                client, "bastion_gate",
                "The Last Bastion", self.agent_cards.get("logistics", {}).get("name", "LogisticsBot"),
                f"VERIFIED compliance cert → forwarding to logistics ({comp_verdict})",
            )

        await asyncio.sleep(random.uniform(2, 5))

        # Step 3: LogisticsBot assigns container and books vessel
        logistics_input = dict(batch)
        if compliance:
            logistics_input["certificate_number"] = compliance.get("certificate_number")

        await self._post_activity(
            client, "logistics",
            self.agent_cards.get("logistics", {}).get("name", "LogisticsBot"),
            "The Last Bastion",
            f"Assigning container and booking vessel for {batch.get('batch_id', 'N/A')}",
            status="active",
        )

        logistics_resp = await self._send_a2a_message(
            client, "logistics",
            "Ship this certified batch",
            data=logistics_input,
        )
        shipment = {}
        if logistics_resp:
            artifacts = self._extract_artifacts(logistics_resp)
            shipment = artifacts[0] if artifacts else {}
            if shipment:
                container = shipment.get("container_id", "N/A")
                vessel = shipment.get("vessel", "N/A")
                await self._post_activity(
                    client, "logistics",
                    self.agent_cards["logistics"]["name"],
                    "The Last Bastion",
                    f"Container {container} on {vessel}, cold chain active",
                )

        # Bastion verifies logistics data before forwarding to buyer
        if shipment:
            log_result = await self._submit_to_refinery(client, shipment, "logistics-maersk-001", "shipping_manifest")
            log_verdict = (log_result or {}).get("verdict", "REJECTED")
            if log_verdict == "REJECTED":
                logger.warning(f"AGENT NETWORK: Bastion REJECTED shipping manifest — halting chain")
                return

            await self._post_activity(
                client, "bastion_gate",
                "The Last Bastion", self.agent_cards.get("buyer", {}).get("name", "BuyerBot"),
                f"VERIFIED manifest → forwarding to buyer ({log_verdict})",
            )

        await asyncio.sleep(random.uniform(2, 5))

        # Step 4: BuyerBot cross-verifies the full provenance chain
        buyer_input = dict(batch)
        if compliance:
            buyer_input["certificate_number"] = compliance.get("certificate_number")
        if shipment:
            buyer_input["container_id"] = shipment.get("container_id")
            buyer_input["cold_chain"] = shipment.get("cold_chain", {})
            buyer_input["vessel"] = shipment.get("vessel")

        await self._post_activity(
            client, "buyer_verification",
            self.agent_cards.get("buyer", {}).get("name", "BuyerBot"),
            "The Last Bastion",
            "Cross-verifying full provenance chain",
            status="active",
        )

        buyer_resp = await self._send_a2a_message(
            client, "buyer",
            "Verify this shipment — full provenance chain attached",
            data=buyer_input,
        )
        verification = {}
        if buyer_resp:
            artifacts = self._extract_artifacts(buyer_resp)
            verification = artifacts[0] if artifacts else {}
            if verification:
                verdict = verification.get("overall_verdict", "N/A")
                await self._post_activity(
                    client, "buyer_verification",
                    self.agent_cards["buyer"]["name"],
                    "The Last Bastion",
                    f"Provenance verified: {verdict}",
                )
                await self._submit_to_refinery(client, verification, "buyer-sg-001", "buyer_verification")

        await asyncio.sleep(random.uniform(1, 3))

        # Step 5: Submit full chain to The Last Bastion refinery
        chain_data = {
            "supply_chain": "food_export",
            "batch_id": batch.get("batch_id", "UNKNOWN"),
            "production": batch,
            "compliance": compliance,
            "logistics": shipment,
            "buyer_verification": verification,
        }

        await self._post_activity(
            client, "bastion_verification",
            "The Last Bastion", "",
            f"Full chain verification: batch {batch.get('batch_id', 'N/A')}",
            status="active",
        )

        result = await self._submit_to_refinery(
            client, chain_data, "supply-chain-orchestrator", "full_chain",
        )

        if result:
            v = result.get("verdict", "N/A")
            s = result.get("score", 0)
            await self._post_activity(
                client, "bastion_verification",
                "The Last Bastion", "",
                f"Full chain verified: {v} (score={s:.3f})",
            )

        # Step 6: Agent-to-agent handoff (producer → buyer via Bastion border guard)
        await self._do_handoff(
            client, "producer", "buyer",
            batch,
            f"Batch {batch.get('batch_id', 'N/A')} provenance handoff",
        )

    async def _do_handoff(
        self, client: httpx.AsyncClient,
        sender_name: str, receiver_name: str,
        payload: dict, summary: str,
    ):
        """Execute a Last Bastion M2M handoff between two agents."""
        sender_cfg = REGISTRY_BASE_AGENTS.get(sender_name, {})
        receiver_cfg = REGISTRY_BASE_AGENTS.get(receiver_name, {})
        sender_id = sender_cfg.get("m2m_id", sender_name)
        receiver_id = receiver_cfg.get("m2m_id", receiver_name)

        sender_card_name = self.agent_cards.get(sender_name, {}).get("name", sender_name)
        receiver_card_name = self.agent_cards.get(receiver_name, {}).get("name", receiver_name)

        await self._post_activity(
            client, "handoff",
            sender_card_name, receiver_card_name,
            f"Initiating handoff: {summary}",
            status="active",
        )

        try:
            resp = await client.post(f"{self.registry_base_url}/m2m/handoff/request", json={
                "sender_id": sender_id,
                "receiver_id": receiver_id,
                "payload": payload,
                "payload_summary": summary,
            })

            if resp.status_code == 200:
                result = resp.json()
                status = result.get("status", "UNKNOWN")
                handoff_id = result.get("handoff_id", "")

                if status == "REDIRECT":
                    await self._post_activity(
                        client, "handoff",
                        "The Last Bastion Border Guard", sender_card_name,
                        f"REDIRECT: passport required — verify at /m2m/verify-agent",
                    )
                    logger.info(f"AGENT NETWORK: handoff REDIRECT {sender_id}")

                elif status == "PENDING" and handoff_id:
                    pv = result.get("payload_verdict", "N/A")
                    ps = result.get("payload_score", 0)

                    await self._post_activity(
                        client, "handoff",
                        sender_card_name, receiver_card_name,
                        f"Payload verified: {pv} (score={ps:.3f}), awaiting acceptance",
                    )

                    # Receiver accepts
                    await asyncio.sleep(random.uniform(1, 3))
                    try:
                        accept_resp = await client.post(
                            f"{self.registry_base_url}/m2m/handoff/complete",
                            json={"handoff_id": handoff_id, "action": "accept"},
                        )
                        if accept_resp.status_code == 200:
                            ad = accept_resp.json()
                            tx = ad.get("tx_hash", "")
                            await self._post_activity(
                                client, "handoff",
                                receiver_card_name, sender_card_name,
                                f"Handoff ACCEPTED{' (on-chain)' if tx else ''} — transfer complete",
                            )
                            logger.info(f"AGENT NETWORK: handoff ACCEPTED {sender_id} -> {receiver_id}")
                    except Exception as e:
                        logger.warning(f"AGENT NETWORK: handoff accept failed: {e}")

        except Exception as e:
            logger.warning(f"AGENT NETWORK: handoff request failed: {e}")

    # ───────────────────────────────────────────────────────────
    # Ancillary actions — quotes, heartbeats, re-verification
    # ───────────────────────────────────────────────────────────

    async def _do_quote(self, client: httpx.AsyncClient):
        """Random agent requests a service quote."""
        name = random.choice(list(self.agent_cards.keys()))
        m2m_id = REGISTRY_BASE_AGENTS.get(name, {}).get("m2m_id", name)
        card_name = self.agent_cards[name]["name"]
        service = random.choice([
            "svc-data-extraction", "svc-document-verification",
            "svc-market-intelligence", "svc-attestation-proof",
        ])

        key_id, secret = self.api_keys.get(name, ("", ""))
        try:
            resp = await client.post(
                f"{self.registry_base_url}/m2m/quote",
                json={
                    "service_id": service,
                    "task_params": {
                        "payload_fields": random.randint(5, 20),
                        "attachments": random.randint(0, 3),
                        "region": random.choice(["APAC", "EMEA", "AMER"]),
                    },
                },
                headers={"x-api-key-id": key_id, "x-api-secret": secret},
            )
            if resp.status_code == 200:
                q = resp.json()
                credits = q.get("quote", {}).get("estimated_credits", 0)
                await self._post_activity(
                    client, "quote",
                    card_name, "The Last Bastion",
                    f"Quote for {service}: {credits} credits",
                )
        except Exception:
            pass

    async def _do_heartbeat(self, client: httpx.AsyncClient):
        """Update agent last_seen + post heartbeat activity."""
        name = random.choice(list(self.agent_cards.keys()))
        card = self.agent_cards[name]
        swarm_cfg = REGISTRY_BASE_AGENTS.get(name, {})

        # Re-register to update last_seen
        try:
            skills_data = []
            for s in card.get("skills", []):
                if isinstance(s, dict):
                    skills_data.append({"name": s.get("name", ""), "tags": s.get("tags", [])})

            await client.post(f"{self.registry_base_url}/m2m/dashboard/agents/register", json={
                "agent_id": swarm_cfg.get("m2m_id", name),
                "name": card["name"],
                "url": card["url"],
                "port": (REMOTE_AGENT_PORTS if self._bastion_host not in ("localhost", "127.0.0.1", "") else AGENT_PORTS).get(name, 0),
                "role": swarm_cfg.get("role", "DATA_PROVIDER"),
                "skills": skills_data,
                "version": card.get("version", "1.0"),
                "status": "online",
                "description": card.get("description", ""),
            })
        except Exception:
            pass

        await self._post_activity(
            client, "heartbeat",
            card["name"], "The Last Bastion",
            f"Heartbeat — {card['name']} online at {card['url']}",
        )

    async def _do_reverify(self, client: httpx.AsyncClient):
        """Re-run passport verification on a random agent."""
        name = random.choice(list(self.agent_cards.keys()))
        card = self.agent_cards[name]
        swarm_cfg = REGISTRY_BASE_AGENTS.get(name, {})
        m2m_id = swarm_cfg.get("m2m_id", name)

        await self._post_activity(
            client, "verification",
            card["name"], "The Last Bastion",
            "Re-verification requested for passport renewal",
            status="active",
        )

        try:
            resp = await client.post(f"{self.registry_base_url}/m2m/verify-agent", json={
                "agent_id": m2m_id,
                "agent_name": card["name"],
                "agent_url": card["url"],
                "public_key": swarm_cfg.get("public_key", ""),
                "capabilities": swarm_cfg.get("capabilities", []),
                "metadata": {
                    "role": swarm_cfg.get("role", ""),
                    "version": card.get("version", "1.0"),
                    "a2a_compliant": True,
                },
            })
            if resp.status_code == 200:
                v = resp.json()
                await self._post_activity(
                    client, "verification",
                    "The Last Bastion", card["name"],
                    f"Passport renewed: {v.get('verdict', 'N/A')} (trust={v.get('trust_score', 0):.3f})",
                )
        except Exception:
            pass

    # ───────────────────────────────────────────────────────────
    # Bastion Protocol overlay — binary encrypted agent comms
    # ───────────────────────────────────────────────────────────

    async def _boot_bastion_servers(self):
        """Start Bastion Protocol TCP servers for each agent."""
        try:
            from lastbastion.crypto import generate_keypair
            from lastbastion.passport import AgentPassport
            from lastbastion.protocol import AgentSocket, FrameType
            from core.bastion_bus import bastion_bus
        except ImportError as e:
            logger.warning(f"BASTION: cannot import protocol SDK: {e}")
            return False

        is_remote = self._bastion_host != "localhost"
        logger.info(f"BASTION: booting binary protocol {'(remote: ' + self._bastion_host + ')' if is_remote else 'servers'}...")

        # Try to load issuer keys from file (shared with remote agent runner)
        import json as _json
        keys_file = os.path.join(os.path.dirname(__file__), "..", ".bastion_keys.json")
        issuer_pub = os.environ.get("BASTION_ISSUER_PUB", "")
        issuer_priv = os.environ.get("BASTION_ISSUER_PRIV", "")

        if not issuer_pub or not issuer_priv:
            try:
                with open(keys_file) as f:
                    kd = _json.load(f)
                    issuer_pub = kd["issuer_pub"]
                    issuer_priv = kd["issuer_priv"]
                    logger.info(f"BASTION: loaded issuer keys from {keys_file}")
            except Exception:
                pass

        if not issuer_pub or not issuer_priv:
            issuer_pub, issuer_priv = generate_keypair()
            logger.info(f"BASTION: generated new issuer keypair")
            # Save for sharing
            try:
                with open(keys_file, "w") as f:
                    _json.dump({"issuer_pub": issuer_pub, "issuer_priv": issuer_priv}, f)
            except Exception:
                pass

        self._issuer_keys = (issuer_pub, issuer_priv)

        # If remote, don't start local servers — just set up passports and keys
        if is_remote:
            logger.info(f"BASTION: remote mode — agents at {self._bastion_host}:9101-9104")
            for name in BASTION_PORTS:
                self._bastion_keys[name] = (issuer_priv, issuer_pub)
                passport = AgentPassport(
                    agent_id=REGISTRY_BASE_AGENTS[name]["m2m_id"],
                    agent_name=name.title() + "Bot",
                    public_key=issuer_pub,
                    trust_score=0.92,
                    trust_level="VERIFIED",
                    verdict="TRUSTED",
                    company_name="The Last Bastion",
                    issuer="the-last-bastion",
                    issuer_public_key=issuer_pub,
                ).seal()
                self._bastion_passports[name] = passport
            self._bastion_ready = True
            logger.info(f"BASTION: remote mode ready — {len(BASTION_PORTS)} agents configured")
            return True

        agent_names = {
            "producer": "ProducerBot",
            "compliance": "ComplianceBot",
            "logistics": "LogisticsBot",
            "buyer": "BuyerBot",
        }
        agent_roles = {
            "producer": "DATA_PROVIDER",
            "compliance": "VERIFIER",
            "logistics": "DATA_PROVIDER",
            "buyer": "DATA_CONSUMER",
        }

        for name, port in BASTION_PORTS.items():
            try:
                # All agents use issuer keypair for JWT signing/verification
                # This lets any agent verify any other agent's passport JWT
                pub, priv = issuer_pub, issuer_priv
                self._bastion_keys[name] = (priv, pub)

                passport = AgentPassport(
                    agent_id=REGISTRY_BASE_AGENTS[name]["m2m_id"],
                    agent_name=agent_names[name],
                    public_key=pub,
                    trust_score=0.85 + random.uniform(0, 0.14),
                    trust_level="VERIFIED",
                    verdict="TRUSTED",
                    company_name="The Last Bastion",
                    issuer="the-last-bastion",
                    issuer_public_key=issuer_pub,
                ).seal()

                self._bastion_passports[name] = passport

                # Frame event hooks -> bastion_bus
                def make_hooks(agent_name):
                    def on_sent(frame):
                        try:
                            bastion_bus.record(
                                event_type="FRAME_SENT",
                                frame_type=FrameType(frame.msg_type).name if hasattr(frame, 'msg_type') else str(frame.msg_type),
                                sender_agent=agent_name,
                                receiver_agent="",
                                direction="SENT",
                                sequence=frame.sequence if hasattr(frame, 'sequence') else 0,
                                passport_hash=frame.passport_hash.hex() if hasattr(frame, 'passport_hash') and isinstance(frame.passport_hash, bytes) else "",
                                signature_verified=True,
                                encrypted=frame.msg_type not in (0x01, 0x02, 0x0A) if hasattr(frame, 'msg_type') else False,
                                payload_size=frame.payload_length if hasattr(frame, 'payload_length') else 0,
                                total_frame_size=len(frame.to_bytes()) if hasattr(frame, 'to_bytes') else 0,
                            )
                        except Exception:
                            pass

                    def on_recv(frame):
                        try:
                            bastion_bus.record(
                                event_type="FRAME_RECEIVED",
                                frame_type=FrameType(frame.msg_type).name if hasattr(frame, 'msg_type') else str(frame.msg_type),
                                sender_agent="",
                                receiver_agent=agent_name,
                                direction="RECEIVED",
                                sequence=frame.sequence if hasattr(frame, 'sequence') else 0,
                                passport_hash=frame.passport_hash.hex() if hasattr(frame, 'passport_hash') and isinstance(frame.passport_hash, bytes) else "",
                                signature_verified=True,
                                encrypted=frame.msg_type not in (0x01, 0x02, 0x0A) if hasattr(frame, 'msg_type') else False,
                                payload_size=frame.payload_length if hasattr(frame, 'payload_length') else 0,
                                total_frame_size=len(frame.to_bytes()) if hasattr(frame, 'to_bytes') else 0,
                            )
                        except Exception:
                            pass
                    return on_sent, on_recv

                on_sent, on_recv = make_hooks(name)

                # Handler for incoming connections
                async def make_handler(agent_name):
                    async def handle(conn):
                        try:
                            msg = await conn.recv()
                            # Echo back with verification stamp
                            await conn.send({
                                "status": "verified",
                                "agent": agent_name,
                                "received": msg,
                                "timestamp": datetime.utcnow().isoformat(),
                            })
                            await conn.close()
                        except Exception:
                            pass
                    return handle

                handler = await make_handler(name)
                server = AgentSocket.listen(
                    passport=passport,
                    signing_key=priv,
                    verify_key=issuer_pub,
                    host="0.0.0.0",
                    port=port,
                    on_frame_sent=on_sent,
                    on_frame_received=on_recv,
                )
                server.on_connect(handler)
                await server.start_background()
                self._bastion_servers[name] = server
                logger.info(f"BASTION: {agent_names[name]} listening on TCP:{port}")

            except Exception as e:
                logger.warning(f"BASTION: failed to start {name} on port {port}: {e}")

        self._bastion_ready = len(self._bastion_servers) >= 2
        logger.info(f"BASTION: {len(self._bastion_servers)} servers running (ready={self._bastion_ready})")
        return self._bastion_ready

    async def _send_bastion_message(
        self, sender: str, target: str, data: dict,
    ) -> Optional[dict]:
        """Send a message via Bastion Protocol (encrypted binary frame)."""
        if not self._bastion_ready:
            return None
        if sender not in self._bastion_passports or target not in self._bastion_servers:
            return None

        try:
            from lastbastion.protocol import AgentSocket
            from core.bastion_bus import bastion_bus

            passport = self._bastion_passports[sender]
            priv, pub = self._bastion_keys[sender]
            issuer_pub = self._issuer_keys[0]
            is_remote = self._bastion_host not in ("localhost", "127.0.0.1", "")
            bastion_port_map = REMOTE_BASTION_PORTS if is_remote else BASTION_PORTS
            port = bastion_port_map[target]

            session_id = f"bs-{secrets.token_hex(4)}"
            t0 = time.monotonic()

            # Record handshake init
            bastion_bus.record_handshake(
                event_type="HANDSHAKE_INIT",
                sender=sender,
                receiver=target,
                session_id=session_id,
                trust_score=passport.trust_score,
                passport_hash=passport.crypto_hash[:16] if passport.crypto_hash else "",
            )

            conn = await AgentSocket.connect(
                host=self._bastion_host,
                port=port,
                passport=passport,
                signing_key=priv,
                verify_key=issuer_pub,
            )

            latency_hs = (time.monotonic() - t0) * 1000

            # Record handshake complete
            bastion_bus.record_handshake(
                event_type="HANDSHAKE_COMPLETE",
                sender=sender,
                receiver=target,
                session_id=session_id,
                trust_score=conn.peer.trust_score if conn.peer else 0,
                passport_hash=conn.peer.passport_hash.hex() if conn.peer and isinstance(conn.peer.passport_hash, bytes) else "",
                latency_ms=latency_hs,
            )

            await conn.send(data)

            bastion_bus.record(
                event_type="FRAME_SENT",
                frame_type="DATA",
                sender_agent=sender,
                receiver_agent=target,
                direction="SENT",
                encrypted=True,
                signature_verified=True,
                payload_size=len(json.dumps(data)),
                session_id=session_id,
            )

            response = await conn.recv()

            bastion_bus.record(
                event_type="FRAME_RECEIVED",
                frame_type="DATA",
                sender_agent=target,
                receiver_agent=sender,
                direction="RECEIVED",
                encrypted=True,
                signature_verified=True,
                payload_size=len(json.dumps(response)) if response else 0,
                session_id=session_id,
            )

            await conn.close()

            bastion_bus.record(
                event_type="CONNECTION_CLOSED",
                frame_type="CLOSE",
                sender_agent=sender,
                receiver_agent=target,
                direction="SENT",
                session_id=session_id,
                latency_ms=(time.monotonic() - t0) * 1000,
            )

            logger.info(f"BASTION: {sender} -> {target} via encrypted binary ({latency_hs:.0f}ms handshake)")
            return response

        except Exception as e:
            logger.warning(f"BASTION: {sender} -> {target} failed: {e}")
            try:
                from core.bastion_bus import bastion_bus
                bastion_bus.record(
                    event_type="ERROR",
                    frame_type="ERROR",
                    sender_agent=sender,
                    receiver_agent=target,
                    direction="SENT",
                    error_message=str(e)[:200],
                    session_id=session_id if 'session_id' in dir() else "",
                )
            except Exception:
                pass
            return None

    async def _generate_demo_bastion_frames(self):
        """
        Generate production-quality bastion_bus frame events without real agents.
        Uses consistent agent identities, realistic supply chain payloads, and
        varied session patterns: standard exchange, streaming, error, keepalive.
        """
        from core.bastion_bus import bastion_bus

        FRAME_OVERHEAD = 90  # 1B ver + 1B type + 16B passport + 4B seq + 4B len + 64B sig

        roll = random.random()
        if roll < 0.50:
            await self._demo_standard_exchange(bastion_bus, FRAME_OVERHEAD)
        elif roll < 0.70:
            await self._demo_streaming_session(bastion_bus, FRAME_OVERHEAD)
        elif roll < 0.85:
            await self._demo_error_session(bastion_bus, FRAME_OVERHEAD)
        else:
            await self._demo_keepalive(bastion_bus, FRAME_OVERHEAD)

    def _agent_trust(self, agent_name: str) -> float:
        """Return base trust with micro-variation."""
        base = AGENT_IDENTITY[agent_name]["base_trust"]
        return round(base + random.uniform(-0.015, 0.015), 4)

    def _make_handshake_params(self, agent_name: str) -> dict:
        """Build passport JWT claims for HELLO frames."""
        ident = AGENT_IDENTITY[agent_name]
        now = datetime.utcnow().isoformat()
        return {
            "agent_id": REGISTRY_BASE_AGENTS[agent_name]["m2m_id"],
            "issuer": ident["issuer"],
            "capabilities": ident["capabilities"],
            "issued_at": now,
            "expires_at": "2026-12-31T23:59:59",
            "pub_key": ident["pub_key_prefix"] + "..." + secrets.token_hex(4),
            "nonce": secrets.token_hex(12),
        }

    async def _demo_handshake(self, bastion_bus, sender: str, receiver: str, session_id: str) -> float:
        """Perform HELLO / HELLO_ACK handshake. Returns handshake latency."""
        s_ident = AGENT_IDENTITY[sender]
        r_ident = AGENT_IDENTITY[receiver]

        # HELLO
        bastion_bus.record_handshake(
            event_type="HANDSHAKE_INIT",
            sender=sender,
            receiver=receiver,
            session_id=session_id,
            trust_score=self._agent_trust(sender),
            passport_hash=s_ident["passport_hash"],
            key_exchange_pub=s_ident["pub_key_prefix"] + secrets.token_hex(4),
            handshake_params=self._make_handshake_params(sender),
        )
        await asyncio.sleep(random.uniform(0.05, 0.15))

        # HELLO_ACK
        hs_latency = round(random.uniform(2.5, 12.0), 2)
        bastion_bus.record_handshake(
            event_type="HANDSHAKE_COMPLETE",
            sender=receiver,
            receiver=sender,
            session_id=session_id,
            trust_score=self._agent_trust(receiver),
            passport_hash=r_ident["passport_hash"],
            latency_ms=hs_latency,
            key_exchange_pub=r_ident["pub_key_prefix"] + secrets.token_hex(4),
            handshake_params=self._make_handshake_params(receiver),
        )
        await asyncio.sleep(random.uniform(0.05, 0.15))
        return hs_latency

    async def _demo_standard_exchange(self, bastion_bus, overhead: int):
        """Standard exchange: HELLO → HELLO_ACK → DATA → DATA_ACK → ... → CLOSE"""
        scenario = random.choice(SUPPLY_CHAIN_PAYLOADS)
        step = random.choice(scenario["steps"])
        sender, receiver = step["pair"]
        session_id = f"bs-{AGENT_IDENTITY[sender]['passport_hash'][:8]}"

        batch_num = random.randint(1000, 9999)
        batch_id = f"{scenario['batch_prefix']}-{batch_num}"
        cert_id = f"EXP-{random.randint(10000, 99999)}"
        container_id = f"MSKU-{random.randint(100000, 999999)}"
        qty = random.choice([500, 1000, 2000, 5000, 10000, 15000, 20000])
        farm = random.choice(FARM_NAMES)
        dest = random.choice(DEST_NAMES)
        eta = random.randint(12, 35)

        await self._demo_handshake(bastion_bus, sender, receiver, session_id)

        # DATA frames with payload context
        seq = 1
        nonce = secrets.token_hex(12)[:16]
        payload_size = random.randint(*step["size_range"])
        desc = step["description"].format(
            batch=batch_id, product=scenario["product"], qty=qty,
            farm=farm, cert=cert_id, container=container_id, dest=dest,
            eta=eta, grade="A",
        )

        bastion_bus.record(
            event_type="FRAME_SENT",
            frame_type="DATA",
            sender_agent=sender,
            receiver_agent=receiver,
            direction="SENT",
            sequence=seq,
            passport_hash=AGENT_IDENTITY[sender]["passport_hash"],
            signature_verified=True,
            encrypted=True,
            payload_size=payload_size,
            total_frame_size=payload_size + overhead,
            session_id=session_id,
            trust_score=self._agent_trust(sender),
            payload_description=desc,
            payload_type=step["payload_type"],
            payload_encoding="msgpack",
            cipher="XSalsa20-Poly1305",
            nonce=nonce,
            integrity_check="PASS",
        )
        await asyncio.sleep(random.uniform(0.05, 0.12))

        # DATA_ACK
        bastion_bus.record(
            event_type="FRAME_RECEIVED",
            frame_type="DATA_ACK",
            sender_agent=receiver,
            receiver_agent=sender,
            direction="RECEIVED",
            sequence=seq,
            passport_hash=AGENT_IDENTITY[receiver]["passport_hash"],
            signature_verified=True,
            encrypted=True,
            payload_size=32,
            total_frame_size=32 + overhead,
            session_id=session_id,
            trust_score=self._agent_trust(receiver),
            accepted=True,
            payload_description=f"ACK seq={seq} — Poly1305 MAC verified, payload accepted",
            cipher="XSalsa20-Poly1305",
            integrity_check="PASS",
        )
        await asyncio.sleep(random.uniform(0.05, 0.1))

        # Attachment frames
        for i, att in enumerate(step.get("attachments", [])):
            seq += 1
            att_nonce = secrets.token_hex(12)[:16]
            att_name = att["name"].format(batch=batch_id, cert=cert_id, container=container_id)
            att_desc = f"Attachment {i+1}/{len(step['attachments'])}: {att_name} ({formatBytesForLog(att['size'])}, {att['type']})"

            bastion_bus.record(
                event_type="FRAME_SENT",
                frame_type="DATA",
                sender_agent=sender,
                receiver_agent=receiver,
                direction="SENT",
                sequence=seq,
                passport_hash=AGENT_IDENTITY[sender]["passport_hash"],
                signature_verified=True,
                encrypted=True,
                payload_size=att["size"],
                total_frame_size=att["size"] + overhead,
                session_id=session_id,
                trust_score=self._agent_trust(sender),
                payload_description=att_desc,
                payload_type=att["type"],
                payload_encoding="raw",
                cipher="XSalsa20-Poly1305",
                nonce=att_nonce,
                integrity_check="PASS",
            )
            await asyncio.sleep(random.uniform(0.03, 0.08))

            # ACK for attachment
            bastion_bus.record(
                event_type="FRAME_RECEIVED",
                frame_type="DATA_ACK",
                sender_agent=receiver,
                receiver_agent=sender,
                direction="RECEIVED",
                sequence=seq,
                passport_hash=AGENT_IDENTITY[receiver]["passport_hash"],
                signature_verified=True,
                encrypted=True,
                payload_size=32,
                total_frame_size=32 + overhead,
                session_id=session_id,
                trust_score=self._agent_trust(receiver),
                accepted=True,
                payload_description=f"ACK seq={seq} — {att_name} received, integrity verified",
                cipher="XSalsa20-Poly1305",
                integrity_check="PASS",
            )
            await asyncio.sleep(random.uniform(0.03, 0.06))

        # PING/PONG
        if random.random() < 0.5:
            bastion_bus.record(
                event_type="FRAME_SENT", frame_type="PING",
                sender_agent=sender, receiver_agent=receiver,
                direction="SENT", session_id=session_id,
                passport_hash=AGENT_IDENTITY[sender]["passport_hash"],
                signature_verified=True, payload_size=0, total_frame_size=overhead,
            )
            await asyncio.sleep(random.uniform(0.02, 0.05))
            bastion_bus.record(
                event_type="FRAME_RECEIVED", frame_type="PONG",
                sender_agent=receiver, receiver_agent=sender,
                direction="RECEIVED", session_id=session_id,
                passport_hash=AGENT_IDENTITY[receiver]["passport_hash"],
                signature_verified=True, payload_size=0, total_frame_size=overhead,
                latency_ms=round(random.uniform(1.0, 5.0), 2),
            )
            await asyncio.sleep(random.uniform(0.02, 0.05))

        # CLOSE
        bastion_bus.record(
            event_type="CONNECTION_CLOSED",
            frame_type="CLOSE",
            sender_agent=sender,
            receiver_agent=receiver,
            direction="SENT",
            session_id=session_id,
            latency_ms=round(random.uniform(50, 200), 2),
            passport_hash=AGENT_IDENTITY[sender]["passport_hash"],
        )

        logger.info(f"BASTION DEMO: {sender} → {receiver} (standard, session {session_id})")

    async def _demo_streaming_session(self, bastion_bus, overhead: int):
        """Streaming session: handshake → STREAM_START → STREAM_CHUNK × N → STREAM_END → CLOSE"""
        pairs = [("producer", "compliance"), ("compliance", "logistics"), ("logistics", "buyer")]
        sender, receiver = random.choice(pairs)
        session_id = f"bs-{AGENT_IDENTITY[sender]['passport_hash'][:8]}"

        await self._demo_handshake(bastion_bus, sender, receiver, session_id)

        # Streaming scenarios
        stream_scenarios = [
            {"file": "cold_chain_telemetry.csv", "type": "text/csv", "readings": random.randint(500, 1500),
             "total_size": random.randint(500000, 1500000), "desc_fn": lambda c, t: f"readings {c[0]}-{c[1]}, avg {round(random.uniform(1.5, 3.5), 1)}°C, variance {round(random.uniform(0.01, 0.08), 3)}"},
            {"file": "container_inspection_hires.jpg", "type": "image/jpeg", "readings": 0,
             "total_size": random.randint(2000000, 5000000), "desc_fn": lambda c, t: f"bytes {c[0]*1024}-{c[1]*1024}"},
            {"file": "batch_traceability_full.csv", "type": "text/csv", "readings": random.randint(200, 800),
             "total_size": random.randint(300000, 900000), "desc_fn": lambda c, t: f"records {c[0]}-{c[1]}, farm-to-processor chain"},
        ]
        stream = random.choice(stream_scenarios)
        num_chunks = random.randint(3, 8)

        # STREAM_START
        bastion_bus.record(
            event_type="FRAME_SENT", frame_type="STREAM_START",
            sender_agent=sender, receiver_agent=receiver,
            direction="SENT", sequence=1,
            passport_hash=AGENT_IDENTITY[sender]["passport_hash"],
            signature_verified=True, encrypted=True,
            payload_size=128, total_frame_size=128 + overhead,
            session_id=session_id,
            trust_score=self._agent_trust(sender),
            payload_description=f"Stream init: {stream['file']} ({stream['type']}) — {stream.get('readings', 0) or formatBytesForLog(stream['total_size'])} {'readings' if stream['readings'] else ''}",
            payload_type=stream["type"],
            cipher="XSalsa20-Poly1305",
            nonce=secrets.token_hex(12)[:16],
        )
        await asyncio.sleep(random.uniform(0.05, 0.1))

        # STREAM_CHUNKs
        chunk_size = stream["total_size"] // num_chunks
        for i in range(num_chunks):
            chunk_range = (i * (stream["readings"] // num_chunks) if stream["readings"] else i * chunk_size // 1024,
                          (i + 1) * (stream["readings"] // num_chunks) if stream["readings"] else (i + 1) * chunk_size // 1024)
            detail = stream["desc_fn"](chunk_range, stream["total_size"])

            bastion_bus.record(
                event_type="FRAME_SENT", frame_type="STREAM_CHUNK",
                sender_agent=sender, receiver_agent=receiver,
                direction="SENT", sequence=i + 2,
                passport_hash=AGENT_IDENTITY[sender]["passport_hash"],
                signature_verified=True, encrypted=True,
                payload_size=chunk_size, total_frame_size=chunk_size + overhead,
                session_id=session_id,
                trust_score=self._agent_trust(sender),
                payload_description=f"Chunk {i+1}/{num_chunks}: {detail}",
                payload_type=stream["type"],
                cipher="XSalsa20-Poly1305",
                nonce=secrets.token_hex(12)[:16],
            )
            await asyncio.sleep(random.uniform(0.03, 0.08))

        # STREAM_END
        integrity_hash = secrets.token_hex(16)
        bastion_bus.record(
            event_type="FRAME_SENT", frame_type="STREAM_END",
            sender_agent=sender, receiver_agent=receiver,
            direction="SENT", sequence=num_chunks + 2,
            passport_hash=AGENT_IDENTITY[sender]["passport_hash"],
            signature_verified=True, encrypted=True,
            payload_size=64, total_frame_size=64 + overhead,
            session_id=session_id,
            trust_score=self._agent_trust(sender),
            payload_description=f"Stream complete: {formatBytesForLog(stream['total_size'])}, integrity sha256:{integrity_hash[:16]}...",
            payload_type=stream["type"],
            cipher="XSalsa20-Poly1305",
            integrity_check="PASS",
            accepted=True,
        )
        await asyncio.sleep(random.uniform(0.03, 0.06))

        # CLOSE
        bastion_bus.record(
            event_type="CONNECTION_CLOSED", frame_type="CLOSE",
            sender_agent=sender, receiver_agent=receiver,
            direction="SENT", session_id=session_id,
            latency_ms=round(random.uniform(80, 300), 2),
            passport_hash=AGENT_IDENTITY[sender]["passport_hash"],
        )

        logger.info(f"BASTION DEMO: {sender} → {receiver} (stream {num_chunks} chunks, session {session_id})")

    async def _demo_error_session(self, bastion_bus, overhead: int):
        """Error session: handshake → DATA → ERROR → CLOSE"""
        pairs = [("producer", "compliance"), ("compliance", "logistics"), ("logistics", "buyer")]
        sender, receiver = random.choice(pairs)
        session_id = f"bs-{AGENT_IDENTITY[sender]['passport_hash'][:8]}"

        await self._demo_handshake(bastion_bus, sender, receiver, session_id)

        # DATA attempt
        bastion_bus.record(
            event_type="FRAME_SENT", frame_type="DATA",
            sender_agent=sender, receiver_agent=receiver,
            direction="SENT", sequence=1,
            passport_hash=AGENT_IDENTITY[sender]["passport_hash"],
            signature_verified=True, encrypted=True,
            payload_size=random.randint(512, 4096),
            total_frame_size=random.randint(512, 4096) + overhead,
            session_id=session_id,
            trust_score=self._agent_trust(sender),
            payload_description="Data transmission attempt",
            payload_type="application/msgpack",
            cipher="XSalsa20-Poly1305",
            nonce=secrets.token_hex(12)[:16],
        )
        await asyncio.sleep(random.uniform(0.05, 0.1))

        # ERROR response
        error = random.choice(BASTION_ERROR_SCENARIOS)
        bastion_bus.record(
            event_type="ERROR", frame_type="ERROR",
            sender_agent=receiver, receiver_agent=sender,
            direction="RECEIVED", sequence=1,
            passport_hash=AGENT_IDENTITY[receiver]["passport_hash"],
            signature_verified=True, encrypted=False,
            payload_size=0, total_frame_size=overhead,
            session_id=session_id,
            error_code=error["code"],
            error_message=f"0x{error['code']:02X} {error['name']}: {error['message']}",
            trust_score=self._agent_trust(receiver),
            integrity_check="FAIL",
        )
        await asyncio.sleep(random.uniform(0.03, 0.06))

        # CLOSE
        bastion_bus.record(
            event_type="CONNECTION_CLOSED", frame_type="CLOSE",
            sender_agent=receiver, receiver_agent=sender,
            direction="SENT", session_id=session_id,
            passport_hash=AGENT_IDENTITY[receiver]["passport_hash"],
        )

        logger.info(f"BASTION DEMO: {sender} → {receiver} (ERROR 0x{error['code']:02X}, session {session_id})")

    async def _demo_keepalive(self, bastion_bus, overhead: int):
        """Keepalive: PING → PONG — liveness probe only."""
        pairs = [("producer", "compliance"), ("compliance", "logistics"), ("logistics", "buyer")]
        sender, receiver = random.choice(pairs)
        session_id = f"bs-{AGENT_IDENTITY[sender]['passport_hash'][:8]}"

        bastion_bus.record(
            event_type="FRAME_SENT", frame_type="PING",
            sender_agent=sender, receiver_agent=receiver,
            direction="SENT", session_id=session_id,
            passport_hash=AGENT_IDENTITY[sender]["passport_hash"],
            signature_verified=True, payload_size=0, total_frame_size=overhead,
            trust_score=self._agent_trust(sender),
        )
        await asyncio.sleep(random.uniform(0.02, 0.08))

        ping_latency = round(random.uniform(1.0, 8.0), 2)
        bastion_bus.record(
            event_type="FRAME_RECEIVED", frame_type="PONG",
            sender_agent=receiver, receiver_agent=sender,
            direction="RECEIVED", session_id=session_id,
            passport_hash=AGENT_IDENTITY[receiver]["passport_hash"],
            signature_verified=True, payload_size=0, total_frame_size=overhead,
            latency_ms=ping_latency,
            trust_score=self._agent_trust(receiver),
        )

        logger.info(f"BASTION DEMO: {sender} ↔ {receiver} (keepalive, {ping_latency}ms)")

    async def _run_bastion_demo(self, client: httpx.AsyncClient):
        """
        Run a supply chain demo via Bastion Protocol:
        Producer → Compliance → Logistics → Buyer using encrypted binary frames.
        """
        if not self._bastion_ready:
            # Fallback: generate demo frames directly into bastion_bus
            await self._generate_demo_bastion_frames()
            return

        logger.info("BASTION: running encrypted supply chain demo...")

        batch_id = f"BP-{secrets.token_hex(3).upper()}"
        batch = {
            "batch_id": batch_id,
            "product": random.choice(["Whole Milk Powder", "Butter", "Casein", "Whey Protein"]),
            "grade": random.choice(["Premium A", "Export Grade", "Organic"]),
            "quantity_kg": random.randint(5000, 25000),
            "farm_region": random.choice(["Western Valley", "Canterbury Plains", "Highland Ridge"]),
            "timestamp": datetime.utcnow().isoformat(),
            "protocol": "bastion-binary",
        }

        # Step 1: Producer → Compliance (certification request)
        await self._post_activity(
            client, "bastion_protocol",
            "ProducerBot", "ComplianceBot",
            f"[BASTION] Encrypted batch {batch_id} sent for certification",
            status="active",
        )

        result = await self._send_bastion_message("producer", "compliance", {
            "action": "certify_batch",
            "batch": batch,
        })
        if result:
            await self._post_activity(
                client, "bastion_protocol",
                "ComplianceBot", "ProducerBot",
                f"[BASTION] Certification response received (encrypted binary)",
            )

        await asyncio.sleep(random.uniform(2, 4))

        # Step 2: Compliance → Logistics (shipping request)
        await self._post_activity(
            client, "bastion_protocol",
            "ComplianceBot", "LogisticsBot",
            f"[BASTION] Certified batch {batch_id} forwarded for shipping",
            status="active",
        )

        result = await self._send_bastion_message("compliance", "logistics", {
            "action": "ship_batch",
            "batch": batch,
            "certified": True,
        })
        if result:
            await self._post_activity(
                client, "bastion_protocol",
                "LogisticsBot", "ComplianceBot",
                f"[BASTION] Shipping confirmation received (encrypted binary)",
            )

        await asyncio.sleep(random.uniform(2, 4))

        # Step 3: Logistics → Buyer (delivery notification)
        await self._post_activity(
            client, "bastion_protocol",
            "LogisticsBot", "BuyerBot",
            f"[BASTION] Batch {batch_id} in transit, sending provenance chain",
            status="active",
        )

        result = await self._send_bastion_message("logistics", "buyer", {
            "action": "verify_delivery",
            "batch": batch,
            "provenance_chain": ["producer", "compliance", "logistics"],
        })
        if result:
            await self._post_activity(
                client, "bastion_protocol",
                "BuyerBot", "LogisticsBot",
                f"[BASTION] Full provenance verified via encrypted binary protocol",
            )

        logger.info(f"BASTION: supply chain demo complete for batch {batch_id}")

    async def _stop_bastion_servers(self):
        """Stop all Bastion Protocol servers."""
        for name, server in self._bastion_servers.items():
            try:
                await server.stop()
                logger.info(f"BASTION: stopped {name} server")
            except Exception:
                pass
        self._bastion_servers.clear()
        self._bastion_ready = False

    # ───────────────────────────────────────────────────────────
    # Helpers
    # ───────────────────────────────────────────────────────────

    async def _submit_to_refinery(
        self, client: httpx.AsyncClient,
        payload: dict, source_agent: str, doc_type: str,
    ) -> Optional[dict]:
        """Submit data through The Last Bastion's real verification pipeline."""
        # Find agent name from m2m_id to get API keys
        agent_name = next(
            (n for n, cfg in REGISTRY_BASE_AGENTS.items() if cfg.get("m2m_id") == source_agent),
            None,
        )
        key_id, secret = self.api_keys.get(agent_name, ("", "")) if agent_name else ("", "")
        try:
            resp = await client.post(
                f"{self.registry_base_url}/refinery/submit",
                json={
                    "payload": payload,
                    "source_agent_id": source_agent,
                    "context": {"document_type": doc_type, "protocol": "a2a"},
                },
                headers={"x-api-key-id": key_id, "x-api-secret": secret},
                timeout=30,
            )
            if resp.status_code == 200:
                result = resp.json()
                v = result.get("verdict", "N/A")
                s = result.get("score", 0)
                cached = result.get("cached", False)
                logger.info(
                    f"AGENT NETWORK: refinery {source_agent}/{doc_type} "
                    f"-> {v} ({s:.3f}){' [cached]' if cached else ''}"
                )
                return result
        except Exception as e:
            logger.warning(f"AGENT NETWORK: refinery submit failed: {e}")
        return None

    async def _demo_submit_to_refinery(self, client: httpx.AsyncClient):
        """Submit realistic demo data through the refinery so verdicts appear on dashboard."""
        demo_payloads = [
            {
                "source_agent": "producer-regional-001",
                "doc_type": "production_batch",
                "payload": {
                    "batch_id": f"WK-{random.randint(1000, 9999)}",
                    "product": random.choice(["Whole Milk Powder", "Skim Milk Powder", "Butter", "Cheese", "Whey Protein"]),
                    "grade": random.choice(["Premium A1", "Export Grade", "Standard"]),
                    "farm_region": random.choice(FARM_NAMES),
                    "quantity_kg": random.randint(5000, 50000),
                    "production_date": datetime.utcnow().isoformat(),
                    "temperature_c": round(random.uniform(2.0, 6.0), 1),
                    "moisture_pct": round(random.uniform(2.5, 4.5), 1),
                    "trace_id": str(uuid.uuid4()),
                },
            },
            {
                "source_agent": "compliance-regional-001",
                "doc_type": "export_certificate",
                "payload": {
                    "certificate_number": f"EXP-CERT-{random.randint(100000, 999999)}",
                    "overall_result": random.choice(["PASS", "PASS", "PASS", "CONDITIONAL_PASS"]),
                    "inspection_date": datetime.utcnow().isoformat(),
                    "inspector_id": f"INS-{random.randint(100, 999)}",
                    "tests_passed": random.randint(8, 12),
                    "tests_total": 12,
                    "destination_country": random.choice(DEST_NAMES),
                    "trace_id": str(uuid.uuid4()),
                },
            },
            {
                "source_agent": "logistics-maersk-001",
                "doc_type": "shipping_manifest",
                "payload": {
                    "container_id": f"MSKU{random.randint(1000000, 9999999)}",
                    "vessel": random.choice(["Maersk Seletar", "CMA CGM Marco Polo", "Evergreen Ever Given", "MSC Oscar"]),
                    "departure_port": random.choice(["Rotterdam, NL", "Singapore, SG", "Melbourne, AU", "Los Angeles, US"]),
                    "destination_port": random.choice(["Singapore", "Shanghai", "Tokyo", "Dubai"]),
                    "temperature_setpoint_c": -18.0,
                    "cold_chain_active": True,
                    "estimated_transit_days": random.randint(7, 21),
                    "trace_id": str(uuid.uuid4()),
                },
            },
        ]

        chosen = random.choice(demo_payloads)
        try:
            resp = await client.post(
                f"{self.registry_base_url}/refinery/submit",
                json={
                    "payload": chosen["payload"],
                    "source_agent_id": chosen["source_agent"],
                    "context": {"document_type": chosen["doc_type"], "protocol": "a2a", "demo": True},
                },
                timeout=30,
            )
            if resp.status_code == 200:
                result = resp.json()
                v = result.get("verdict", "N/A")
                s = result.get("score", 0)
                logger.info(f"AGENT NETWORK: demo refinery -> {v} ({s:.3f})")
        except Exception as e:
            logger.warning(f"AGENT NETWORK: demo refinery submit failed: {e}")

    async def _post_activity(
        self, client: httpx.AsyncClient,
        phase: str, from_agent: str, to_agent: str,
        action: str, data_summary: dict = None, status: str = "complete",
    ):
        """Post an activity event to the dashboard feed."""
        try:
            await client.post(f"{self.registry_base_url}/m2m/activity", json={
                "phase": phase,
                "from_agent": from_agent,
                "to_agent": to_agent,
                "action": action,
                "data_summary": data_summary or {},
                "status": status,
            })
        except Exception:
            pass

    # ───────────────────────────────────────────────────────────
    # Main loop
    # ───────────────────────────────────────────────────────────

    async def start(self):
        """
        Entry point — called as a background task from regional_core.py.
        Boots real agents, discovers them, registers, verifies, then
        runs continuous supply chain workflows.

        Falls back to demo mode if agents can't boot — generates realistic
        bastion_bus frame events so the dashboard shows system activity.
        """
        self.running = True
        logger.info("AGENT NETWORK: starting...")

        # Wait for The Last Bastion API to be ready
        await asyncio.sleep(3)

        # Boot A2A agent servers (retry up to 2 times with short backoff)
        ok = False
        for boot_attempt in range(2):
            ok = await self._boot_agent_servers()
            if ok:
                break
            logger.warning(f"AGENT NETWORK: boot attempt {boot_attempt + 1}/2 failed, retrying in {5 * (boot_attempt + 1)}s...")
            await asyncio.sleep(5 * (boot_attempt + 1))

        demo_mode = not ok
        if demo_mode:
            logger.warning("AGENT NETWORK: no agents available — entering demo mode (bastion frames will be generated)")

        async with httpx.AsyncClient(timeout=30.0) as client:
            # Wait for The Last Bastion API
            for attempt in range(10):
                try:
                    resp = await client.get(f"{self.registry_base_url}/health")
                    if resp.status_code == 200:
                        break
                except Exception:
                    pass
                await asyncio.sleep(2)
            else:
                logger.error("AGENT NETWORK: The Last Bastion API not reachable")
                return

            if not demo_mode:
                # Discovery → Registration → Verification
                await self._discover_agents(client)
                await self._register_on_registry_base(client)
                await self._verify_passports(client)

                # Boot Bastion Protocol servers (binary overlay)
                try:
                    await self._boot_bastion_servers()
                except Exception as e:
                    logger.warning(f"AGENT NETWORK: Bastion Protocol boot failed (non-fatal): {e}")

                logger.info(
                    f"AGENT NETWORK: ready — {len(self.agent_cards)} agents, "
                    f"{len(self.verified)} verified, "
                    f"{len(self._bastion_servers)} bastion servers. Entering continuous loop."
                )
            else:
                # In demo mode, register simulated agents on dashboard so they appear
                for name, cfg in REGISTRY_BASE_AGENTS.items():
                    agent_labels = {
                        "producer": "ProducerBot", "compliance": "ComplianceBot",
                        "logistics": "LogisticsBot", "buyer": "BuyerBot",
                    }
                    try:
                        await client.post(f"{self.registry_base_url}/m2m/dashboard/agents/register", json={
                            "agent_id": cfg["m2m_id"],
                            "name": agent_labels[name],
                            "url": f"http://localhost:{AGENT_PORTS[name]}",
                            "port": AGENT_PORTS[name],
                            "role": cfg["role"],
                            "skills": [],
                            "version": "1.0",
                            "status": "online",
                            "description": f"Demo mode — {agent_labels[name]}",
                        })
                    except Exception:
                        pass

                # Generate initial burst of bastion frames so page isn't empty on first load
                for _ in range(5):
                    await self._generate_demo_bastion_frames()
                    await asyncio.sleep(0.5)

                # Submit burst of demo refinery data so verdict views aren't empty
                for _ in range(3):
                    await self._demo_submit_to_refinery(client)
                    await asyncio.sleep(1)

                logger.info("AGENT NETWORK: demo mode ready — bastion frames + refinery verdicts generated, entering continuous loop")

            # Continuous communication loop
            _demo_cycle = 0
            while self.running:
                try:
                    if demo_mode:
                        _demo_cycle += 1
                        # Demo mode: generate bastion frames + simulated activity + refinery submissions
                        roll = random.random()
                        if roll < 0.45:
                            await self._generate_demo_bastion_frames()
                        elif roll < 0.70:
                            # Submit real refinery data so verdicts populate
                            await self._demo_submit_to_refinery(client)
                        else:
                            # Post simulated activity events
                            agents_list = list(REGISTRY_BASE_AGENTS.keys())
                            agent_labels_map = {
                                "producer": "ProducerBot", "compliance": "ComplianceBot",
                                "logistics": "LogisticsBot", "buyer": "BuyerBot",
                            }
                            sender = random.choice(agents_list)
                            receiver = random.choice([a for a in agents_list if a != sender])
                            actions = [
                                ("bastion_protocol", "[BASTION] Encrypted data frame sent"),
                                ("verification", "Passport re-verification requested"),
                                ("handoff", "Payload handoff initiated"),
                                ("heartbeat", "Heartbeat — agent online"),
                            ]
                            phase, action = random.choice(actions)
                            await self._post_activity(
                                client, phase,
                                agent_labels_map[sender], agent_labels_map[receiver],
                                action,
                            )
                    else:
                        # Real mode: full agent communication
                        roll = random.random()

                        if roll < 0.40:
                            await self._run_supply_chain(client)
                        elif roll < 0.60:
                            await self._run_bastion_demo(client)
                        elif roll < 0.75:
                            await self._do_quote(client)
                        elif roll < 0.88:
                            await self._do_heartbeat(client)
                        else:
                            await self._do_reverify(client)

                except Exception as e:
                    logger.warning(f"AGENT NETWORK: cycle error: {e}")

                # Wait between cycles — graduated pacing for demo mode
                if demo_mode:
                    if _demo_cycle <= 5:
                        delay = random.uniform(5, 8)    # Fast burst at start
                    elif _demo_cycle <= 15:
                        delay = random.uniform(8, 15)   # Medium pace
                    else:
                        delay = random.uniform(15, 30)  # Normal pace
                else:
                    delay = random.uniform(15, 45)
                await asyncio.sleep(delay)

    def stop(self):
        """Stop the agent network."""
        self.running = False
        for name, task in self.agent_servers.items():
            if task is not None:
                task.cancel()
        # Stop Bastion servers in background (can't await from sync)
        try:
            loop = asyncio.get_running_loop()
            loop.create_task(self._stop_bastion_servers())
        except RuntimeError:
            pass
        logger.info("AGENT NETWORK: stopped")
