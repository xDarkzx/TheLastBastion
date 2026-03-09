"""
A2A Protocol Demo — NZ Food Export Supply Chain.

Demonstrates real, standards-compliant A2A communication through
a complete NZ food export supply chain:

1. Discovers 4 supply chain agents via Agent Cards
2. ProducerBot generates a dairy export batch
3. ComplianceBot validates MPI compliance and issues export cert
4. LogisticsBot assigns container and books vessel with cold chain
5. BuyerBot cross-verifies the full provenance chain
6. All data submitted to The Last Bastion's verification pipeline

Prerequisites:
    Start the agent network first:
        python agents/a2a/agent_runner.py

    Then in another terminal:
        python agents/a2a/run_demo.py

    Optionally start The Last Bastion API for verification:
        uvicorn regional_core:app --reload --port 8000
"""
import asyncio
import json
import logging
import os
import sys
import uuid
import warnings

import httpx

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))

warnings.filterwarnings("ignore", message="A2AClient is deprecated")

from a2a.client import A2AClient
from a2a.types import (
    DataPart,
    Message,
    MessageSendParams,
    Part,
    Role,
    SendMessageRequest,
    TextPart,
)

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(message)s")
logger = logging.getLogger("A2A.Demo")

# Agent endpoints
AGENTS = {
    "producer":   "http://localhost:9001",
    "compliance": "http://localhost:9002",
    "logistics":  "http://localhost:9003",
    "buyer":      "http://localhost:9004",
}

REGISTRY_BASE_API = os.getenv("REGISTRY_BASE_API", "http://localhost:8000")


def banner(text):
    print()
    print("=" * 65)
    print("  " + text)
    print("=" * 65)


def phase(num, text):
    sep = "-" * 65
    print("\n" + sep)
    print("  PHASE %d: %s" % (num, text))
    print(sep)


def ok(text):
    print("  [OK] " + text)


def info(text):
    print("    " + text)


async def discover_agent(client, name, url):
    """Fetches an agent's A2A Agent Card."""
    a2a = A2AClient(httpx_client=client, url=url)
    card = await a2a.get_card()
    return {
        "name": card.name,
        "url": card.url,
        "version": card.version,
        "description": getattr(card, "description", ""),
        "skills": [
            {"id": s.id, "name": s.name, "tags": s.tags}
            for s in card.skills
        ],
        "capabilities": {
            "streaming": card.capabilities.streaming if card.capabilities else False,
        },
    }


async def send_task(client, url, text="", data=None, context_id=None):
    """Sends a message/send JSON-RPC request to an A2A agent."""
    a2a = A2AClient(httpx_client=client, url=url)

    parts = []
    if text:
        parts.append(Part(root=TextPart(text=text)))
    if data:
        parts.append(Part(root=DataPart(data=data)))

    msg = Message(
        messageId=str(uuid.uuid4()),
        role=Role.user,
        parts=parts,
        contextId=context_id,
    )

    request = SendMessageRequest(
        id=str(uuid.uuid4()),
        params=MessageSendParams(message=msg),
    )

    response = await a2a.send_message(request)

    # Parse response
    result = response.root
    if hasattr(result, "result"):
        r = result.result
        if hasattr(r, "model_dump"):
            return r.model_dump()
        return {"raw": str(r)}
    if hasattr(result, "error"):
        return {"error": str(result.error)}
    return {"raw": str(result)}


def extract_artifacts(response):
    """Extracts artifact data from an A2A task response."""
    artifacts = response.get("artifacts", [])
    extracted = []
    for art in artifacts:
        for part in art.get("parts", []):
            root = part.get("root", part)
            if root.get("kind") == "data":
                extracted.append(root.get("data", {}))
            elif root.get("data"):
                extracted.append(root["data"])
    return extracted


def extract_status_text(response):
    """Extracts the final status message text."""
    status = response.get("status", {})
    msg = status.get("message", {})
    parts = msg.get("parts", [])
    for part in parts:
        root = part.get("root", part)
        if root.get("kind") == "text":
            return root.get("text", "")
        if root.get("text"):
            return root["text"]
    return ""


# ---------------------------------------------------------------------------
# The Last Bastion dashboard helpers
# ---------------------------------------------------------------------------

async def register_agent_on_dashboard(client, agent_id, card, port):
    """Registers an agent on The Last Bastion dashboard."""
    try:
        await client.post(REGISTRY_BASE_API + "/m2m/dashboard/agents/register", json={
            "agent_id": agent_id,
            "name": card["name"],
            "url": card.get("url", f"http://localhost:{port}"),
            "port": port,
            "role": "supply_chain",
            "skills": card.get("skills", []),
            "version": card.get("version", "1.0"),
            "status": "online",
            "description": card.get("description", ""),
        })
    except Exception:
        pass  # The Last Bastion may not be running


async def post_activity(client, phase_name, from_agent, to_agent, action, data_summary=None, status="complete"):
    """Posts an activity event to The Last Bastion dashboard."""
    try:
        await client.post(REGISTRY_BASE_API + "/m2m/activity", json={
            "phase": phase_name,
            "from_agent": from_agent,
            "to_agent": to_agent,
            "action": action,
            "data_summary": data_summary or {},
            "status": status,
        })
    except Exception:
        pass


async def submit_step_to_refinery(client, step_name, data, source_agent):
    """Submits a single supply chain step to The Last Bastion's refinery."""
    try:
        resp = await client.post(REGISTRY_BASE_API + "/refinery/submit", json={
            "payload": data,
            "source_agent_id": source_agent,
            "context": {"protocol": "a2a", "step": step_name},
        })
        resp.raise_for_status()
        result = resp.json()
        ok("Refinery: %s -> %s (score=%.4f)" % (
            step_name, result.get("verdict", "N/A"), result.get("score", 0)))
        return result
    except Exception as e:
        info("(Refinery not available for %s: %s)" % (step_name, e))
        return None


async def run_demo():
    banner("NZ FOOD EXPORT SUPPLY CHAIN — A2A DEMO")
    print("  Agent-to-Agent Protocol (Google A2A / JSON-RPC 2.0)")
    print("  Scenario: Dairy export from Waikato to Shanghai")
    print()

    async with httpx.AsyncClient(timeout=30.0) as client:

        # === PHASE 1: AGENT DISCOVERY ===
        phase(1, "AGENT DISCOVERY VIA AGENT CARDS")
        print("  Fetching /.well-known/agent-card.json from each agent...")
        print()

        await post_activity(client, "discovery", "The Last Bastion", "", "Starting agent discovery", status="active")

        cards = {}
        ports = {"producer": 9001, "compliance": 9002, "logistics": 9003, "buyer": 9004}
        for name, url in AGENTS.items():
            try:
                card = await discover_agent(client, name, url)
                cards[name] = card
                ok("%s (v%s)" % (card["name"], card["version"]))
                for skill in card["skills"]:
                    tags = ", ".join(skill["tags"][:4])
                    info("Skill: %s [%s]" % (skill["name"], tags))

                # Register on The Last Bastion dashboard
                await register_agent_on_dashboard(client, name, card, ports[name])

            except Exception as e:
                print("  [FAIL] %s at %s -- %s" % (name, url, e))
                print("    Start agents first: python agents/a2a/agent_runner.py")
                return

        await post_activity(client, "discovery", "The Last Bastion", "",
                            "All 4 agents discovered and registered",
                            {"agents": list(cards.keys())}, "complete")

        # === PHASE 2: PRODUCTION DATA ===
        phase(2, "PRODUCTION DATA (ProducerBot)")
        print("  ProducerBot generates an export batch...")
        print()

        await post_activity(client, "production", "ProducerBot", "The Last Bastion",
                            "Generating dairy export batch", status="active")

        producer_resp = await send_task(
            client, AGENTS["producer"],
            text="Generate a dairy export batch for Waikato region",
        )
        status_text = extract_status_text(producer_resp)
        ok("Task completed: %s" % status_text)

        production_data = extract_artifacts(producer_resp)
        batch = production_data[0] if production_data else {}
        if batch:
            info("Batch: %s" % batch.get("batch_id", "N/A"))
            info("Product: %s" % batch.get("product", "N/A"))
            info("Grade: %s" % batch.get("grade", "N/A"))
            info("Region: %s" % batch.get("farm_region", "N/A"))
            info("Organic: %s" % batch.get("organic_certification", "N/A"))
            qty_key = [k for k in batch if k.startswith("quantity_")]
            if qty_key:
                info("Quantity: %s %s" % (batch[qty_key[0]], qty_key[0].replace("quantity_", "")))

        await post_activity(client, "production", "ProducerBot", "ComplianceBot",
                            "Batch generated, sending to compliance",
                            {"batch_id": batch.get("batch_id", "N/A"),
                             "product": batch.get("product", "N/A")})

        # Submit production step to refinery
        await submit_step_to_refinery(client, "production", batch, "ProducerBot")

        # === PHASE 3: MPI COMPLIANCE CHECK ===
        phase(3, "MPI COMPLIANCE CHECK (ComplianceBot)")
        print("  ProducerBot -> ComplianceBot: 'Certify this batch for export'")
        print()

        compliance = {}
        if batch:
            await post_activity(client, "compliance", "ComplianceBot", "",
                                "Running MPI compliance checks",
                                {"batch_id": batch.get("batch_id", "N/A")}, "active")

            compliance_resp = await send_task(
                client, AGENTS["compliance"],
                text="Certify this batch for export",
                data=batch,
            )
            status_text = extract_status_text(compliance_resp)
            ok("Task completed: %s" % status_text)

            compliance_data = extract_artifacts(compliance_resp)
            compliance = compliance_data[0] if compliance_data else {}
            if compliance:
                checks = compliance.get("checks", {})
                for check_name, check_result in checks.items():
                    info("%s: %s" % (check_name.replace("_", " ").title(), check_result.get("status", "N/A")))
                info("Result: %s" % compliance.get("overall_result", "N/A"))
                cert = compliance.get("certificate_number")
                if cert:
                    info("Certificate: %s" % cert)
                markets = compliance.get("valid_for_export_to", [])
                if markets:
                    info("Export markets: %s" % ", ".join(markets))

            await post_activity(client, "compliance", "ComplianceBot", "LogisticsBot",
                                "MPI compliance verified, cert issued",
                                {"certificate": compliance.get("certificate_number", "N/A"),
                                 "result": compliance.get("overall_result", "N/A")})

            # Submit compliance step to refinery
            await submit_step_to_refinery(client, "compliance", compliance, "ComplianceBot")

        # === PHASE 4: LOGISTICS & COLD CHAIN ===
        phase(4, "LOGISTICS & COLD CHAIN (LogisticsBot)")
        print("  ComplianceBot -> LogisticsBot: 'Ship this certified batch'")
        print()

        # Merge production + compliance data for logistics
        logistics_input = {}
        if batch:
            logistics_input.update(batch)
        if compliance:
            logistics_input["certificate_number"] = compliance.get("certificate_number")
            logistics_input["checks"] = compliance.get("checks", {})

        shipment = {}
        if logistics_input:
            await post_activity(client, "logistics", "LogisticsBot", "",
                                "Assigning container and booking vessel",
                                {"batch_id": batch.get("batch_id", "N/A")}, "active")

            logistics_resp = await send_task(
                client, AGENTS["logistics"],
                text="Ship this certified batch",
                data=logistics_input,
            )
            status_text = extract_status_text(logistics_resp)
            ok("Task completed: %s" % status_text)

            logistics_data = extract_artifacts(logistics_resp)
            shipment = logistics_data[0] if logistics_data else {}
            if shipment:
                info("Container: %s (%s)" % (shipment.get("container_id", "N/A"), shipment.get("container_type", "N/A")))
                info("Vessel: %s (voyage %s)" % (shipment.get("vessel", "N/A"), shipment.get("voyage_id", "N/A")))
                route = shipment.get("route", {})
                info("Route: %s -> %s (%s days)" % (route.get("origin", "N/A"), route.get("destination", "N/A"), route.get("transit_days", "N/A")))
                info("ETA: %s" % shipment.get("eta", "N/A"))
                cold = shipment.get("cold_chain", {})
                info("Cold chain: %s, %d readings, %s" % (
                    cold.get("monitoring", "N/A"),
                    len(cold.get("readings", [])),
                    "INTACT" if cold.get("chain_intact") else "EXCURSION DETECTED"))
                info("Bill of Lading: %s" % shipment.get("bill_of_lading", "N/A"))

            await post_activity(client, "logistics", "LogisticsBot", "BuyerBot",
                                "Container booked, cold chain active",
                                {"container_id": shipment.get("container_id", "N/A"),
                                 "vessel": shipment.get("vessel", "N/A"),
                                 "destination": shipment.get("route", {}).get("destination", "N/A")})

            # Submit logistics step to refinery
            await submit_step_to_refinery(client, "logistics", shipment, "LogisticsBot")

        # === PHASE 5: BUYER VERIFICATION ===
        phase(5, "BUYER VERIFICATION (BuyerBot)")
        print("  LogisticsBot -> BuyerBot: 'Shipment arriving with full provenance'")
        print()

        # Merge all chain data for buyer
        buyer_input = {}
        if batch:
            buyer_input.update(batch)
        if compliance:
            buyer_input["certificate_number"] = compliance.get("certificate_number")
        if shipment:
            buyer_input["container_id"] = shipment.get("container_id")
            buyer_input["cold_chain"] = shipment.get("cold_chain", {})
            buyer_input["route"] = shipment.get("route", {})
            buyer_input["vessel"] = shipment.get("vessel")
            buyer_input["bill_of_lading"] = shipment.get("bill_of_lading")

        verification = {}
        if buyer_input:
            await post_activity(client, "buyer_verification", "BuyerBot", "",
                                "Cross-verifying full provenance chain",
                                {"batch_id": batch.get("batch_id", "N/A")}, "active")

            buyer_resp = await send_task(
                client, AGENTS["buyer"],
                text="Verify this shipment — full provenance chain attached",
                data=buyer_input,
            )
            status_text = extract_status_text(buyer_resp)
            ok("Task completed: %s" % status_text)

            buyer_data = extract_artifacts(buyer_resp)
            verification = buyer_data[0] if buyer_data else {}
            if verification:
                cross = verification.get("cross_verification", {})
                info("Production-cert match: %s" % cross.get("production_cert_match", "N/A"))
                info("Cert-manifest match: %s" % cross.get("cert_manifest_match", "N/A"))
                info("Cold chain unbroken: %s" % cross.get("cold_chain_unbroken", "N/A"))
                info("Documents authentic: %s" % cross.get("documents_authentic", "N/A"))
                info("Verdict: %s" % verification.get("overall_verdict", "N/A"))
                buyer_info = verification.get("buyer", {})
                info("Buyer: %s (%s)" % (buyer_info.get("name", "N/A"), buyer_info.get("country", "N/A")))
                pt = verification.get("payment_terms")
                if pt:
                    info("Payment: $%s %s (%s)" % (
                        "{:,.0f}".format(pt.get("total_value_usd", 0)),
                        pt.get("currency", "USD"),
                        pt.get("payment_terms", "N/A")))

            await post_activity(client, "buyer_verification", "BuyerBot", "The Last Bastion",
                                "Provenance verified, shipment accepted",
                                {"verdict": verification.get("overall_verdict", "N/A"),
                                 "buyer": verification.get("buyer", {}).get("name", "N/A")})

            # Submit buyer verification step to refinery
            await submit_step_to_refinery(client, "buyer_verification", verification, "BuyerBot")

        # === PHASE 6: THE REGISTRY BASE VERIFICATION ===
        phase(6, "THE REGISTRY BASE VERIFICATION PIPELINE")
        print("  Submitting full supply chain data to The Last Bastion for trust verification...")
        print()

        try:
            # Submit the combined provenance chain
            chain_data = {
                "supply_chain": "nz_food_export",
                "batch_id": batch.get("batch_id", "UNKNOWN"),
                "production": batch,
                "compliance": compliance,
                "logistics": shipment,
                "buyer_verification": verification,
            }

            resp = await client.post(REGISTRY_BASE_API + "/refinery/submit", json={
                "payload": chain_data,
                "source_agent_id": "supply-chain-demo",
                "context": {"protocol": "a2a", "chain_type": "nz_food_export"},
            })
            resp.raise_for_status()
            verdict = resp.json()
            ok("Supply chain verified: %s (score=%.4f)" % (
                verdict.get("verdict", "N/A"), verdict.get("score", 0)))
            proof = verdict.get("proof_hash", "N/A")
            info("Proof hash: %s..." % proof[:24])

            await post_activity(client, "registry_base_verification", "The Last Bastion", "",
                                "Full chain verified through 5-layer pipeline",
                                {"verdict": verdict.get("verdict", "N/A"),
                                 "score": verdict.get("score", 0),
                                 "proof_hash": proof[:24]})

            # Get refinery stats
            resp = await client.get(REGISTRY_BASE_API + "/refinery/stats")
            resp.raise_for_status()
            stats = resp.json()
            info("Total verifications: %s" % stats.get("total_submissions", 0))
            info("Verdicts: %s" % stats.get("verdicts", {}))

        except Exception as e:
            print("  (The Last Bastion API not running: %s)" % e)
            print("  Start it with: uvicorn regional_core:app --reload --port 8000")

        # === SUMMARY ===
        banner("DEMO COMPLETE")
        print()
        print("  What just happened:")
        print("  1. 4 supply chain agents discovered each other via A2A Agent Cards")
        print("  2. ProducerBot generated a NZ dairy export batch with provenance")
        print("  3. ComplianceBot validated MPI compliance and issued export cert")
        print("  4. LogisticsBot assigned reefer container, booked vessel, tracked cold chain")
        print("  5. BuyerBot cross-verified the full provenance chain and accepted shipment")
        print("  6. All data submitted to The Last Bastion's 5-layer verification pipeline")
        print("  7. Each step registered on the dashboard with activity feed events")
        print()
        print("  Protocol: Google A2A (Agent-to-Agent)")
        print("  Transport: JSON-RPC 2.0 over HTTP")
        print("  Data format: A2A DataPart (structured JSON)")
        print()
        print("  Dashboard: http://localhost:5173")
        print("  Supply Chain Agents:")
        for name, url in AGENTS.items():
            print("    %s/.well-known/agent-card.json  (%s)" % (url, name))
        print()


if __name__ == "__main__":
    asyncio.run(run_demo())
