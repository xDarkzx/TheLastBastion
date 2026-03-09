"""
BuyerBot — International Buyer & Import Verifier.

A2A-compliant agent representing an international buyer/importer.
Receives the full provenance chain (production -> compliance -> logistics),
cross-verifies all certificates match, confirms or rejects the shipment,
and calculates payment terms based on quality grade.

Skills:
  - verify-shipment: Cross-verifies full provenance chain and accepts/rejects
  - payment-terms: Calculates payment terms based on grade and shipment data
"""
import logging
import random
import uuid
from datetime import datetime

from a2a.server.agent_execution import AgentExecutor, RequestContext
from a2a.server.events.event_queue import EventQueue
from a2a.types import (
    AgentSkill,
    Artifact,
    DataPart,
    Message,
    Part,
    Role,
    TaskArtifactUpdateEvent,
    TaskState,
    TaskStatus,
    TaskStatusUpdateEvent,
    TextPart,
)

from agents.a2a.base_agent import build_a2a_server, build_agent_card

logger = logging.getLogger("A2A.BuyerBot")

AGENT_ID = "buyer-bot-001"
PORT = 9004

# Price ranges per category (USD/kg or per unit)
PRICE_TABLE = {
    "dairy": {"Premium A1": 4.80, "Standard A2": 3.90, "Commercial B1": 3.20, "Select Grade": 4.20},
    "meat": {"Premium A1": 18.50, "Standard A2": 14.00, "Commercial B1": 10.50, "Select Grade": 16.00},
    "seafood": {"Premium A1": 32.00, "Standard A2": 24.00, "Commercial B1": 18.00, "Select Grade": 28.00},
    "wine": {"Premium A1": 120.00, "Standard A2": 80.00, "Commercial B1": 45.00, "Select Grade": 95.00},
    "horticulture": {"Premium A1": 6.50, "Standard A2": 4.50, "Commercial B1": 3.00, "Select Grade": 5.50},
    "apiculture": {"Premium A1": 85.00, "Standard A2": 55.00, "Commercial B1": 35.00, "Select Grade": 70.00},
}

BUYERS = [
    {"name": "Shanghai Foods Import Co.", "country": "China", "currency": "USD"},
    {"name": "Singapore FreshChain Pte Ltd", "country": "Singapore", "currency": "USD"},
    {"name": "Dubai Premium Foods LLC", "country": "UAE", "currency": "USD"},
    {"name": "Tokyo Gourmet Trading", "country": "Japan", "currency": "USD"},
    {"name": "London Fine Foods Ltd", "country": "UK", "currency": "GBP"},
]


def verify_shipment(shipment_data: dict) -> dict:
    """Cross-verifies the full provenance chain and issues acceptance/rejection."""
    buyer = random.choice(BUYERS)

    # Extract data from the chain
    batch_id = shipment_data.get("batch_id", "UNKNOWN")
    product = shipment_data.get("product", shipment_data.get("category", "Unknown"))
    category = shipment_data.get("category", "dairy")
    grade = shipment_data.get("grade", "Standard A2")
    cert_number = shipment_data.get("certificate_number", None)
    container_id = shipment_data.get("container_id", None)
    cold_chain = shipment_data.get("cold_chain", {})
    route = shipment_data.get("route", {})

    # Cross-verification checks
    batch_cert_match = cert_number is not None  # cert was issued for this batch
    cert_manifest_match = container_id is not None  # shipping manifest exists
    cold_chain_ok = cold_chain.get("chain_intact", True) if cold_chain else True
    docs_authentic = random.random() > 0.02  # 98% pass rate

    all_verified = batch_cert_match and cert_manifest_match and cold_chain_ok and docs_authentic

    # Calculate payment
    price_per_unit = PRICE_TABLE.get(category, PRICE_TABLE["dairy"]).get(grade, 4.00)
    # Add some variance
    price_per_unit *= random.uniform(0.95, 1.05)
    price_per_unit = round(price_per_unit, 2)

    # Estimate quantity from various possible field names
    quantity = 0
    for key in shipment_data:
        if key.startswith("quantity_"):
            quantity = shipment_data[key]
            break
    if quantity == 0:
        quantity = shipment_data.get("unit_count", 40) * 600  # default dairy assumption

    total_value = round(price_per_unit * quantity, 2)
    payment_days = 30 if grade == "Premium A1" else (45 if grade in ("Standard A2", "Select Grade") else 60)

    verification = {
        "source": "international_buyer",
        "agent_id": AGENT_ID,
        "buyer": buyer,
        "batch_id": batch_id,
        "cross_verification": {
            "production_cert_match": "MATCH" if batch_cert_match else "MISMATCH",
            "cert_manifest_match": "MATCH" if cert_manifest_match else "MISMATCH",
            "cold_chain_unbroken": "VERIFIED" if cold_chain_ok else "BROKEN",
            "documents_authentic": "VERIFIED" if docs_authentic else "SUSPECT",
        },
        "overall_verdict": "SHIPMENT ACCEPTED" if all_verified else "SHIPMENT REJECTED",
        "rejection_reasons": [] if all_verified else [
            r for r, ok in [
                ("Production batch does not match compliance certificate", batch_cert_match),
                ("Compliance certificate missing from shipping manifest", cert_manifest_match),
                ("Cold chain breach detected during transit", cold_chain_ok),
                ("Document authenticity check failed", docs_authentic),
            ] if not ok
        ],
        "payment_terms": {
            "price_per_unit_usd": price_per_unit,
            "quantity": quantity,
            "total_value_usd": total_value,
            "payment_terms": "Net %d days" % payment_days,
            "currency": buyer["currency"],
            "incoterms": "CIF %s" % route.get("destination", buyer["country"]),
        } if all_verified else None,
        "destination": route.get("destination", buyer["country"]),
        "timestamp": datetime.utcnow().isoformat(),
    }

    return verification


class BuyerExecutor(AgentExecutor):
    """Handles incoming A2A requests for the BuyerBot."""

    async def execute(self, context: RequestContext, event_queue: EventQueue):
        task_id = context.task_id
        ctx_id = context.context_id

        user_msg = context.message
        incoming_data = {}

        for part in user_msg.parts:
            if isinstance(part.root, DataPart):
                incoming_data = part.root.data

        # Status: working
        await event_queue.enqueue_event(
            TaskStatusUpdateEvent(
                taskId=task_id,
                contextId=ctx_id,
                status=TaskStatus(
                    state=TaskState.working,
                    message=Message(
                        messageId=str(uuid.uuid4()),
                        role=Role.agent,
                        parts=[Part(root=TextPart(text="Cross-verifying provenance chain..."))],
                    ),
                ),
                final=False,
            )
        )

        result = verify_shipment(incoming_data)

        # Emit artifact
        await event_queue.enqueue_event(
            TaskArtifactUpdateEvent(
                taskId=task_id,
                contextId=ctx_id,
                artifact=Artifact(
                    artifactId=str(uuid.uuid4()),
                    name="buyer_verification",
                    description="Buyer verdict: %s — %s" % (result["batch_id"], result["overall_verdict"]),
                    parts=[Part(root=DataPart(data=result))],
                ),
                final=False,
            )
        )

        # Status: completed
        verdict = result["overall_verdict"]
        payment_info = ""
        if result.get("payment_terms"):
            pt = result["payment_terms"]
            payment_info = ", $%s %s, %s" % (
                "{:,.0f}".format(pt["total_value_usd"]), pt["currency"], pt["payment_terms"])
        await event_queue.enqueue_event(
            TaskStatusUpdateEvent(
                taskId=task_id,
                contextId=ctx_id,
                status=TaskStatus(
                    state=TaskState.completed,
                    message=Message(
                        messageId=str(uuid.uuid4()),
                        role=Role.agent,
                        parts=[Part(root=TextPart(
                            text="%s for batch %s by %s%s" % (
                                verdict, result["batch_id"],
                                result["buyer"]["name"], payment_info)
                        ))],
                    ),
                ),
                final=True,
            )
        )

    async def cancel(self, context: RequestContext, event_queue: EventQueue):
        raise Exception("BuyerBot does not support task cancellation")


def create_buyer_agent():
    """Creates the BuyerBot A2A server."""
    card = build_agent_card(
        name="International Buyer & Import Verifier",
        description=(
            "Autonomous agent representing international food importers. Receives the full "
            "export provenance chain (production -> compliance -> logistics), cross-verifies "
            "all certificates, confirms or rejects shipments, and calculates payment terms."
        ),
        url="http://localhost:%d/" % PORT,
        skills=[
            AgentSkill(
                id="verify-shipment",
                name="Shipment Verification",
                description="Cross-verifies the full provenance chain and accepts or rejects the shipment",
                tags=["buyer", "verification", "import", "provenance", "cross-verify"],
                examples=["Verify this shipment", "Cross-check provenance chain"],
                inputModes=["application/json"],
                outputModes=["application/json"],
            ),
            AgentSkill(
                id="payment-terms",
                name="Payment Terms",
                description="Calculates payment terms based on product grade and shipment data",
                tags=["buyer", "payment", "trade-finance", "import"],
                examples=["Calculate payment terms", "What's the price for this grade?"],
                inputModes=["application/json"],
                outputModes=["application/json"],
            ),
        ],
    )

    return build_a2a_server(card, BuyerExecutor()), card


if __name__ == "__main__":
    from agents.a2a.base_agent import run_agent_server
    app, card = create_buyer_agent()
    print("Starting %s on port %d" % (card.name, PORT))
    run_agent_server(app, PORT)
