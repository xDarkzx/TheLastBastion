"""
ProducerBot — Supply Chain Producer Agent.

A2A-compliant agent representing a food/agriculture producer.
Generates batch production data with full provenance: product type,
batch ID, quantity, grade, harvest/process date, farm location,
organic certification.

Skills:
  - production-batch: Generates export-ready production batch data
  - batch-lookup: Retrieves details for an existing batch ID
"""
import logging
import random
import uuid
from datetime import datetime, timedelta

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

logger = logging.getLogger("A2A.ProducerBot")

AGENT_ID = "producer-bot-001"
PORT = 9001

# International export product catalogue
PRODUCTS = [
    {"name": "Whole Milk Powder (WMP)", "category": "dairy", "unit": "kg", "bag_size": 600, "temp_range": "ambient"},
    {"name": "Skim Milk Powder (SMP)", "category": "dairy", "unit": "kg", "bag_size": 600, "temp_range": "ambient"},
    {"name": "Grass-Fed Beef Primals", "category": "meat", "unit": "kg", "bag_size": 25, "temp_range": "2-6C"},
    {"name": "Lamb Rack French-Cut", "category": "meat", "unit": "kg", "bag_size": 15, "temp_range": "-18C"},
    {"name": "Atlantic Salmon Fillets", "category": "seafood", "unit": "kg", "bag_size": 10, "temp_range": "0-2C"},
    {"name": "Sauvignon Blanc Reserve", "category": "wine", "unit": "cases", "bag_size": 12, "temp_range": "12-16C"},
    {"name": "Golden Kiwifruit", "category": "horticulture", "unit": "trays", "bag_size": 1, "temp_range": "0-2C"},
    {"name": "Raw Honey UMF 15+", "category": "apiculture", "unit": "kg", "bag_size": 20, "temp_range": "ambient"},
]

REGIONS = ["Western Valley", "Canterbury Plains", "Southern Highlands", "Coastal Bay", "Riverlands", "Highland Ridge", "Alpine Basin"]
CERTIFICATIONS = ["Organic Certified", "GlobalGAP", "ISO 22000", "Fair Trade", "None"]
GRADES = ["Premium A1", "Standard A2", "Commercial B1", "Select Grade"]


def generate_production_batch() -> dict:
    """Generates a realistic food export production batch."""
    product = random.choice(PRODUCTS)
    region = random.choice(REGIONS)
    bags = random.randint(20, 80)
    quantity = bags * product["bag_size"]
    cert = random.choice(CERTIFICATIONS)
    grade = random.choice(GRADES)
    process_date = datetime.utcnow() - timedelta(days=random.randint(1, 5))

    prefix = {"dairy": "DRY", "meat": "MET", "seafood": "SEA", "wine": "WNE",
              "horticulture": "HRT", "apiculture": "API"}
    batch_id = "%s-%d-%04d" % (prefix.get(product["category"], "EXP"),
                                datetime.utcnow().year, random.randint(1, 9999))

    return {
        "source": "supply_chain_producer",
        "agent_id": AGENT_ID,
        "batch_id": batch_id,
        "product": product["name"],
        "category": product["category"],
        "quantity_kg" if product["unit"] == "kg" else f"quantity_{product['unit']}": quantity,
        "unit_count": bags,
        "unit_type": "%d%s bags" % (product["bag_size"], product["unit"]) if product["unit"] == "kg" else product["unit"],
        "grade": grade,
        "farm_region": region,
        "organic_certification": cert,
        "process_date": process_date.strftime("%Y-%m-%d"),
        "expiry_date": (process_date + timedelta(days=random.choice([180, 365, 730]))).strftime("%Y-%m-%d"),
        "storage_temp": product["temp_range"],
        "traceability": {
            "farm_id": "FARM-%s-%04d" % (region[:3].upper(), random.randint(1, 999)),
            "processor_id": "PROC-%04d" % random.randint(100, 999),
            "facility_number": "FAC-%06d" % random.randint(100000, 999999),
            "traceable": product["category"] in ("dairy", "meat"),
        },
        "timestamp": datetime.utcnow().isoformat(),
    }


class ProducerExecutor(AgentExecutor):
    """Handles incoming A2A requests for the ProducerBot."""

    async def execute(self, context: RequestContext, event_queue: EventQueue):
        task_id = context.task_id
        ctx_id = context.context_id

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
                        parts=[Part(root=TextPart(text="Generating production batch data..."))],
                    ),
                ),
                final=False,
            )
        )

        batch = generate_production_batch()

        # Emit artifact
        await event_queue.enqueue_event(
            TaskArtifactUpdateEvent(
                taskId=task_id,
                contextId=ctx_id,
                artifact=Artifact(
                    artifactId=str(uuid.uuid4()),
                    name="production_batch",
                    description="Export batch: %s — %s" % (batch["batch_id"], batch["product"]),
                    parts=[Part(root=DataPart(data=batch))],
                ),
                final=False,
            )
        )

        # Status: completed
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
                            text="Batch %s ready: %s, %s, %s, %s" % (
                                batch["batch_id"], batch["product"], batch["grade"],
                                batch["farm_region"], batch["organic_certification"])
                        ))],
                    ),
                ),
                final=True,
            )
        )

    async def cancel(self, context: RequestContext, event_queue: EventQueue):
        raise Exception("ProducerBot does not support task cancellation")


def create_producer_agent():
    """Creates the ProducerBot A2A server."""
    card = build_agent_card(
        name="Supply Chain Producer",
        description=(
            "Autonomous agent representing a food/agriculture producer. Generates batch "
            "production data with full provenance: product type, batch ID, quantity, grade, "
            "farm location, organic certification, and traceability chain."
        ),
        url="http://localhost:%d/" % PORT,
        skills=[
            AgentSkill(
                id="production-batch",
                name="Production Batch Data",
                description="Generates export-ready production batch data with full provenance chain",
                tags=["food", "export", "production", "provenance", "supply-chain"],
                examples=["Generate a dairy export batch", "Create production data for meat export"],
                inputModes=["text", "application/json"],
                outputModes=["application/json"],
            ),
            AgentSkill(
                id="batch-lookup",
                name="Batch Lookup",
                description="Retrieves production details for an existing batch ID",
                tags=["food", "batch", "traceability", "lookup"],
                examples=["Look up batch DRY-2026-0847", "Get batch details"],
                inputModes=["text", "application/json"],
                outputModes=["application/json"],
            ),
        ],
    )

    return build_a2a_server(card, ProducerExecutor()), card


if __name__ == "__main__":
    from agents.a2a.base_agent import run_agent_server
    app, card = create_producer_agent()
    print("Starting %s on port %d" % (card.name, PORT))
    run_agent_server(app, PORT)
