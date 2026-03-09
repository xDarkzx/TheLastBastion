"""
LogisticsBot — Export Freight & Cold Chain Tracker.

A2A-compliant agent managing freight logistics and cold chain monitoring
for food exports. Assigns containers, tracks temperature/humidity
during transit, monitors GPS, and calculates ETAs.

Skills:
  - ship-batch: Assigns container and vessel for a certified export batch
  - cold-chain-status: Returns current cold chain telemetry for a shipment
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

logger = logging.getLogger("A2A.LogisticsBot")

AGENT_ID = "logistics-bot-001"
PORT = 9003

ROUTES = [
    {"origin": "Port of Rotterdam", "destination": "Shanghai", "transit_days": 28, "vessel": "Maersk Kobe"},
    {"origin": "Port of Singapore", "destination": "Hamburg", "transit_days": 22, "vessel": "CMA CGM Bellini"},
    {"origin": "Port of Melbourne", "destination": "Dubai", "transit_days": 18, "vessel": "Evergreen Harmony"},
    {"origin": "Port of Busan", "destination": "Tokyo", "transit_days": 5, "vessel": "ONE Aquila"},
    {"origin": "Port of Los Angeles", "destination": "Sydney", "transit_days": 16, "vessel": "MSC Gülsün"},
    {"origin": "Port of Santos", "destination": "London", "transit_days": 24, "vessel": "Hapag-Lloyd Express"},
]

CONTAINER_PREFIXES = ["MSCU", "CMAU", "EISU", "OOLU", "HLCU", "MAEU"]


def assign_shipment(batch_data: dict) -> dict:
    """Assigns container, vessel, and route for a certified export batch."""
    route = random.choice(ROUTES)
    prefix = random.choice(CONTAINER_PREFIXES)
    container_id = "%s-%07d" % (prefix, random.randint(1000000, 9999999))

    # Determine reefer requirements from batch data
    storage_temp = batch_data.get("storage_temp",
                   batch_data.get("checks", {}).get("temperature_records", {}).get("required_range", "2-6C"))

    is_reefer = storage_temp != "ambient"
    departure = datetime.utcnow() + timedelta(days=random.randint(1, 3))
    eta = departure + timedelta(days=route["transit_days"])

    # Generate cold chain telemetry snapshots
    readings = []
    for i in range(min(5, route["transit_days"])):
        day_offset = i * (route["transit_days"] // 5) if route["transit_days"] >= 5 else i
        readings.append({
            "timestamp": (departure + timedelta(days=day_offset)).isoformat(),
            "temperature_c": round(random.uniform(1.5, 6.5) if is_reefer else random.uniform(15, 25), 1),
            "humidity_pct": round(random.uniform(60, 85), 1),
            "gps_lat": round(random.uniform(-45.0, 55.0), 4),
            "gps_lon": round(random.uniform(-120.0, 170.0), 4),
            "door_status": "SEALED",
            "power_status": "ON" if is_reefer else "N/A",
        })

    # Check for temperature excursions
    temp_excursions = [r for r in readings if is_reefer and (r["temperature_c"] < 0 or r["temperature_c"] > 8)]
    cold_chain_intact = len(temp_excursions) == 0

    batch_id = batch_data.get("batch_id", batch_data.get("certificate_number", "UNKNOWN"))

    return {
        "source": "export_logistics",
        "agent_id": AGENT_ID,
        "batch_id": batch_id,
        "container_id": container_id,
        "container_type": "40ft Reefer" if is_reefer else "40ft Dry",
        "vessel": route["vessel"],
        "voyage_id": "26E-%04d" % random.randint(100, 9999),
        "route": {
            "origin": route["origin"],
            "destination": route["destination"],
            "transit_days": route["transit_days"],
        },
        "departure_date": departure.strftime("%Y-%m-%d"),
        "eta": eta.strftime("%Y-%m-%d"),
        "temperature_setting": storage_temp,
        "cold_chain": {
            "monitoring": "ACTIVE" if is_reefer else "N/A",
            "readings": readings,
            "excursions": len(temp_excursions),
            "chain_intact": cold_chain_intact,
        },
        "tracking_status": "GPS_ACTIVE",
        "customs_clearance": "PRE-CLEARED",
        "bill_of_lading": "BOL-%s-%04d" % (datetime.utcnow().strftime("%y%m"), random.randint(1, 9999)),
        "timestamp": datetime.utcnow().isoformat(),
    }


class LogisticsExecutor(AgentExecutor):
    """Handles incoming A2A requests for the LogisticsBot."""

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
                        parts=[Part(root=TextPart(text="Assigning container and booking vessel..."))],
                    ),
                ),
                final=False,
            )
        )

        shipment = assign_shipment(incoming_data)

        # Emit artifact
        await event_queue.enqueue_event(
            TaskArtifactUpdateEvent(
                taskId=task_id,
                contextId=ctx_id,
                artifact=Artifact(
                    artifactId=str(uuid.uuid4()),
                    name="shipment_manifest",
                    description="Shipment: %s via %s (%s -> %s)" % (
                        shipment["container_id"], shipment["vessel"],
                        shipment["route"]["origin"], shipment["route"]["destination"]),
                    parts=[Part(root=DataPart(data=shipment))],
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
                            text="Shipment booked: %s on %s, %s -> %s, ETA %s, cold chain %s" % (
                                shipment["container_id"], shipment["vessel"],
                                shipment["route"]["origin"], shipment["route"]["destination"],
                                shipment["eta"],
                                "INTACT" if shipment["cold_chain"]["chain_intact"] else "EXCURSION DETECTED")
                        ))],
                    ),
                ),
                final=True,
            )
        )

    async def cancel(self, context: RequestContext, event_queue: EventQueue):
        raise Exception("LogisticsBot does not support task cancellation")


def create_logistics_agent():
    """Creates the LogisticsBot A2A server."""
    card = build_agent_card(
        name="Export Logistics & Cold Chain",
        description=(
            "Autonomous freight and cold chain agent for food exports. "
            "Assigns reefer containers, books vessels, tracks temperature/humidity/GPS "
            "during transit. Routes across major international shipping lanes."
        ),
        url="http://localhost:%d/" % PORT,
        skills=[
            AgentSkill(
                id="ship-batch",
                name="Ship Export Batch",
                description="Assigns container, vessel, and route for a certified export batch",
                tags=["logistics", "freight", "cold-chain", "shipping", "export"],
                examples=["Ship this certified batch", "Book container for export"],
                inputModes=["application/json"],
                outputModes=["application/json"],
            ),
            AgentSkill(
                id="cold-chain-status",
                name="Cold Chain Status",
                description="Returns current cold chain telemetry (temperature, humidity, GPS) for a shipment",
                tags=["cold-chain", "temperature", "tracking", "reefer"],
                examples=["Cold chain status for container MSCU-7234519", "Check temperature readings"],
                inputModes=["text", "application/json"],
                outputModes=["application/json"],
            ),
        ],
    )

    return build_a2a_server(card, LogisticsExecutor()), card


if __name__ == "__main__":
    from agents.a2a.base_agent import run_agent_server
    app, card = create_logistics_agent()
    print("Starting %s on port %d" % (card.name, PORT))
    run_agent_server(app, PORT)
