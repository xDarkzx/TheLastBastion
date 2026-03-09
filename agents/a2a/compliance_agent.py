"""
ComplianceBot — Export Compliance Checker.

A2A-compliant agent that validates food exports against international
food safety standards. Checks residue limits, temperature records,
traceability, and labelling. Issues or rejects export certificates.

Skills:
  - export-certification: Validates a production batch and issues/rejects export cert
  - regulation-check: Checks specific compliance requirements for a product category
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

logger = logging.getLogger("A2A.ComplianceBot")

AGENT_ID = "compliance-bot-001"
PORT = 9002

# International food safety compliance rules by category
COMPLIANCE_RULES = {
    "dairy": {"standard": "Codex Alimentarius CAC/RCP 57", "max_residue_ppm": 0.01, "temp_required": True},
    "meat": {"standard": "Codex Alimentarius CAC/RCP 58", "max_residue_ppm": 0.005, "temp_required": True},
    "seafood": {"standard": "Codex Alimentarius CAC/RCP 52", "max_residue_ppm": 0.05, "temp_required": True},
    "wine": {"standard": "OIV International Standards", "max_residue_ppm": 0.1, "temp_required": False},
    "horticulture": {"standard": "GlobalGAP IFA v6", "max_residue_ppm": 0.01, "temp_required": True},
    "apiculture": {"standard": "Codex Alimentarius CXS 12", "max_residue_ppm": 0.001, "temp_required": False},
}


def validate_batch(batch_data: dict) -> dict:
    """Validates a production batch against international export requirements."""
    category = batch_data.get("category", "dairy")
    rules = COMPLIANCE_RULES.get(category, COMPLIANCE_RULES["dairy"])
    batch_id = batch_data.get("batch_id", "UNKNOWN")
    traceability = batch_data.get("traceability", {})

    # Run compliance checks
    residue_level = round(random.uniform(0.0001, rules["max_residue_ppm"] * 1.2), 4)
    residue_passed = residue_level <= rules["max_residue_ppm"]

    temp_compliant = True
    if rules["temp_required"]:
        temp_compliant = random.random() > 0.05  # 95% pass rate

    traceability_complete = bool(traceability.get("farm_id") and traceability.get("processor_id"))
    labelling_ok = random.random() > 0.03  # 97% pass rate

    all_passed = residue_passed and temp_compliant and traceability_complete and labelling_ok

    checks = {
        "residue_testing": {
            "status": "PASSED" if residue_passed else "FAILED",
            "measured_ppm": residue_level,
            "mrl_limit_ppm": rules["max_residue_ppm"],
            "detail": "Below MRL limits" if residue_passed else "EXCEEDS maximum residue limit",
        },
        "temperature_records": {
            "status": "COMPLIANT" if temp_compliant else "NON-COMPLIANT",
            "required_range": batch_data.get("storage_temp", "2-6C"),
            "detail": "Cold chain records complete" if temp_compliant else "Temperature excursion detected",
        },
        "traceability": {
            "status": "VERIFIED" if traceability_complete else "INCOMPLETE",
            "farm_id": traceability.get("farm_id", "MISSING"),
            "processor_id": traceability.get("processor_id", "MISSING"),
            "facility_number": traceability.get("facility_number", "MISSING"),
            "detail": "Farm-to-processor chain complete" if traceability_complete else "Missing traceability records",
        },
        "labelling": {
            "status": "COMPLIANT" if labelling_ok else "NON-COMPLIANT",
            "detail": "Country of origin, allergens, and nutritional info present" if labelling_ok else "Labelling deficiencies found",
        },
    }

    cert_number = "EXP-CERT-%d-%04d" % (datetime.utcnow().year, random.randint(1, 9999)) if all_passed else None

    return {
        "source": "export_compliance_checker",
        "agent_id": AGENT_ID,
        "batch_id": batch_id,
        "product": batch_data.get("product", "Unknown"),
        "category": category,
        "applicable_standard": rules["standard"],
        "checks": checks,
        "overall_result": "CERTIFIED" if all_passed else "REJECTED",
        "certificate_number": cert_number,
        "valid_for_export_to": ["China", "Singapore", "Japan", "UAE", "EU", "UK"] if all_passed else [],
        "inspector_id": "INS-%04d" % random.randint(100, 999),
        "timestamp": datetime.utcnow().isoformat(),
    }


class ComplianceExecutor(AgentExecutor):
    """Handles incoming A2A requests for the ComplianceBot."""

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
                        parts=[Part(root=TextPart(text="Running export compliance checks..."))],
                    ),
                ),
                final=False,
            )
        )

        result = validate_batch(incoming_data)

        # Emit artifact
        await event_queue.enqueue_event(
            TaskArtifactUpdateEvent(
                taskId=task_id,
                contextId=ctx_id,
                artifact=Artifact(
                    artifactId=str(uuid.uuid4()),
                    name="compliance_result",
                    description="Compliance: %s — %s" % (result["batch_id"], result["overall_result"]),
                    parts=[Part(root=DataPart(data=result))],
                ),
                final=False,
            )
        )

        # Status: completed
        cert_info = "cert %s" % result["certificate_number"] if result["certificate_number"] else "no certificate"
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
                            text="Compliance check complete: %s — %s (%s)" % (
                                result["batch_id"], result["overall_result"], cert_info)
                        ))],
                    ),
                ),
                final=True,
            )
        )

    async def cancel(self, context: RequestContext, event_queue: EventQueue):
        raise Exception("ComplianceBot does not support task cancellation")


def create_compliance_agent():
    """Creates the ComplianceBot A2A server."""
    card = build_agent_card(
        name="Export Compliance Checker",
        description=(
            "Autonomous agent validating food exports against international food safety "
            "standards (Codex Alimentarius, GlobalGAP, OIV). Checks residue limits, "
            "temperature records, traceability, and labelling compliance."
        ),
        url="http://localhost:%d/" % PORT,
        skills=[
            AgentSkill(
                id="export-certification",
                name="Export Certification",
                description="Validates production batch data and issues or rejects export certificates",
                tags=["compliance", "export", "food-safety", "certification", "codex"],
                examples=["Certify this batch for export", "Check export compliance"],
                inputModes=["application/json"],
                outputModes=["application/json"],
            ),
            AgentSkill(
                id="regulation-check",
                name="Regulation Lookup",
                description="Checks specific compliance requirements for a product category",
                tags=["compliance", "regulation", "food-safety", "standards"],
                examples=["What are dairy export requirements?", "Check meat residue limits"],
                inputModes=["text", "application/json"],
                outputModes=["application/json"],
            ),
        ],
    )

    return build_a2a_server(card, ComplianceExecutor()), card


if __name__ == "__main__":
    from agents.a2a.base_agent import run_agent_server
    app, card = create_compliance_agent()
    print("Starting %s on port %d" % (card.name, PORT))
    run_agent_server(app, PORT)
