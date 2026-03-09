"""
Echo Agent — Simplest integration test for external developers.

Receives any payload via A2A, echoes it back through the verification pipeline.
Returns the verification verdict alongside the echoed data.

"Can my agent talk to yours?" — this agent answers that question.

Port: 9010
"""

import asyncio
import json
import logging
import uuid
from datetime import datetime
from typing import Any, AsyncIterable

import httpx
import uvicorn
from a2a.server.agent_execution import AgentExecutor, RequestContext
from a2a.server.events import EventQueue
from a2a.types import (
    AgentSkill,
    DataPart,
    Message,
    Part,
    Role,
    Task,
    TaskState,
    TaskStatus,
    TextPart,
)

from agents.a2a.base_agent import (
    add_passport_routes,
    build_a2a_server,
    build_agent_card,
)

logger = logging.getLogger("EchoAgent")

ECHO_PORT = 9010
REGISTRY_URL = "http://localhost:8000"


class EchoExecutor(AgentExecutor):
    """Echoes the incoming payload and optionally verifies it."""

    async def execute(self, context: RequestContext, event_queue: EventQueue):
        # Extract the incoming message text/data
        incoming = ""
        incoming_data = {}
        if context.message and context.message.parts:
            for part in context.message.parts:
                if hasattr(part, "root"):
                    part = part.root
                if isinstance(part, TextPart):
                    incoming = part.text
                elif isinstance(part, DataPart):
                    incoming_data = part.data if isinstance(part.data, dict) else {}

        # Try to parse text as JSON if no data part
        if not incoming_data and incoming:
            try:
                incoming_data = json.loads(incoming)
            except (json.JSONDecodeError, TypeError):
                incoming_data = {"message": incoming}

        # Run verification if we have data
        verification = {"note": "no verification — no payload data"}
        if incoming_data:
            try:
                async with httpx.AsyncClient(timeout=30.0) as client:
                    resp = await client.post(
                        f"{REGISTRY_URL}/refinery/submit",
                        json={
                            "payload": incoming_data,
                            "source_agent_id": "echo-agent",
                            "context": {"via": "echo-agent"},
                        },
                    )
                    if resp.status_code == 200:
                        verification = resp.json()
                    else:
                        verification = {"error": f"HTTP {resp.status_code}"}
            except Exception as e:
                verification = {"error": str(e)}

        # Build echo response
        response = {
            "echo": incoming_data or incoming,
            "timestamp": datetime.utcnow().isoformat() + "Z",
            "verification": {
                "verdict": verification.get("verdict", "N/A"),
                "score": verification.get("score", 0),
                "proof_hash": verification.get("proof_hash", ""),
            },
        }

        task = Task(
            id=context.task_id or str(uuid.uuid4()),
            contextId=context.context_id or str(uuid.uuid4()),
            status=TaskStatus(state=TaskState.completed),
            history=[
                Message(
                    messageId=str(uuid.uuid4()),
                    role=Role.agent,
                    parts=[DataPart(data=response)],
                ),
            ],
        )
        event_queue.enqueue_event(task)

    async def cancel(self, context: RequestContext, event_queue: EventQueue):
        pass


def create_echo_agent():
    card = build_agent_card(
        name="Echo Agent",
        description=(
            "Integration test agent. Send any payload — it echoes back "
            "with a verification verdict from The Last Bastion pipeline."
        ),
        url=f"http://localhost:{ECHO_PORT}",
        skills=[
            AgentSkill(
                id="echo",
                name="Echo & Verify",
                description="Echoes your payload and runs it through the verification pipeline.",
                tags=["test", "echo", "verification"],
                examples=["Send any JSON payload to test connectivity and verification."],
            ),
        ],
    )
    return build_a2a_server(card, EchoExecutor())


def main():
    app = create_echo_agent()
    starlette_app = app.build()
    logger.info(f"Echo Agent starting on port {ECHO_PORT}")
    uvicorn.run(starlette_app, host="0.0.0.0", port=ECHO_PORT, log_level="info")


if __name__ == "__main__":
    main()
