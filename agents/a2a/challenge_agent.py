"""
Challenge Agent — Sends crafted payloads to test the verification pipeline.

External developers connect to this agent and receive a series of test payloads:
- Clean data (should pass verification)
- Injection attempts (should be caught)
- Arithmetic mismatches (should be flagged)
- Empty/minimal payloads (edge cases)

The agent returns each payload with its expected verdict so devs can compare.

Port: 9011
"""

import asyncio
import json
import logging
import uuid
from datetime import datetime
from typing import Any, AsyncIterable

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

from agents.a2a.base_agent import build_a2a_server, build_agent_card

logger = logging.getLogger("ChallengeAgent")

CHALLENGE_PORT = 9011

# Pre-built challenge payloads
CHALLENGES = [
    {
        "id": "clean-invoice",
        "category": "CLEAN",
        "description": "Valid invoice with correct arithmetic",
        "expected_verdict": "VERIFIED",
        "payload": {
            "invoice_id": "TEST-INV-001",
            "vendor": "Verified Supplies Ltd",
            "items": [
                {"name": "Component A", "qty": 10, "unit_price": 50.00},
                {"name": "Component B", "qty": 5, "unit_price": 200.00},
            ],
            "subtotal": 1500.00,
            "tax": 225.00,
            "total": 1725.00,
            "currency": "NZD",
        },
    },
    {
        "id": "sql-injection",
        "category": "MALICIOUS",
        "description": "SQL injection in vendor name",
        "expected_verdict": "REJECTED",
        "payload": {
            "invoice_id": "TEST-INV-002",
            "vendor": "'; DROP TABLE users; --",
            "amount": 100.00,
        },
    },
    {
        "id": "xss-injection",
        "category": "MALICIOUS",
        "description": "XSS script tag in field value",
        "expected_verdict": "REJECTED",
        "payload": {
            "invoice_id": "TEST-INV-003",
            "vendor": '<img src=x onerror=alert("xss")>',
            "amount": 500.00,
        },
    },
    {
        "id": "arithmetic-mismatch",
        "category": "SUSPICIOUS",
        "description": "Total doesn't match line items",
        "expected_verdict": "QUARANTINE",
        "payload": {
            "invoice_id": "TEST-INV-004",
            "vendor": "Mismatch Corp",
            "items": [
                {"name": "Widget", "qty": 10, "unit_price": 100.00},
            ],
            "total": 50000.00,  # Should be 1000.00
        },
    },
    {
        "id": "empty-payload",
        "category": "EDGE_CASE",
        "description": "Empty object — minimal data",
        "expected_verdict": "REJECTED",
        "payload": {},
    },
    {
        "id": "python-injection",
        "category": "MALICIOUS",
        "description": "Python code injection attempt",
        "expected_verdict": "REJECTED",
        "payload": {
            "vendor": "__import__('os').system('rm -rf /')",
            "amount": 0,
        },
    },
]


class ChallengeExecutor(AgentExecutor):
    """Serves challenge payloads for testing the verification pipeline."""

    async def execute(self, context: RequestContext, event_queue: EventQueue):
        # Parse incoming request for specific challenge or "all"
        requested = "all"
        if context.message and context.message.parts:
            for part in context.message.parts:
                if hasattr(part, "root"):
                    part = part.root
                if isinstance(part, TextPart) and part.text.strip():
                    requested = part.text.strip().lower()

        # Select challenges
        if requested == "all":
            selected = CHALLENGES
        else:
            selected = [c for c in CHALLENGES if c["id"] == requested or c["category"].lower() == requested]
            if not selected:
                selected = CHALLENGES  # fallback to all

        response = {
            "challenge_set": f"{len(selected)} payloads",
            "instruction": (
                "Submit each payload to /refinery/submit and compare the verdict "
                "against expected_verdict. This tests your integration with "
                "The Last Bastion verification pipeline."
            ),
            "challenges": selected,
            "timestamp": datetime.utcnow().isoformat() + "Z",
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


def create_challenge_agent():
    card = build_agent_card(
        name="Challenge Agent",
        description=(
            "Sends crafted test payloads (clean, malicious, edge cases) "
            "to help developers test their integration with The Last Bastion "
            "verification pipeline."
        ),
        url=f"http://localhost:{CHALLENGE_PORT}",
        skills=[
            AgentSkill(
                id="challenge-all",
                name="Get All Challenges",
                description="Returns all test payloads with expected verdicts.",
                tags=["test", "challenge", "verification"],
                examples=[
                    "Send 'all' to get every challenge payload.",
                    "Send 'clean' to get only clean payloads.",
                    "Send 'malicious' to get injection test payloads.",
                ],
            ),
        ],
    )
    return build_a2a_server(card, ChallengeExecutor())


def main():
    app = create_challenge_agent()
    starlette_app = app.build()
    logger.info(f"Challenge Agent starting on port {CHALLENGE_PORT}")
    uvicorn.run(starlette_app, host="0.0.0.0", port=CHALLENGE_PORT, log_level="info")


if __name__ == "__main__":
    main()
