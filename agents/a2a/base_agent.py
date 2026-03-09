"""
Base A2A Agent — Shared infrastructure for all The Last Bastion demo agents.

Each agent is a standards-compliant A2A server:
  - Publishes an Agent Card at /.well-known/agent-card.json
  - Accepts JSON-RPC 2.0 calls (message/send, tasks/get, etc.)
  - Uses the official a2a-sdk for all protocol handling

This base class provides:
  - Agent Card construction from config
  - Server startup/shutdown
  - A2A client for calling other agents
  - Logging and heartbeat
"""
import asyncio
import logging
import uuid
from datetime import datetime
from typing import Any, Dict, List, Optional

import httpx
import uvicorn

from a2a.client import A2AClient
from a2a.server.apps import A2AStarletteApplication
from a2a.server.request_handlers import DefaultRequestHandler
from a2a.server.tasks import InMemoryTaskStore
from a2a.types import (
    AgentCapabilities,
    AgentCard,
    AgentProvider,
    AgentSkill,
    DataPart,
    Message,
    MessageSendParams,
    Role,
    SendMessageRequest,
    TextPart,
)

logger = logging.getLogger("A2A.BaseAgent")


def build_agent_card(
    name: str,
    description: str,
    url: str,
    version: str = "1.0.0",
    skills: List[AgentSkill] = None,
    input_modes: List[str] = None,
    output_modes: List[str] = None,
    streaming: bool = False,
) -> AgentCard:
    """Constructs a standards-compliant A2A Agent Card."""
    return AgentCard(
        name=name,
        description=description,
        url=url,
        version=version,
        provider=AgentProvider(
            organization="The Last Bastion",
            url="https://registry-base.nz",
        ),
        capabilities=AgentCapabilities(
            streaming=streaming,
            pushNotifications=False,
            stateTransitionHistory=True,
        ),
        defaultInputModes=input_modes or ["application/json", "text"],
        defaultOutputModes=output_modes or ["application/json", "text"],
        skills=skills or [],
    )


def build_a2a_server(
    agent_card: AgentCard,
    executor,
) -> A2AStarletteApplication:
    """Builds an A2A Starlette application from an agent card + executor."""
    task_store = InMemoryTaskStore()
    request_handler = DefaultRequestHandler(
        agent_executor=executor,
        task_store=task_store,
    )
    return A2AStarletteApplication(
        agent_card=agent_card,
        http_handler=request_handler,
    )


async def discover_agent(agent_url: str) -> Optional[AgentCard]:
    """Fetches another agent's Agent Card for discovery."""
    async with httpx.AsyncClient(timeout=10.0) as client:
        try:
            a2a_client = A2AClient(httpx_client=client, url=agent_url)
            card = await a2a_client.get_card()
            logger.info(f"Discovered agent: {card.name} at {agent_url}")
            return card
        except Exception as e:
            logger.error(f"Failed to discover agent at {agent_url}: {e}")
            return None


async def send_a2a_message(
    target_url: str,
    parts: list,
    context_id: str = None,
    metadata: dict = None,
) -> dict:
    """
    Sends a message/send JSON-RPC call to another A2A agent.

    This is the standard way agents communicate in A2A.
    """
    async with httpx.AsyncClient(timeout=30.0) as client:
        a2a_client = A2AClient(httpx_client=client, url=target_url)

        message = Message(
            messageId=str(uuid.uuid4()),
            role=Role.user,
            parts=parts,
            contextId=context_id,
        )

        request = SendMessageRequest(
            id=str(uuid.uuid4()),
            params=MessageSendParams(
                message=message,
                metadata=metadata,
            ),
        )

        response = await a2a_client.send_message(request)

        # Extract result from response
        result = response.root
        if hasattr(result, "result"):
            return _serialize_response(result.result)
        elif hasattr(result, "error"):
            return {"error": str(result.error)}
        return {"raw": str(result)}


def _serialize_response(result) -> dict:
    """Converts an A2A response object to a plain dict."""
    if hasattr(result, "model_dump"):
        return result.model_dump()
    if hasattr(result, "__dict__"):
        return {k: v for k, v in result.__dict__.items() if not k.startswith("_")}
    return {"value": str(result)}


def add_passport_routes(starlette_app, private_key_hex: str = ""):
    """
    Adds /passport/challenge and /passport/fingerprint endpoints to a Starlette app.

    These are required for anti-clone enforcement in the verification pipeline:
    - /passport/challenge: proves the agent holds its Ed25519 private key
    - /passport/fingerprint: reports runtime environment hash for clone detection
    """
    from starlette.responses import JSONResponse
    from starlette.routing import Route
    import json as _json

    async def passport_challenge(request):
        """Sign a nonce with this agent's Ed25519 private key to prove identity."""
        if not private_key_hex:
            return JSONResponse({"error": "no_private_key"}, status_code=501)
        try:
            body = await request.json()
            nonce = body.get("nonce", "")
            if not nonce:
                return JSONResponse({"error": "missing_nonce"}, status_code=400)

            from lastbastion.crypto import sign_bytes
            passport_id = body.get("passport_id", "")
            # Crypto-bind nonce to agent identity (matches verifier expectation)
            challenge_data = f"{passport_id}:{nonce}" if passport_id else nonce
            signature = sign_bytes(challenge_data.encode(), private_key_hex)
            return JSONResponse({"signature": signature, "passport_id": passport_id})
        except Exception as e:
            logger.error(f"Challenge-response failed: {e}")
            return JSONResponse({"error": str(e)}, status_code=500)

    async def passport_fingerprint(request):
        """Report this agent's runtime fingerprint for anti-clone verification."""
        try:
            from lastbastion.passport import generate_runtime_fingerprint
            fp = generate_runtime_fingerprint()
            return JSONResponse({"runtime_fingerprint": fp})
        except Exception as e:
            logger.error(f"Fingerprint generation failed: {e}")
            return JSONResponse({"error": str(e)}, status_code=500)

    # Append routes to the existing Starlette app
    starlette_app.routes.append(Route("/passport/challenge", passport_challenge, methods=["POST"]))
    starlette_app.routes.append(Route("/passport/fingerprint", passport_fingerprint, methods=["GET"]))
    logger.info("Passport anti-clone routes mounted: /passport/challenge, /passport/fingerprint")
    return starlette_app


def run_agent_server(app: A2AStarletteApplication, port: int, host: str = "0.0.0.0"):
    """Starts a single agent's A2A server (blocking)."""
    starlette_app = app.build()
    uvicorn.run(starlette_app, host=host, port=port, log_level="info")
