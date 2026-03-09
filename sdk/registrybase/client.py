"""
RegistryBaseClient — thin async httpx wrapper for The Last Bastion API.

Usage:
    from registrybase import RegistryBaseClient

    client = RegistryBaseClient(
        api_key="sandbox_sk_abc:secret",
        base_url="http://localhost:8000"
    )

    # Register and verify an agent
    await client.register_agent("my-agent-001", public_key="ed25519_pub_key")
    result = await client.verify_agent("my-agent-001", agent_url="http://my-agent:9000")

    # Start a sandbox session and run attacks
    session = await client.start_session("my-agent-001", config={"timeout": 120})
    attacks = await client.run_attacks(session["id"], attack_types=["prompt_injection", "replay"])
    results = await client.get_results(session["id"])
"""

import httpx
from typing import Any, Dict, List, Optional

from registrybase.exceptions import (
    AuthenticationError,
    NotFoundError,
    RateLimitError,
    RegistryBaseError,
    ValidationError,
)


class RegistryBaseClient:
    """Async client for The Last Bastion Agent Security Sandbox."""

    def __init__(
        self,
        api_key: str = "",
        base_url: str = "http://localhost:8000",
        timeout: float = 30.0,
    ):
        self.base_url = base_url.rstrip("/")
        self._timeout = timeout

        # Parse "key_id:secret" format
        self._key_id = ""
        self._key_secret = ""
        if ":" in api_key:
            self._key_id, self._key_secret = api_key.split(":", 1)
        elif api_key:
            self._key_id = api_key

        self._client: Optional[httpx.AsyncClient] = None

    async def _get_client(self) -> httpx.AsyncClient:
        if self._client is None or self._client.is_closed:
            headers = {"Content-Type": "application/json"}
            if self._key_id:
                headers["X-API-Key-ID"] = self._key_id
            if self._key_secret:
                headers["X-API-Secret"] = self._key_secret
            self._client = httpx.AsyncClient(
                base_url=self.base_url,
                headers=headers,
                timeout=self._timeout,
            )
        return self._client

    async def close(self):
        if self._client and not self._client.is_closed:
            await self._client.aclose()

    async def __aenter__(self):
        return self

    async def __aexit__(self, *args):
        await self.close()

    def _handle_response(self, resp: httpx.Response) -> dict:
        if resp.status_code == 401:
            raise AuthenticationError("Authentication failed", status_code=401)
        if resp.status_code == 404:
            raise NotFoundError("Resource not found", status_code=404)
        if resp.status_code == 429:
            raise RateLimitError("Rate limit exceeded", status_code=429)
        if resp.status_code == 422:
            raise ValidationError("Validation error", status_code=422, detail=resp.json())
        if resp.status_code >= 400:
            raise RegistryBaseError(
                f"API error {resp.status_code}", status_code=resp.status_code
            )
        return resp.json()

    # -----------------------------------------------------------------------
    # M2M Core Methods
    # -----------------------------------------------------------------------

    async def register_agent(
        self,
        agent_id: str,
        public_key: str = "",
        role: str = "DATA_PROVIDER",
        capabilities: List[str] = None,
    ) -> dict:
        """Register an agent on the platform. Returns agent_id and API key."""
        client = await self._get_client()
        resp = await client.post("/m2m/register", json={
            "agent_id": agent_id,
            "public_key": public_key or f"ed25519_pub_{agent_id}",
            "role": role,
            "capabilities": capabilities or [],
        })
        return self._handle_response(resp)

    async def verify_agent(
        self,
        agent_id: str,
        agent_url: str = "",
        capabilities: List[str] = None,
    ) -> dict:
        """Submit an agent for trust verification (10-check pipeline)."""
        client = await self._get_client()
        resp = await client.post(f"/m2m/dashboard/agents/{agent_id}/verify", json={
            "agent_url": agent_url,
            "capabilities": capabilities or [],
        })
        return self._handle_response(resp)

    async def get_trust_status(self, agent_id: str) -> dict:
        """Get the current trust status for an agent."""
        client = await self._get_client()
        resp = await client.get(f"/m2m/dashboard/agents/{agent_id}")
        return self._handle_response(resp)

    async def submit_payload(
        self,
        payload: Dict[str, Any],
        context: Dict[str, Any] = None,
        source_agent_id: str = "",
    ) -> dict:
        """Submit data payload for verification through the refinery pipeline."""
        client = await self._get_client()
        resp = await client.post("/refinery/submit", json={
            "payload": payload,
            "context": context or {},
            "source_agent_id": source_agent_id,
        })
        return self._handle_response(resp)

    async def handoff(
        self,
        sender_id: str,
        receiver_id: str,
        payload: Dict[str, Any],
    ) -> dict:
        """Initiate a verified handoff between two agents."""
        client = await self._get_client()
        resp = await client.post("/m2m/handoff", json={
            "sender_id": sender_id,
            "receiver_id": receiver_id,
            "payload": payload,
        })
        return self._handle_response(resp)

    # -----------------------------------------------------------------------
    # Sandbox Methods
    # -----------------------------------------------------------------------

    async def start_session(
        self,
        agent_id: str,
        config: Dict[str, Any] = None,
    ) -> dict:
        """Start a sandbox test session for an agent."""
        client = await self._get_client()
        resp = await client.post("/sandbox/sessions", json={
            "agent_id": agent_id,
            "config": config or {},
        })
        return self._handle_response(resp)

    async def run_attacks(
        self,
        session_id: str,
        attack_types: List[str] = None,
    ) -> dict:
        """Run attack simulations against an agent in a session."""
        client = await self._get_client()
        resp = await client.post(f"/sandbox/sessions/{session_id}/attacks", json={
            "attack_types": attack_types or [],
        })
        return self._handle_response(resp)

    async def get_session(self, session_id: str) -> dict:
        """Get sandbox session status."""
        client = await self._get_client()
        resp = await client.get(f"/sandbox/sessions/{session_id}")
        return self._handle_response(resp)

    async def submit_to_session(
        self,
        session_id: str,
        payload: Dict[str, Any],
        context: Dict[str, Any] = None,
    ) -> dict:
        """Submit a payload for verification within a sandbox session."""
        client = await self._get_client()
        resp = await client.post(f"/sandbox/sessions/{session_id}/submit", json={
            "payload": payload,
            "context": context or {},
        })
        return self._handle_response(resp)

    async def get_results(self, session_id: str) -> dict:
        """Get full results for a sandbox session."""
        client = await self._get_client()
        resp = await client.get(f"/sandbox/sessions/{session_id}/results")
        return self._handle_response(resp)

    async def get_trust_history(self, agent_id: str) -> list:
        """Get trust score audit trail for an agent."""
        client = await self._get_client()
        resp = await client.get(f"/sandbox/agents/{agent_id}/trust-history")
        return self._handle_response(resp)

    async def get_leaderboard(self) -> list:
        """Get the public agent trust leaderboard."""
        client = await self._get_client()
        resp = await client.get("/sandbox/leaderboard")
        return self._handle_response(resp)
