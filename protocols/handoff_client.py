"""
Handoff Client — Outgoing A2A Handoff SDK.

Used by agents that want to SEND data to another agent.
Handles discovery, verification, handoff requests, and retries.

Usage:
    client = HandoffClient(agent_id="financial-bot-001",
                           api_base="http://localhost:8000")
    await client.register_self(public_key="abc123", role="DATA_PROVIDER")
    agents = await client.discover_agents(tags=["verification"])
    result = await client.request_handoff("insurance-bot-001", payload)
"""
import logging
from typing import Any, Dict, List, Optional

import httpx

logger = logging.getLogger("HandoffClient")

API_TIMEOUT = 30.0


class HandoffClient:
    """
    Outgoing handoff SDK — the sending side of A2A.

    Handles:
    - Agent self-registration
    - Service/agent discovery
    - Sending handoff requests
    - Handling REDIRECT responses (auto-verify if needed)
    - Retrieving own passport status
    """

    def __init__(
        self,
        agent_id: str,
        api_base: str = "http://localhost:8000",
    ):
        self.agent_id = agent_id
        self.api_base = api_base.rstrip("/")
        self.api_key_id = ""
        self.api_secret = ""
        self._client = httpx.AsyncClient(timeout=API_TIMEOUT)

    async def register_self(
        self,
        public_key: str = "",
        role: str = "DATA_CONSUMER",
        display_name: str = "",
        capabilities: list = None,
    ) -> Dict[str, Any]:
        """Registers this agent with The Last Bastion. Returns API key."""
        try:
            resp = await self._client.post(
                f"{self.api_base}/m2m/register",
                json={
                    "agent_id": self.agent_id,
                    "public_key": public_key or "0" * 64,
                    "role": role,
                    "display_name": display_name or self.agent_id,
                    "capabilities": capabilities or [],
                },
            )
            resp.raise_for_status()
            data = resp.json()
            # Store API key for authenticated endpoints
            api_key = data.get("api_key", {})
            self.api_key_id = api_key.get("key_id", "")
            self.api_secret = api_key.get("secret", "")
            logger.info(
                f"Registered as {self.agent_id}, "
                f"key={self.api_key_id[:8]}..."
            )
            return data
        except Exception as e:
            logger.error(f"Registration failed: {e}")
            return {"error": str(e)}

    async def verify_self(
        self,
        agent_name: str = "",
        agent_url: str = "",
        public_key: str = "",
        capabilities: list = None,
        metadata: dict = None,
    ) -> Dict[str, Any]:
        """Submits this agent for full verification (passport stamping)."""
        try:
            resp = await self._client.post(
                f"{self.api_base}/m2m/verify-agent",
                json={
                    "agent_id": self.agent_id,
                    "agent_name": agent_name or self.agent_id,
                    "agent_url": agent_url,
                    "public_key": public_key or "0" * 64,
                    "capabilities": capabilities or [],
                    "metadata": metadata or {},
                },
            )
            resp.raise_for_status()
            return resp.json()
        except Exception as e:
            logger.error(f"Verification failed: {e}")
            return {"error": str(e)}

    async def discover_agents(
        self, tags: list = None, region: str = ""
    ) -> List[Dict[str, Any]]:
        """Discovers available services/agents."""
        try:
            params = {}
            if tags:
                params["tags"] = ",".join(tags)
            if region:
                params["region"] = region
            resp = await self._client.get(
                f"{self.api_base}/m2m/discover", params=params
            )
            resp.raise_for_status()
            return resp.json().get("services", [])
        except Exception as e:
            logger.error(f"Discovery failed: {e}")
            return []

    async def get_own_passport(self) -> Dict[str, Any]:
        """Checks this agent's verification status."""
        try:
            resp = await self._client.get(
                f"{self.api_base}/m2m/verify-agent/{self.agent_id}"
            )
            resp.raise_for_status()
            return resp.json()
        except Exception as e:
            logger.error(f"Passport check failed: {e}")
            return {"verified": False, "status": "ERROR"}

    async def request_handoff(
        self,
        target_id: str,
        payload: Dict[str, Any],
        payload_summary: str = "",
        auto_verify: bool = True,
    ) -> Dict[str, Any]:
        """
        Sends a handoff request to a target agent.

        If the response is REDIRECT and auto_verify is True,
        automatically submits for verification and retries.
        """
        try:
            resp = await self._client.post(
                f"{self.api_base}/m2m/handoff/request",
                json={
                    "sender_id": self.agent_id,
                    "receiver_id": target_id,
                    "payload": payload,
                    "payload_summary": payload_summary,
                },
            )
            resp.raise_for_status()
            data = resp.json()

            # Handle REDIRECT — auto-verify and retry
            if data.get("status") == "REDIRECT" and auto_verify:
                logger.info(
                    f"Got REDIRECT — auto-verifying {self.agent_id}..."
                )
                verify_result = await self.verify_self()
                if verify_result.get("verdict") in ("TRUSTED", "SUSPICIOUS"):
                    logger.info("Verification complete — retrying handoff...")
                    return await self.request_handoff(
                        target_id, payload, payload_summary,
                        auto_verify=False,  # Don't loop
                    )

            return data
        except Exception as e:
            logger.error(f"Handoff request failed: {e}")
            return {"status": "error", "message": str(e)}

    async def close(self):
        """Closes the HTTP client."""
        await self._client.aclose()
