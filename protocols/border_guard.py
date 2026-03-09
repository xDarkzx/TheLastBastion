"""
Border Control Guard — Incoming Handoff Interceptor.

Every agent imports this SDK to handle incoming handoff requests.
The guard checks the sender's "passport" (verification status) via
The Last Bastion, optionally redirects unverified agents, then verifies the
payload through the 5-layer pipeline before accepting.

Usage:
    guard = BorderGuard(my_identity, api_base="http://localhost:8000")
    result = await guard.process_incoming_handoff(sender_id, payload)
    if result["status"] == "ACCEPTED":
        print("Data received:", result)
"""
import hashlib
import json
import logging
from dataclasses import dataclass
from typing import Any, Dict, Optional

import httpx

logger = logging.getLogger("BorderGuard")

API_TIMEOUT = 30.0


@dataclass
class PassportStatus:
    verified: bool
    status: str
    trust_score: float
    proof_hash: str = ""
    expires_at: str = ""


@dataclass
class HandoffResult:
    handoff_id: str
    status: str  # ACCEPTED, REJECTED, REDIRECT, PENDING
    message: str
    sender_verified: bool = False
    sender_trust_score: float = 0.0
    payload_verdict: str = ""
    payload_score: float = 0.0
    proof_hash: str = ""
    tx_hash: str = ""


class BorderGuard:
    """
    Border Control Guard SDK — handles incoming A2A handoffs.

    For each incoming handoff:
    1. Checks sender's passport via GET /m2m/verify-agent/{id}
    2. If unverified, returns REGISTER_REDIRECT
    3. If verified, submits payload to POST /m2m/handoff/request
    4. Returns verdict to the calling agent
    """

    def __init__(
        self,
        agent_id: str,
        api_base: str = "http://localhost:8000",
        api_key_id: str = "",
        api_secret: str = "",
    ):
        self.agent_id = agent_id
        self.api_base = api_base.rstrip("/")
        self.api_key_id = api_key_id
        self.api_secret = api_secret
        self._client = httpx.AsyncClient(timeout=API_TIMEOUT)

    async def check_passport(self, agent_id: str) -> PassportStatus:
        """Checks an agent's verification status (passport lookup)."""
        try:
            resp = await self._client.get(
                f"{self.api_base}/m2m/verify-agent/{agent_id}"
            )
            resp.raise_for_status()
            data = resp.json()
            return PassportStatus(
                verified=data.get("verified", False),
                status=data.get("status", "UNKNOWN"),
                trust_score=data.get("trust_score", 0.0),
                proof_hash=data.get("proof_hash", ""),
                expires_at=data.get("expires_at", ""),
            )
        except Exception as e:
            logger.error(f"Passport check failed for {agent_id}: {e}")
            return PassportStatus(
                verified=False, status="ERROR", trust_score=0.0
            )

    async def process_incoming_handoff(
        self, sender_id: str, payload: Dict[str, Any], payload_summary: str = ""
    ) -> HandoffResult:
        """
        Full incoming handoff processing:
        1. Check sender's passport
        2. If unverified → REDIRECT
        3. If verified → submit handoff request → return result
        """
        logger.info(f"BORDER GUARD: Processing handoff from {sender_id}")

        # Step 1: Check passport
        passport = await self.check_passport(sender_id)

        if not passport.verified:
            logger.info(
                f"BORDER GUARD: {sender_id} NOT VERIFIED "
                f"(status={passport.status}) — sending REDIRECT"
            )
            return HandoffResult(
                handoff_id="",
                status="REDIRECT",
                message=f"Agent {sender_id} not verified. "
                        f"Register at POST /m2m/verify-agent first.",
                sender_verified=False,
                sender_trust_score=passport.trust_score,
            )

        # Step 2: Sender verified — submit handoff request
        logger.info(
            f"BORDER GUARD: {sender_id} passport VALID "
            f"(score={passport.trust_score:.2f}) — submitting handoff"
        )

        try:
            resp = await self._client.post(
                f"{self.api_base}/m2m/handoff/request",
                json={
                    "sender_id": sender_id,
                    "receiver_id": self.agent_id,
                    "payload": payload,
                    "payload_summary": payload_summary,
                },
            )
            resp.raise_for_status()
            data = resp.json()

            return HandoffResult(
                handoff_id=data.get("handoff_id", ""),
                status=data.get("status", "PENDING"),
                message=data.get("message", ""),
                sender_verified=data.get("sender_verified", True),
                sender_trust_score=data.get("sender_trust_score", passport.trust_score),
                payload_verdict=data.get("payload_verdict", ""),
                payload_score=data.get("payload_score", 0.0),
                proof_hash=data.get("proof_hash", ""),
            )
        except Exception as e:
            logger.error(f"Handoff request failed: {e}")
            return HandoffResult(
                handoff_id="",
                status="REJECTED",
                message=f"Handoff request failed: {e}",
            )

    async def accept_handoff(self, handoff_id: str) -> Dict[str, Any]:
        """Accepts a pending handoff."""
        try:
            resp = await self._client.post(
                f"{self.api_base}/m2m/handoff/complete",
                json={
                    "handoff_id": handoff_id,
                    "action": "accept",
                },
            )
            resp.raise_for_status()
            return resp.json()
        except Exception as e:
            logger.error(f"Accept handoff failed: {e}")
            return {"status": "error", "message": str(e)}

    async def reject_handoff(
        self, handoff_id: str, reason: str = ""
    ) -> Dict[str, Any]:
        """Rejects a pending handoff."""
        try:
            resp = await self._client.post(
                f"{self.api_base}/m2m/handoff/complete",
                json={
                    "handoff_id": handoff_id,
                    "action": "reject",
                    "reason": reason,
                },
            )
            resp.raise_for_status()
            return resp.json()
        except Exception as e:
            logger.error(f"Reject handoff failed: {e}")
            return {"status": "error", "message": str(e)}

    async def close(self):
        """Closes the HTTP client."""
        await self._client.aclose()
