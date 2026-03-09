"""
LastBastionClient — async API client for The Last Bastion.

Three usage patterns:
1. Company registers on the website (human-approved) → gets API key
2. Agent uses this client to get verified → receives Agent Passport
3. Agent uses passport to submit payloads for fraud verification

Usage:
    from lastbastion import LastBastionClient
    from lastbastion.crypto import generate_keypair

    # Generate Ed25519 keypair (or bring your own)
    public_key, private_key = generate_keypair()

    async with LastBastionClient(base_url="https://api.thelastbastion.io") as client:
        # Full flow: register (challenge-response) → verify → passport
        passport = await client.register_and_verify(
            agent_id="my-agent-001",
            public_key=public_key,
            private_key=private_key,
            agent_url="http://my-agent:9000",
        )

        # Submit data for fraud verification
        result = await client.submit_payload({"invoice": {...}})

        # Verify another agent's passport
        check = await client.verify_passport(other_agent_jwt)
"""

import httpx
from typing import Any, Dict, List, Optional, Tuple

from lastbastion.exceptions import (
    AuthenticationError,
    NotFoundError,
    RateLimitError,
    LastBastionError,
    ValidationError,
    PassportError,
)
from lastbastion.passport import AgentPassport


class LastBastionClient:
    """Async client for The Last Bastion Agent Security Platform."""

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

    def _update_api_key(self, key_id: str, secret: str):
        """Update the client's API key after registration."""
        self._key_id = key_id
        self._key_secret = secret
        # Force client recreation with new headers
        if self._client and not self._client.is_closed:
            import asyncio
            try:
                loop = asyncio.get_running_loop()
                loop.create_task(self._client.aclose())
            except RuntimeError:
                pass
        self._client = None

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
            raise LastBastionError(
                f"API error {resp.status_code}", status_code=resp.status_code
            )
        return resp.json()

    @staticmethod
    def generate_keypair() -> Tuple[str, str]:
        """
        Generate an Ed25519 keypair for agent identity.

        Returns (public_key_hex, private_key_hex).
        The public key is submitted during registration.
        The private key signs the cryptographic challenge to prove identity.
        Keep the private key secret.
        """
        from lastbastion.crypto import generate_keypair
        return generate_keypair()

    # -------------------------------------------------------------------
    # M2M Core Methods
    # -------------------------------------------------------------------

    async def register_agent(
        self,
        agent_id: str,
        public_key: str = "",
        role: str = "DATA_PROVIDER",
        capabilities: List[str] = None,
        display_name: str = "",
    ) -> dict:
        """
        Register an agent on the platform.

        The server uses challenge-response by default:
        - Returns a challenge (nonce) that must be signed with the agent's
          Ed25519 private key
        - Call complete_challenge() with the signature to finish registration

        If the server has REQUIRE_CHALLENGE=false, registration completes
        immediately and returns an API key.
        """
        client = await self._get_client()
        resp = await client.post("/m2m/register", json={
            "agent_id": agent_id,
            "public_key": public_key or f"ed25519_pub_{agent_id}",
            "role": role,
            "capabilities": capabilities or [],
            "display_name": display_name or agent_id,
        })
        return self._handle_response(resp)

    async def complete_challenge(
        self,
        challenge_id: str,
        signature: str,
    ) -> dict:
        """
        Complete challenge-response registration by submitting the signed nonce.

        After calling register_agent(), the server returns a challenge_id and nonce.
        Sign the nonce with your Ed25519 private key and submit the signature here.

        On success, returns the API key and initial trust score.
        The client automatically updates its API key for subsequent requests.

        Args:
            challenge_id: The challenge_id from register_agent() response
            signature: Hex-encoded Ed25519 signature of the nonce
        """
        client = await self._get_client()
        resp = await client.post("/m2m/register/verify", json={
            "challenge_id": challenge_id,
            "signature": signature,
        })
        result = self._handle_response(resp)

        # Auto-update client with the new API key
        api_key_data = result.get("api_key", {})
        if api_key_data.get("key_id") and api_key_data.get("secret"):
            self._update_api_key(api_key_data["key_id"], api_key_data["secret"])

        return result

    async def register_with_keypair(
        self,
        agent_id: str,
        public_key: str,
        private_key: str,
        role: str = "DATA_PROVIDER",
        capabilities: List[str] = None,
        display_name: str = "",
    ) -> dict:
        """
        Register an agent with automatic challenge-response signing.

        This handles the full registration flow:
        1. POST /m2m/register → get challenge (nonce)
        2. Sign nonce with Ed25519 private key
        3. POST /m2m/register/verify → complete registration
        4. Auto-update client with new API key

        Args:
            agent_id: Unique agent identifier
            public_key: Ed25519 public key (hex)
            private_key: Ed25519 private key (hex) — used to sign the challenge
            role: Agent role (DATA_PROVIDER, DATA_CONSUMER, VERIFIER, BROKER)
            capabilities: List of agent capabilities
            display_name: Human-readable name

        Returns:
            Registration result with API key, trust score, and next steps
        """
        from lastbastion.crypto import sign_bytes

        # Step 1: Register — get challenge
        reg = await self.register_agent(
            agent_id=agent_id,
            public_key=public_key,
            role=role,
            capabilities=capabilities,
            display_name=display_name,
        )

        # If server returned a challenge (default mode), sign it
        if reg.get("status") == "CHALLENGE_ISSUED":
            nonce = reg["nonce"]
            challenge_id = reg["challenge_id"]

            # Sign the nonce with our private key
            signature = sign_bytes(nonce.encode(), private_key)

            # Complete the challenge
            result = await self.complete_challenge(challenge_id, signature)
            return result

        # Legacy mode (REQUIRE_CHALLENGE=false) — already registered
        api_key_data = reg.get("api_key", {})
        if api_key_data.get("key_id") and api_key_data.get("secret"):
            self._update_api_key(api_key_data["key_id"], api_key_data["secret"])

        return reg

    async def verify_agent(
        self,
        agent_id: str,
        agent_url: str = "",
        capabilities: List[str] = None,
    ) -> dict:
        """
        Submit an agent for trust verification (10-check pipeline).

        The agent will be subjected to:
        - Ed25519 challenge-response (must sign a nonce with private key)
        - Runtime fingerprint verification (clone detection)
        - Source IP cross-check
        - Behavioral analysis, anti-Sybil, payload inspection

        Returns a dict with trust_score, trust_level, verdict, and per-check breakdown.
        """
        client = await self._get_client()
        resp = await client.post(f"/m2m/dashboard/agents/{agent_id}/verify")
        return self._handle_response(resp)

    async def get_trust_status(self, agent_id: str) -> dict:
        """Get the current trust status and full profile for an agent."""
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
        resp = await client.post("/m2m/handoff/request", json={
            "sender_id": sender_id,
            "receiver_id": receiver_id,
            "payload": payload,
        })
        return self._handle_response(resp)

    # -------------------------------------------------------------------
    # Sandbox Methods
    # -------------------------------------------------------------------

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

    # -------------------------------------------------------------------
    # Passport Methods
    # -------------------------------------------------------------------

    async def issue_passport(
        self,
        agent_id: str,
        agent_name: str = "",
        public_key: str = "",
        company_name: str = "",
        company_domain: str = "",
        agent_card_url: str = "",
        geo_ip: str = "",
        geo_country: str = "",
        runtime_fingerprint: str = "",
        ip_allowlist: List[str] = None,
    ) -> dict:
        """
        Request a signed Agent Passport. Agent must already be verified
        with trust level VERIFIED or higher.
        """
        client = await self._get_client()
        resp = await client.post("/m2m/passport/issue", json={
            "agent_id": agent_id,
            "agent_name": agent_name,
            "public_key": public_key,
            "company_name": company_name,
            "company_domain": company_domain,
            "agent_card_url": agent_card_url,
            "geo_ip": geo_ip,
            "geo_country": geo_country,
            "runtime_fingerprint": runtime_fingerprint,
            "ip_allowlist": ip_allowlist or [],
        })
        return self._handle_response(resp)

    async def verify_passport(self, jwt_token: str) -> dict:
        """Verify a passport JWT against The Last Bastion server."""
        client = await self._get_client()
        resp = await client.post("/m2m/passport/verify", json={
            "jwt_token": jwt_token,
        })
        return self._handle_response(resp)

    async def get_passport(self, agent_id: str) -> dict:
        """Get the latest passport for an agent."""
        client = await self._get_client()
        resp = await client.get(f"/m2m/passport/{agent_id}")
        return self._handle_response(resp)

    async def renew_passport(self, agent_id: str) -> dict:
        """Re-verify and issue a fresh passport for an agent."""
        client = await self._get_client()
        resp = await client.post("/m2m/passport/renew", json={
            "agent_id": agent_id,
        })
        return self._handle_response(resp)

    async def sync_passport_budget(
        self, passport_id: str, interactions_used: int
    ) -> dict:
        """Sync consumed budget with server. Returns authoritative remaining."""
        client = await self._get_client()
        resp = await client.post("/m2m/passport/budget/sync", json={
            "passport_id": passport_id,
            "interactions_used": interactions_used,
        })
        return self._handle_response(resp)

    async def get_passport_budget(self, passport_id: str) -> dict:
        """Check budget status for a passport."""
        client = await self._get_client()
        resp = await client.get(f"/m2m/passport/{passport_id}/budget")
        return self._handle_response(resp)

    async def report_budget_strike(
        self, passport_id: str, strikes: int, agent_id: str = ""
    ) -> dict:
        """Report a post-exhaustion strike to the server."""
        client = await self._get_client()
        resp = await client.post("/m2m/passport/budget/strike", json={
            "passport_id": passport_id,
            "strikes": strikes,
            "agent_id": agent_id,
        })
        return self._handle_response(resp)

    async def file_appeal(
        self, agent_id: str, reason: str = "", evidence: str = ""
    ) -> dict:
        """File an appeal against escalation lockout."""
        client = await self._get_client()
        resp = await client.post("/m2m/appeal", json={
            "agent_id": agent_id,
            "reason": reason,
            "evidence": evidence,
        })
        return self._handle_response(resp)

    async def get_appeal_status(self, appeal_id: str) -> dict:
        """Check the status of a filed appeal."""
        client = await self._get_client()
        resp = await client.get(f"/m2m/appeal/{appeal_id}")
        return self._handle_response(resp)

    # -------------------------------------------------------------------
    # Payload Verification Convenience Methods
    # -------------------------------------------------------------------

    async def verify_payload(
        self,
        data: Dict[str, Any],
        format: str = "json",
        source_agent_id: str = "",
        poll_interval: float = 1.0,
        max_wait: float = 30.0,
    ) -> dict:
        """
        Submit data for verification and wait for the result.

        Convenience wrapper around submit_payload() that returns the
        verdict immediately (refinery is synchronous).

        Args:
            data: The payload data to verify
            format: Data format hint (json, csv, pdf)
            source_agent_id: Optional agent ID for provenance
            poll_interval: Unused (kept for API compat)
            max_wait: Unused (kept for API compat)

        Returns:
            Dict with verdict, score, proof_hash, submission_id
        """
        return await self.submit_payload(
            payload=data,
            context={"format": format},
            source_agent_id=source_agent_id,
        )

    async def get_verification_status(self, submission_id: str) -> dict:
        """
        Check the verification status for a submission.

        Args:
            submission_id: The submission ID returned from submit_payload()

        Returns:
            Dict with verdict, score, and proof details
        """
        client = await self._get_client()
        resp = await client.get(f"/refinery/status/{submission_id}")
        return self._handle_response(resp)

    async def get_report_url(self, submission_id: str) -> str:
        """
        Get the verification report URL for a submission.

        Args:
            submission_id: The submission ID

        Returns:
            URL string for the verification report
        """
        return f"{self.base_url}/refinery/report/{submission_id}"

    async def register_and_verify(
        self,
        agent_id: str,
        public_key: str = "",
        private_key: str = "",
        agent_url: str = "",
        agent_name: str = "",
        role: str = "DATA_PROVIDER",
        capabilities: List[str] = None,
        company_name: str = "",
        company_domain: str = "",
    ) -> dict:
        """
        Full flow: register → sign challenge → verify → issue passport.

        Handles the cryptographic challenge-response automatically if a
        private_key is provided. If no keypair is provided, generates one.

        Args:
            agent_id: Unique agent identifier
            public_key: Ed25519 public key (hex). Generated if empty.
            private_key: Ed25519 private key (hex). Generated if empty.
            agent_url: Your A2A endpoint URL
            agent_name: Human-readable name
            role: Agent role
            capabilities: List of capabilities
            company_name: Organization name
            company_domain: Organization domain

        Returns:
            Passport response with jwt_token, trust_score, proof_hash

        Raises:
            PassportError: If verification doesn't reach sufficient trust
        """
        # Generate keypair if not provided
        if not public_key or not private_key:
            from lastbastion.crypto import generate_keypair
            public_key, private_key = generate_keypair()

        # Step 1: Register with automatic challenge signing
        reg = await self.register_with_keypair(
            agent_id=agent_id,
            public_key=public_key,
            private_key=private_key,
            role=role,
            capabilities=capabilities,
            display_name=agent_name or agent_id,
        )

        # Step 2: Verify (10-check pipeline)
        verification = await self.verify_agent(
            agent_id=agent_id,
            agent_url=agent_url,
            capabilities=capabilities,
        )

        trust_level = verification.get("trust_level", "NONE")
        if trust_level in ("NONE", "NEW"):
            raise PassportError(
                f"Agent verification did not reach VERIFIED trust (got {trust_level}). "
                "Passport requires at minimum BASIC trust level.",
                detail=verification,
            )

        # Step 3: Issue passport
        passport = await self.issue_passport(
            agent_id=agent_id,
            agent_name=agent_name,
            public_key=public_key,
            company_name=company_name,
            company_domain=company_domain,
        )

        return passport
