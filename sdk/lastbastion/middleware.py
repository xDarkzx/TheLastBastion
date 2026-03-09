"""
Last Bastion Middleware — standalone FastAPI/Starlette middleware.

For simpler integration when you don't need the full Gateway object:

    from lastbastion.middleware import LastBastionMiddleware

    app.add_middleware(
        LastBastionMiddleware,
        issuer_public_key="abc123...",
        min_trust_level="BASIC",
    )
"""

import time
import hashlib
from typing import Any, Dict, Optional

from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request
from starlette.responses import JSONResponse

from lastbastion.passport import AgentPassport, PassportVerifier
from lastbastion.gateway import _extract_passport_from_request, TRUST_LEVELS_ORDERED


class LastBastionMiddleware(BaseHTTPMiddleware):
    """
    Standalone middleware that checks Agent Passports on every request.

    Extracts passport from Authorization: Bearer <jwt> or X-Agent-Passport header.
    Verifies signature, integrity, expiry, and trust level.
    Injects agent context into request.state.agent.
    """

    BUDGET_BY_TRUST = {
        "NONE": 0, "NEW": 25, "BASIC": 50,
        "VERIFIED": 100, "ESTABLISHED": 200, "GOLD": 500,
    }

    def __init__(
        self,
        app,
        issuer_public_key: str = "",
        min_trust_level: str = "BASIC",
        require_passport: bool = True,
        exclude_paths: list = None,
        cache_ttl_seconds: int = 300,
    ):
        super().__init__(app)
        self.issuer_public_key = issuer_public_key
        self.min_trust_level = min_trust_level
        self.require_passport = require_passport
        self.exclude_paths = exclude_paths or ["/health", "/docs", "/openapi.json"]
        self.cache_ttl = cache_ttl_seconds
        self._verifier = PassportVerifier(issuer_public_key=issuer_public_key)
        self._cache: Dict[str, Dict[str, Any]] = {}
        self._budget_tracker: Dict[str, Dict[str, Any]] = {}  # passport_id -> budget info

    def _is_excluded(self, path: str) -> bool:
        return any(path.startswith(p) for p in self.exclude_paths)

    def _trust_sufficient(self, level: str) -> bool:
        try:
            got = TRUST_LEVELS_ORDERED.index(level)
            need = TRUST_LEVELS_ORDERED.index(self.min_trust_level)
            return got >= need
        except ValueError:
            return False

    async def dispatch(self, request: Request, call_next):
        # Skip excluded paths
        if self._is_excluded(request.url.path):
            return await call_next(request)

        jwt_token = _extract_passport_from_request(request)

        if not jwt_token:
            if not self.require_passport:
                request.state.agent = {"agent_id": "anonymous", "trust_level": "NONE"}
                return await call_next(request)
            return JSONResponse(
                status_code=401,
                content={"error": "passport_required", "message": "Agent Passport required"},
            )

        # Check cache
        cache_key = hashlib.sha256(jwt_token.encode()).hexdigest()[:16]
        cached = self._cache.get(cache_key)
        if cached and cached["expires"] > time.time():
            request.state.agent = cached["agent_context"]
            return await call_next(request)

        # Verify passport
        try:
            if self.issuer_public_key:
                passport = AgentPassport.from_jwt(jwt_token, self.issuer_public_key)
            else:
                # Without issuer key, attempt to decode without verification
                import json
                from lastbastion.crypto import _b64url_decode
                parts = jwt_token.split(".")
                if len(parts) != 3:
                    raise ValueError("Invalid JWT format")
                claims = json.loads(_b64url_decode(parts[1]))
                passport = AgentPassport(**claims)
        except (ValueError, Exception) as e:
            return JSONResponse(
                status_code=401,
                content={"error": "invalid_passport", "message": str(e)},
            )

        # Check expiry
        if passport.is_expired():
            return JSONResponse(
                status_code=401,
                content={"error": "passport_expired", "agent_id": passport.agent_id},
            )

        # Check integrity (only if we have issuer key for full verification)
        if self.issuer_public_key and not passport.verify_integrity():
            return JSONResponse(
                status_code=401,
                content={"error": "integrity_failed", "agent_id": passport.agent_id},
            )

        # Check trust level
        if not self._trust_sufficient(passport.trust_level):
            return JSONResponse(
                status_code=403,
                content={
                    "error": "insufficient_trust",
                    "agent_id": passport.agent_id,
                    "trust_level": passport.trust_level,
                    "required": self.min_trust_level,
                },
            )

        # Check verdict
        if passport.verdict == "MALICIOUS":
            return JSONResponse(
                status_code=403,
                content={"error": "malicious_agent", "agent_id": passport.agent_id},
            )

        # Check interaction budget
        pid = passport.passport_id
        if pid not in self._budget_tracker:
            self._budget_tracker[pid] = {
                "remaining": passport.interaction_budget,
                "max": passport.interaction_budget_max,
                "agent_id": passport.agent_id,
                "strikes": 0,
                "escalation_tier": 0,
            }
        budget_info = self._budget_tracker[pid]
        if budget_info["remaining"] <= 0:
            # Increment strike counter
            budget_info["strikes"] = budget_info.get("strikes", 0) + 1
            strikes = budget_info["strikes"]

            # Check tier boundaries
            tier = None
            if strikes == 5:
                tier = 1
            elif strikes == 15:
                tier = 2
            elif strikes == 30:
                tier = 3
            if tier is not None:
                budget_info["escalation_tier"] = tier

            escalation_tier = budget_info.get("escalation_tier", 0)
            content = {
                "error": "budget_exhausted",
                "agent_id": passport.agent_id,
                "passport_id": pid,
                "renew_url": "/m2m/passport/renew",
                "post_exhaustion_strikes": strikes,
                "escalation_tier": escalation_tier,
                "message": f"Budget exhausted. Strike {strikes}/30."
                           + (f" File an appeal at /m2m/appeal." if strikes >= 5 else " Re-verify with The Last Bastion."),
            }
            if strikes >= 5:
                content["appeal_url"] = "/m2m/appeal"

            return JSONResponse(status_code=429, content=content)
        budget_info["remaining"] = max(0, budget_info["remaining"] - 1)

        # All checks passed — inject context
        agent_context = {
            "agent_id": passport.agent_id,
            "agent_name": passport.agent_name,
            "trust_score": passport.trust_score,
            "trust_level": passport.trust_level,
            "verdict": passport.verdict,
            "passport_id": passport.passport_id,
            "budget_remaining": budget_info["remaining"],
            "budget_max": budget_info["max"],
        }
        request.state.agent = agent_context

        # Cache
        self._cache[cache_key] = {
            "agent_context": agent_context,
            "expires": time.time() + self.cache_ttl,
        }
        # Evict expired entries
        if len(self._cache) > 500:
            now = time.time()
            expired = [k for k, v in self._cache.items() if v["expires"] < now]
            for k in expired:
                del self._cache[k]

        return await call_next(request)
