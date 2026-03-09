"""
Last Bastion Gateway — border police for your agent ecosystem.

Checks incoming agents before allowing entry to your system.
Works offline (JWT verification only) or online (checks with The Last Bastion server).

Three integration patterns:

    # 1. FastAPI/Starlette middleware
    app.add_middleware(gateway.middleware())

    # 2. Decorator
    @gateway.require_passport(min_trust="VERIFIED")
    async def my_endpoint(request): ...

    # 3. Manual check
    decision = await gateway.check_agent(jwt_token, request)
    if not decision.allowed:
        raise HTTPException(403, decision.reason)
"""

import time
import functools
from typing import Any, Callable, Dict, Optional

from lastbastion.passport import AgentPassport, PassportVerifier
from lastbastion.models import GatewayDecision
from lastbastion.exceptions import GatewayDeniedError


TRUST_LEVELS_ORDERED = ["NONE", "NEW", "BASIC", "VERIFIED", "ESTABLISHED", "GOLD"]


class LastBastionGateway:
    """
    Border police for your agent endpoints. Verifies Agent Passports
    before allowing entry.
    """

    BUDGET_BY_TRUST = {
        "NONE": 0, "NEW": 25, "BASIC": 50,
        "VERIFIED": 100, "ESTABLISHED": 200, "GOLD": 500,
    }

    def __init__(
        self,
        api_key: str = "",
        base_url: str = "http://localhost:8000",
        issuer_public_key: str = "",
        min_trust_level: str = "BASIC",
        require_passport: bool = True,
        verify_online: bool = True,
        cache_ttl_seconds: int = 300,
        budget_sync_interval: int = 60,
    ):
        self.api_key = api_key
        self.base_url = base_url
        self.issuer_public_key = issuer_public_key
        self.min_trust_level = min_trust_level
        self._require_passport = require_passport
        self.verify_online = verify_online
        self.cache_ttl = cache_ttl_seconds
        self.budget_sync_interval = budget_sync_interval

        self._verifier = PassportVerifier(issuer_public_key=issuer_public_key)
        self._cache: Dict[str, Dict[str, Any]] = {}  # jwt_hash -> {decision, expires}
        self._budget_tracker: Dict[str, Dict[str, Any]] = {}  # passport_id -> budget info

    def _trust_sufficient(self, level: str) -> bool:
        """Check if a trust level meets the minimum threshold."""
        try:
            got = TRUST_LEVELS_ORDERED.index(level)
            need = TRUST_LEVELS_ORDERED.index(self.min_trust_level)
            return got >= need
        except ValueError:
            return False

    def _get_cached(self, jwt_token: str) -> Optional[GatewayDecision]:
        """Check cache for a previously verified passport."""
        import hashlib
        key = hashlib.sha256(jwt_token.encode()).hexdigest()[:16]
        entry = self._cache.get(key)
        if entry and entry["expires"] > time.time():
            decision = entry["decision"]
            return GatewayDecision(
                allowed=decision.allowed,
                agent_id=decision.agent_id,
                trust_score=decision.trust_score,
                trust_level=decision.trust_level,
                reason=decision.reason,
                cached=True,
            )
        elif entry:
            del self._cache[key]
        return None

    def _set_cached(self, jwt_token: str, decision: GatewayDecision):
        """Cache a verification decision."""
        import hashlib
        key = hashlib.sha256(jwt_token.encode()).hexdigest()[:16]
        # Evict old entries if cache grows too large
        if len(self._cache) > 1000:
            now = time.time()
            expired = [k for k, v in self._cache.items() if v["expires"] < now]
            for k in expired:
                del self._cache[k]
        self._cache[key] = {
            "decision": decision,
            "expires": time.time() + self.cache_ttl,
        }

    async def check_agent(
        self,
        jwt_token: str,
        request: Any = None,
    ) -> GatewayDecision:
        """
        Verify an agent's passport and decide whether to allow entry.

        Args:
            jwt_token: The passport JWT from the request
            request: Optional request object for IP checking

        Returns:
            GatewayDecision with allowed/denied and reason
        """
        if not jwt_token:
            if not self._require_passport:
                return GatewayDecision(
                    allowed=True,
                    reason="passport_not_required",
                )
            return GatewayDecision(
                allowed=False,
                reason="no_passport_provided",
            )

        # Check cache
        cached = self._get_cached(jwt_token)
        if cached is not None:
            return cached

        # Step 1: Offline verification (JWT signature + integrity + expiry)
        try:
            if self.issuer_public_key:
                passport = AgentPassport.from_jwt(jwt_token, self.issuer_public_key)
            else:
                # Without issuer key, do online verification only
                passport = None
        except ValueError as e:
            decision = GatewayDecision(
                allowed=False,
                reason=f"jwt_invalid: {e}",
            )
            self._set_cached(jwt_token, decision)
            return decision

        if passport:
            # Check expiry
            if passport.is_expired():
                decision = GatewayDecision(
                    allowed=False,
                    agent_id=passport.agent_id,
                    reason="passport_expired",
                )
                self._set_cached(jwt_token, decision)
                return decision

            # Check integrity
            if not passport.verify_integrity():
                decision = GatewayDecision(
                    allowed=False,
                    agent_id=passport.agent_id,
                    reason="integrity_check_failed",
                )
                self._set_cached(jwt_token, decision)
                return decision

            # Check trust level
            if not self._trust_sufficient(passport.trust_level):
                decision = GatewayDecision(
                    allowed=False,
                    agent_id=passport.agent_id,
                    trust_score=passport.trust_score,
                    trust_level=passport.trust_level,
                    reason=f"insufficient_trust: {passport.trust_level} < {self.min_trust_level}",
                )
                self._set_cached(jwt_token, decision)
                return decision

            # Check verdict
            if passport.verdict == "MALICIOUS":
                decision = GatewayDecision(
                    allowed=False,
                    agent_id=passport.agent_id,
                    reason="malicious_verdict",
                )
                self._set_cached(jwt_token, decision)
                return decision

        # Step 2: Online verification (optional — checks revocation, live scores)
        if self.verify_online and self.api_key:
            try:
                from lastbastion import LastBastionClient
                async with LastBastionClient(
                    api_key=self.api_key, base_url=self.base_url
                ) as client:
                    online_result = await client.verify_passport(jwt_token)
                    if not online_result.get("valid", False):
                        decision = GatewayDecision(
                            allowed=False,
                            agent_id=online_result.get("agent_id", ""),
                            reason=f"online_verification_failed: {online_result.get('reasons', [])}",
                        )
                        self._set_cached(jwt_token, decision)
                        return decision
            except Exception:
                # Online check failed — fall through to offline result
                if passport is None:
                    decision = GatewayDecision(
                        allowed=False,
                        reason="online_verification_unavailable_and_no_issuer_key",
                    )
                    return decision

        # All checks passed — now check budget
        agent_id = passport.agent_id if passport else "unknown"
        trust_score = passport.trust_score if passport else 0.0
        trust_level = passport.trust_level if passport else "UNKNOWN"

        if passport:
            self._init_budget(passport)
            budget_decision = self._check_budget(passport)
            if budget_decision is not None:
                # Budget exhausted — do NOT cache (agent might re-verify)
                return budget_decision
            self._decrement_budget(passport)

        budget_info = self._get_budget_info(passport.passport_id) if passport else None

        decision = GatewayDecision(
            allowed=True,
            agent_id=agent_id,
            trust_score=trust_score,
            trust_level=trust_level,
            reason="verified",
            budget_remaining=budget_info["remaining"] if budget_info else -1,
            budget_max=budget_info["max"] if budget_info else 100,
            budget_exhausted=False,
        )
        self._set_cached(jwt_token, decision)
        return decision

    def _init_budget(self, passport: AgentPassport):
        """Initialize budget tracker from passport if first seen."""
        pid = passport.passport_id
        if pid not in self._budget_tracker:
            self._budget_tracker[pid] = {
                "remaining": passport.interaction_budget,
                "max": passport.interaction_budget_max,
                "last_sync": time.time(),
                "agent_id": passport.agent_id,
                "strikes": 0,
                "escalation_tier": 0,
            }

    @staticmethod
    def _tier_for_strikes(strikes: int) -> Optional[int]:
        """Return the tier boundary just crossed, or None."""
        if strikes == 30:
            return 3
        if strikes == 15:
            return 2
        if strikes == 5:
            return 1
        return None

    def _check_budget(self, passport: AgentPassport) -> Optional[GatewayDecision]:
        """Return a denial decision if budget is exhausted, else None."""
        pid = passport.passport_id
        info = self._budget_tracker.get(pid)
        if info and info["remaining"] <= 0:
            # Increment strike counter
            info["strikes"] = info.get("strikes", 0) + 1
            strikes = info["strikes"]

            # Check tier boundaries
            tier = self._tier_for_strikes(strikes)
            if tier is not None:
                info["escalation_tier"] = tier
                # Fire async report to server (best-effort)
                try:
                    import asyncio
                    asyncio.ensure_future(
                        self._report_strike_to_server(pid, strikes, passport.agent_id)
                    )
                except RuntimeError:
                    pass  # No event loop — local tracking only

            return GatewayDecision(
                allowed=False,
                agent_id=passport.agent_id,
                trust_score=passport.trust_score,
                trust_level=passport.trust_level,
                reason="budget_exhausted",
                budget_remaining=0,
                budget_max=info["max"],
                budget_exhausted=True,
                post_exhaustion_strikes=strikes,
                escalation_tier=info.get("escalation_tier", 0),
            )
        return None

    async def _report_strike_to_server(self, passport_id: str, strikes: int, agent_id: str):
        """Report a strike to the server at tier boundaries."""
        if not self.api_key:
            return
        try:
            from lastbastion import LastBastionClient
            async with LastBastionClient(
                api_key=self.api_key, base_url=self.base_url
            ) as client:
                await client.report_budget_strike(passport_id, strikes, agent_id)
        except Exception:
            pass  # Strike report failure is non-fatal

    def _decrement_budget(self, passport: AgentPassport):
        """Decrease budget by 1 and schedule sync if interval elapsed."""
        pid = passport.passport_id
        info = self._budget_tracker.get(pid)
        if info:
            info["remaining"] = max(0, info["remaining"] - 1)

    def _get_budget_info(self, passport_id: str) -> Optional[Dict[str, Any]]:
        """Get current budget info for a passport."""
        return self._budget_tracker.get(passport_id)

    async def sync_budget(self, passport_id: str):
        """Sync budget with server via POST /passport/budget/sync."""
        info = self._budget_tracker.get(passport_id)
        if not info or not self.api_key:
            return
        try:
            from lastbastion import LastBastionClient
            async with LastBastionClient(
                api_key=self.api_key, base_url=self.base_url
            ) as client:
                result = await client.sync_passport_budget(
                    passport_id=passport_id,
                    interactions_used=info["max"] - info["remaining"],
                )
                if "remaining" in result:
                    info["remaining"] = result["remaining"]
                    info["last_sync"] = time.time()
        except Exception:
            pass  # Sync failure is non-fatal — local tracking continues

    def refresh_budget(self, passport_id: str, new_budget: int):
        """Called after re-verification to reset budget."""
        info = self._budget_tracker.get(passport_id)
        if info:
            info["remaining"] = new_budget
            info["max"] = new_budget
            info["last_sync"] = time.time()
        else:
            self._budget_tracker[passport_id] = {
                "remaining": new_budget,
                "max": new_budget,
                "last_sync": time.time(),
                "agent_id": "",
            }

    def require_passport_decorator(
        self,
        min_trust: str = None,
    ) -> Callable:
        """
        Decorator for protecting individual endpoints.

        Usage:
            @gateway.require_passport_decorator(min_trust="VERIFIED")
            async def my_endpoint(request):
                agent = request.state.agent  # injected by decorator
        """
        required_trust = min_trust or self.min_trust_level

        def decorator(func):
            @functools.wraps(func)
            async def wrapper(request, *args, **kwargs):
                # Extract passport from headers
                jwt_token = _extract_passport_from_request(request)

                # Save original min_trust, apply override
                original = self.min_trust_level
                self.min_trust_level = required_trust
                try:
                    decision = await self.check_agent(jwt_token, request)
                finally:
                    self.min_trust_level = original

                if not decision.allowed:
                    from starlette.responses import JSONResponse
                    return JSONResponse(
                        status_code=403,
                        content={
                            "error": "access_denied",
                            "reason": decision.reason,
                            "agent_id": decision.agent_id,
                        },
                    )

                # Inject agent context into request
                request.state.agent = {
                    "agent_id": decision.agent_id,
                    "trust_score": decision.trust_score,
                    "trust_level": decision.trust_level,
                }
                return await func(request, *args, **kwargs)
            return wrapper
        return decorator

    def create_middleware(self):
        """
        Create a Starlette/FastAPI middleware class.

        Usage:
            app.add_middleware(gateway.create_middleware())
        """
        gateway = self

        from starlette.middleware.base import BaseHTTPMiddleware
        from starlette.responses import JSONResponse

        class LastBastionMiddleware(BaseHTTPMiddleware):
            async def dispatch(self, request, call_next):
                jwt_token = _extract_passport_from_request(request)
                decision = await gateway.check_agent(jwt_token, request)

                if not decision.allowed:
                    return JSONResponse(
                        status_code=403,
                        content={
                            "error": "access_denied",
                            "reason": decision.reason,
                            "agent_id": decision.agent_id,
                        },
                    )

                # Inject agent context
                request.state.agent = {
                    "agent_id": decision.agent_id,
                    "trust_score": decision.trust_score,
                    "trust_level": decision.trust_level,
                    "cached": decision.cached,
                }
                return await call_next(request)

        return LastBastionMiddleware


def _extract_passport_from_request(request) -> str:
    """Extract passport JWT from Authorization header or X-Agent-Passport header."""
    # Try Authorization: Bearer <jwt>
    auth = request.headers.get("authorization", "")
    if auth.startswith("Bearer "):
        return auth[7:]

    # Try X-Agent-Passport header
    passport = request.headers.get("x-agent-passport", "")
    if passport:
        return passport

    return ""
