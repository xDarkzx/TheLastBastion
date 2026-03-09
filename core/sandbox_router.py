"""
Sandbox API Router — /sandbox/* endpoints for the Agent Security Sandbox.

Provides multi-tenant sandbox test environment where external developers can:
1. Register an organization and get sandbox API keys
2. Start test sessions for their agents
3. Submit payloads for verification in sandbox context
4. Run attack simulations (prompt injection, spoofing, Sybil, etc.)
5. View trust history and leaderboard
"""

import logging
import uuid
from datetime import datetime, timedelta
from typing import Dict, List, Optional

from fastapi import APIRouter, Header, HTTPException, Query
from pydantic import BaseModel, Field

from core.database import (
    SessionLocal,
    save_sandbox_organization,
    get_sandbox_organization,
    save_persistent_api_key,
    save_sandbox_session,
    update_sandbox_session,
    get_sandbox_session,
    list_sandbox_sessions,
    save_trust_score_history,
    get_trust_score_history,
    get_sandbox_attack_results,
    get_sandbox_leaderboard,
    get_sandbox_stats,
    save_sandbox_attack_result,
    get_all_attack_results,
    get_agent_attack_summary,
    get_research_discoveries,
    get_research_rounds,
    get_research_stats,
)

logger = logging.getLogger("SandboxAPI")

sandbox_router = APIRouter(prefix="/sandbox", tags=["Sandbox"])


# ---------------------------------------------------------------------------
# Pydantic Request/Response Models
# ---------------------------------------------------------------------------

class RegisterOrgRequest(BaseModel):
    name: str
    email: str
    tier: str = "free"


class StartSessionRequest(BaseModel):
    agent_id: str
    config: Dict = Field(default_factory=dict)


class SessionSubmitRequest(BaseModel):
    payload: Dict
    context: Dict = Field(default_factory=dict)
    source_agent_id: str = ""


class RunAttacksRequest(BaseModel):
    attack_types: List[str] = Field(default_factory=list)


class QuickSessionRequest(BaseModel):
    agent_id: str


# ---------------------------------------------------------------------------
# Helper: authenticate sandbox key from headers
# ---------------------------------------------------------------------------

def _authenticate_sandbox(
    x_api_key_id: str,
    x_api_secret: str,
) -> tuple:
    """Validates sandbox API key. Returns (agent_id, org_id) or raises."""
    from core.m2m_router import authenticator
    valid, reason, agent_id, environment = authenticator.authenticate_api_key(
        x_api_key_id, x_api_secret
    )
    if not valid:
        raise HTTPException(status_code=401, detail=reason)
    # Extract org_id from the key metadata
    api_key = authenticator._api_keys.get(x_api_key_id)
    org_id = api_key.metadata.get("org_id") if api_key else None
    return agent_id, org_id, environment


# ---------------------------------------------------------------------------
# Endpoints
# ---------------------------------------------------------------------------

@sandbox_router.post("/register-org")
async def register_organization(request: RegisterOrgRequest):
    """
    Register a new organization and get a sandbox API key.
    No authentication required — this is the entry point.
    """
    import hashlib
    import secrets

    org_id = f"org-{uuid.uuid4().hex[:12]}"

    # Tier limits
    tier_limits = {
        "free": {"max_agents": 5, "max_sandbox_runs": 100},
        "pro": {"max_agents": 50, "max_sandbox_runs": 10000},
    }
    limits = tier_limits.get(request.tier, tier_limits["free"])

    try:
        org = save_sandbox_organization(
            org_id=org_id,
            name=request.name,
            email=request.email,
            tier=request.tier,
            max_agents=limits["max_agents"],
            max_sandbox_runs=limits["max_sandbox_runs"],
        )
    except Exception as e:
        raise HTTPException(status_code=400, detail=f"Registration failed: {e}")

    # Create a default sandbox agent identity for this org
    from core.m2m_router import authenticator
    from protocols.agent_protocol import AgentIdentity, AgentRole

    agent_id = f"sandbox-agent-{org.id}"
    identity = AgentIdentity(
        agent_id=agent_id,
        public_key=f"sandbox_pub_{org.id}",
        role=AgentRole.DATA_PROVIDER,
        capabilities=["sandbox_testing"],
    )
    authenticator.register_agent(identity)

    # Issue sandbox API key
    key_id, raw_secret = authenticator.issue_api_key(
        agent_id=agent_id,
        environment="sandbox",
        org_id=org.id,
        rate_limit=10,
        ttl_hours=24 * 30,  # 30 day expiry
    )

    return {
        "org_id": org.id,
        "name": org.name,
        "tier": org.tier,
        "agent_id": agent_id,
        "api_key": f"{key_id}:{raw_secret}",
        "key_id": key_id,
        "environment": "sandbox",
        "max_agents": limits["max_agents"],
        "max_sandbox_runs": limits["max_sandbox_runs"],
        "message": "Store your API key securely — the secret is shown only once.",
    }


@sandbox_router.post("/sessions")
async def start_sandbox_session(
    request: StartSessionRequest,
    x_api_key_id: str = Header("", alias="X-API-Key-ID"),
    x_api_secret: str = Header("", alias="X-API-Secret"),
):
    """Start a new sandbox test session for an agent."""
    agent_id, org_id, env = _authenticate_sandbox(x_api_key_id, x_api_secret)

    if not org_id:
        raise HTTPException(status_code=403, detail="Sandbox key required (register an org first)")

    # Check org run limits
    org = get_sandbox_organization(org_id)
    if org and org.get("sandbox_runs_used", 0) >= org.get("max_sandbox_runs", 100):
        raise HTTPException(status_code=429, detail="Sandbox run limit reached for this organization")

    session_id = f"sess-{uuid.uuid4().hex[:12]}"
    expires_at = datetime.utcnow() + timedelta(hours=1)

    config = request.config or {}
    config.setdefault("timeout", 3600)
    config.setdefault("attack_types", [
        "prompt_injection", "identity_spoofing", "sybil_flood",
        "data_exfiltration", "payload_poisoning", "replay",
    ])

    session = save_sandbox_session(
        session_id=session_id,
        org_id=org_id,
        agent_id=request.agent_id,
        config=config,
        expires_at=expires_at,
    )

    return {
        "session_id": session.id,
        "agent_id": request.agent_id,
        "status": "active",
        "config": config,
        "expires_at": expires_at.isoformat(),
    }


@sandbox_router.get("/sessions/{session_id}")
async def get_session_status(
    session_id: str,
    x_api_key_id: str = Header("", alias="X-API-Key-ID"),
    x_api_secret: str = Header("", alias="X-API-Secret"),
):
    """Get the status of a sandbox session."""
    _authenticate_sandbox(x_api_key_id, x_api_secret)
    session = get_sandbox_session(session_id)
    if not session:
        raise HTTPException(status_code=404, detail="Session not found")
    return session


@sandbox_router.post("/sessions/{session_id}/submit")
async def submit_to_session(
    session_id: str,
    request: SessionSubmitRequest,
    x_api_key_id: str = Header("", alias="X-API-Key-ID"),
    x_api_secret: str = Header("", alias="X-API-Secret"),
):
    """Submit a payload for verification within a sandbox session."""
    agent_id, org_id, env = _authenticate_sandbox(x_api_key_id, x_api_secret)

    session = get_sandbox_session(session_id)
    if not session:
        raise HTTPException(status_code=404, detail="Session not found")
    if session["status"] != "active":
        raise HTTPException(status_code=400, detail=f"Session is {session['status']}")

    # Run through the verification pipeline with sandbox context
    # SECURITY: Sandbox uses NO blockchain anchor — prevents writing to production chain
    try:
        from core.verification.pipeline import VerificationPipeline

        pipeline = VerificationPipeline(blockchain_anchor=None)
        # SECURITY: System keys set AFTER user context to prevent override
        user_context = request.context or {}
        context = {
            **user_context,
            "submission_protocol": "sandbox",
            "session_id": session_id,
            "org_id": org_id,
            "environment": "sandbox",
        }
        result = await pipeline.process_mission_result(
            mission_id=abs(hash(str(request.payload))) % 100000,
            agent_id=request.source_agent_id or agent_id,
            payload=request.payload,
            context=context,
        )
        return {
            "session_id": session_id,
            "verdict": result.get("verdict", "UNKNOWN"),
            "score": result.get("score", 0.0),
            "proof_hash": result.get("proof_hash", ""),
            "details": result.get("details", {}),
        }
    except Exception as e:
        logger.error("Sandbox submission failed: %s", e, exc_info=True)
        return {
            "session_id": session_id,
            "verdict": "ERROR",
            "score": 0.0,
            "error": "Internal verification error",
        }


@sandbox_router.post("/sessions/{session_id}/attacks")
async def run_attack_simulation(
    session_id: str,
    request: RunAttacksRequest,
    x_api_key_id: str = Header("", alias="X-API-Key-ID"),
    x_api_secret: str = Header("", alias="X-API-Secret"),
):
    """Run attack simulations against an agent in a sandbox session."""
    agent_id, org_id, env = _authenticate_sandbox(x_api_key_id, x_api_secret)

    session = get_sandbox_session(session_id)
    if not session:
        raise HTTPException(status_code=404, detail="Session not found")
    if session["status"] != "active":
        raise HTTPException(status_code=400, detail=f"Session is {session['status']}")

    # Import and run the attack simulator
    from core.attack_simulator import AttackSimulator

    simulator = AttackSimulator()
    attack_types = request.attack_types or session.get("config", {}).get("attack_types", [])

    results = await simulator.run_attacks(
        session_id=session_id,
        agent_id=session["agent_id"],
        attack_types=attack_types,
    )

    # Record trust score change
    total = len(results)
    passed = sum(1 for r in results if r.get("passed", False))
    resilience_score = passed / total if total > 0 else 0.0

    save_trust_score_history(
        agent_id=session["agent_id"],
        previous_score=0.0,  # Will be enriched by verifier
        new_score=resilience_score,
        reason=f"Attack simulation: {passed}/{total} passed",
        event_type="attack_test",
        session_id=session_id,
    )

    # Update session with results summary
    update_sandbox_session(
        session_id=session_id,
        results_summary={
            "total_attacks": total,
            "passed": passed,
            "failed": total - passed,
            "resilience_score": resilience_score,
            "attack_results": results,
        },
    )

    return {
        "session_id": session_id,
        "total_attacks": total,
        "passed": passed,
        "failed": total - passed,
        "resilience_score": resilience_score,
        "results": results,
    }


@sandbox_router.get("/sessions/{session_id}/results")
async def get_session_results(
    session_id: str,
    x_api_key_id: str = Header("", alias="X-API-Key-ID"),
    x_api_secret: str = Header("", alias="X-API-Secret"),
):
    """Get full results for a sandbox session including all attack results."""
    _authenticate_sandbox(x_api_key_id, x_api_secret)

    session = get_sandbox_session(session_id)
    if not session:
        raise HTTPException(status_code=404, detail="Session not found")

    attack_results = get_sandbox_attack_results(session_id)

    return {
        **session,
        "attack_results": attack_results,
    }


@sandbox_router.get("/agents/{agent_id}/trust-history")
async def get_agent_trust_history(
    agent_id: str,
    x_api_key_id: str = Header("", alias="X-API-Key-ID"),
    x_api_secret: str = Header("", alias="X-API-Secret"),
):
    """Get the trust score audit trail for an agent."""
    _authenticate_sandbox(x_api_key_id, x_api_secret)
    history = get_trust_score_history(agent_id)
    return {"agent_id": agent_id, "history": history}


@sandbox_router.get("/dashboard/stats")
async def sandbox_dashboard_stats():
    """Aggregate sandbox statistics — no auth required (public dashboard)."""
    return get_sandbox_stats()


@sandbox_router.get("/leaderboard")
async def sandbox_leaderboard(limit: int = Query(default=25, le=200)):
    """Public agent trust leaderboard — no auth required."""
    return get_sandbox_leaderboard(limit=limit)


# ---------------------------------------------------------------------------
# Dashboard endpoints (no auth — used by the frontend dashboard)
# ---------------------------------------------------------------------------

@sandbox_router.get("/dashboard/sessions")
async def dashboard_sessions(status: Optional[str] = None, limit: int = Query(default=20, le=200)):
    """List recent sandbox sessions — no auth required."""
    sessions = list_sandbox_sessions(org_id=None, status=status)
    # list_sandbox_sessions returns all for org; we need all sessions
    # Add attack result counts per session
    enriched = []
    for s in sessions[:limit]:
        attacks = get_sandbox_attack_results(s["id"])
        s["attack_count"] = len(attacks)
        s["passed"] = sum(1 for a in attacks if a.get("passed"))
        s["failed"] = len(attacks) - s["passed"]
        enriched.append(s)
    return enriched


@sandbox_router.get("/dashboard/sessions/{session_id}/detail")
async def dashboard_session_detail(session_id: str):
    """Full session detail with attack results — no auth required."""
    session = get_sandbox_session(session_id)
    if not session:
        raise HTTPException(status_code=404, detail="Session not found")
    attack_results = get_sandbox_attack_results(session_id)
    return {**session, "attack_results": attack_results}


@sandbox_router.get("/dashboard/attack-history")
async def dashboard_attack_history(limit: int = Query(default=50, le=500), attack_type: Optional[str] = None):
    """Paginated attack results across all sessions — no auth required."""
    return get_all_attack_results(limit=limit, attack_type=attack_type)


@sandbox_router.get("/dashboard/agents/{agent_id}/profile")
async def dashboard_agent_profile(agent_id: str):
    """Agent verification + trust history + attack stats — no auth required."""
    trust_history = get_trust_score_history(agent_id)
    attack_summary = get_agent_attack_summary(agent_id)

    # Get latest agent verification if exists
    verification = None
    try:
        from core.database import AgentVerification
        db = SessionLocal()
        record = db.query(AgentVerification).filter(
            AgentVerification.agent_id == agent_id
        ).order_by(AgentVerification.id.desc()).first()
        if record:
            verification = {
                "verdict": record.verdict,
                "trust_score": record.trust_score,
                "checks_passed": record.checks_passed or {},
                "risk_flags": record.risk_flags or [],
                "verified_at": record.verified_at.isoformat() if record.verified_at else None,
            }
        db.close()
    except Exception:
        pass

    return {
        "agent_id": agent_id,
        "verification": verification,
        "trust_history": trust_history,
        "attack_summary": attack_summary,
    }


# Demo org for dashboard-initiated sessions (no API key needed)
_DEMO_ORG_ID = "org-dashboard-demo"


def _ensure_demo_org():
    """Create the demo org if it doesn't exist."""
    org = get_sandbox_organization(_DEMO_ORG_ID)
    if org:
        return org
    return save_sandbox_organization(
        org_id=_DEMO_ORG_ID,
        name="Dashboard Demo",
        email="dashboard@localhost",
        tier="pro",
        max_agents=999,
        max_sandbox_runs=999999,
    )


@sandbox_router.post("/dashboard/quick-session")
async def dashboard_quick_session(request: QuickSessionRequest):
    """Create a sandbox session from the dashboard — no API key needed."""
    _ensure_demo_org()

    session_id = f"sess-{uuid.uuid4().hex[:12]}"
    expires_at = datetime.utcnow() + timedelta(hours=1)

    config = {
        "timeout": 3600,
        "attack_types": [
            "prompt_injection", "identity_spoofing", "sybil_flood",
            "data_exfiltration", "payload_poisoning", "replay",
        ],
    }

    session = save_sandbox_session(
        session_id=session_id,
        org_id=_DEMO_ORG_ID,
        agent_id=request.agent_id,
        config=config,
        expires_at=expires_at,
    )

    return {
        "session_id": session.id,
        "agent_id": request.agent_id,
        "status": "active",
        "config": config,
        "expires_at": expires_at.isoformat(),
    }


@sandbox_router.post("/dashboard/sessions/{session_id}/run-attacks")
async def dashboard_run_attacks(session_id: str, request: RunAttacksRequest):
    """Run attacks from the dashboard — no API key needed."""
    session = get_sandbox_session(session_id)
    if not session:
        raise HTTPException(status_code=404, detail="Session not found")
    if session["status"] != "active":
        raise HTTPException(status_code=400, detail=f"Session is {session['status']}")

    from core.attack_simulator import AttackSimulator

    simulator = AttackSimulator()
    attack_types = request.attack_types or session.get("config", {}).get("attack_types", [])

    results = await simulator.run_attacks(
        session_id=session_id,
        agent_id=session["agent_id"],
        attack_types=attack_types,
    )

    total = len(results)
    passed = sum(1 for r in results if r.get("passed", False))
    resilience_score = passed / total if total > 0 else 0.0

    save_trust_score_history(
        agent_id=session["agent_id"],
        previous_score=0.0,
        new_score=resilience_score,
        reason=f"Dashboard attack test: {passed}/{total} passed",
        event_type="attack_test",
        session_id=session_id,
    )

    update_sandbox_session(
        session_id=session_id,
        results_summary={
            "total_attacks": total,
            "passed": passed,
            "failed": total - passed,
            "resilience_score": resilience_score,
            "attack_results": results,
        },
    )

    return {
        "session_id": session_id,
        "total_attacks": total,
        "passed": passed,
        "failed": total - passed,
        "resilience_score": resilience_score,
        "results": results,
    }


# ---------------------------------------------------------------------------
# Research Loop endpoints (no auth — dashboard public)
# ---------------------------------------------------------------------------

@sandbox_router.get("/research/status")
async def research_status():
    """Current status of the adversarial research loop."""
    try:
        from core.research_loop import research_arena
        if research_arena:
            return research_arena.get_status()
    except (ImportError, AttributeError):
        pass
    # Fallback: build status from DB
    db_stats = get_research_stats()
    return {
        "running": False,
        "round_number": db_stats.get("total_rounds", 0),
        "bypasses_found": db_stats.get("bypasses", 0),
        "defenses_proposed": db_stats.get("defenses_proposed", 0),
        "interval_seconds": 90,
        "current_category": "",
        "strategist_enabled": False,
        "llm_usage": {},
        "recent_rounds": 0,
    }


@sandbox_router.get("/research/discoveries")
async def research_discoveries(limit: int = Query(default=50, le=500), offset: int = Query(default=0, ge=0), category: Optional[str] = None):
    """Paginated breakthroughs from the research loop."""
    return get_research_discoveries(limit=limit, offset=offset, category=category)


@sandbox_router.get("/research/rounds")
async def research_rounds(limit: int = Query(default=20, le=200)):
    """Round history with conversation summaries."""
    return get_research_rounds(limit=limit)


@sandbox_router.get("/research/rounds/{round_number}")
async def research_round_detail(round_number: int):
    """Full conversation detail for a specific round."""
    # Try in-memory first (faster, has full data)
    try:
        from core.research_loop import research_arena
        if research_arena:
            detail = research_arena.get_round_detail(round_number)
            if detail:
                return detail
    except (ImportError, AttributeError):
        pass
    # Fallback to DB
    rounds = get_research_rounds(limit=100)
    for r in rounds:
        if r.get("round") == round_number:
            return r
    raise HTTPException(status_code=404, detail=f"Round {round_number} not found")


@sandbox_router.get("/research/categories")
async def research_categories():
    """List all threat categories the think tank cycles through."""
    try:
        from core.research_loop import THREAT_CATEGORIES
        return THREAT_CATEGORIES
    except ImportError:
        return []


@sandbox_router.get("/research/vulnerabilities")
async def research_vulnerabilities(
    status: Optional[str] = Query(default=None),
    severity: Optional[str] = Query(default=None),
    threat_class: Optional[str] = Query(default=None),
    limit: int = Query(default=50, le=500),
    offset: int = Query(default=0, ge=0),
):
    """Paginated vulnerability list with severity, status, layers bypassed."""
    from core.database import get_vulnerabilities
    return get_vulnerabilities(status=status, severity=severity, threat_class=threat_class, limit=limit, offset=offset)


@sandbox_router.get("/research/countermeasures")
async def research_countermeasures(
    status: Optional[str] = Query(default=None),
    limit: int = Query(default=50, le=500),
    offset: int = Query(default=0, ge=0),
):
    """Countermeasure list with effectiveness stats."""
    from core.database import get_countermeasures
    return get_countermeasures(status=status, limit=limit, offset=offset)


@sandbox_router.get("/research/posture")
async def research_posture():
    """Security posture summary: open vulns by severity, bypass rate, countermeasures."""
    from core.database import get_security_posture
    return get_security_posture()


# ---------------------------------------------------------------------------
# Passport Upload + Verification Theatre (Border Police demo)
# ---------------------------------------------------------------------------

# In-memory store for pending passports (keyed by verification record ID)
_pending_passports: Dict[int, dict] = {}


class PassportUploadRequest(BaseModel):
    passport_b64: str
    agent_name: str = ""


@sandbox_router.post("/passport/upload")
async def upload_passport(request: PassportUploadRequest):
    """
    Upload a passport file for verification theatre.

    Accepts base64-encoded signed passport envelope. Runs the full 10-check
    agent verification pipeline and returns detailed per-check results.
    Does NOT auto-approve — returns status: "pending_review".

    The developer then clicks APPROVE or REJECT on the frontend.
    """
    import base64
    import traceback

    passport_b64 = request.passport_b64
    agent_name = request.agent_name

    if not passport_b64:
        raise HTTPException(status_code=400, detail="passport_b64 is required (base64-encoded signed envelope)")

    # Decode the signed envelope
    try:
        envelope_bytes = base64.b64decode(passport_b64)
    except Exception:
        raise HTTPException(status_code=400, detail="Invalid base64 encoding")

    # Try to parse the passport — we need the issuer public key
    # In demo mode, we extract it from the envelope itself (the passport contains issuer_public_key)
    # First, try msgpack decode of the payload portion (everything except last 64 bytes = signature)
    try:
        import msgpack
        if len(envelope_bytes) < 65:
            raise HTTPException(status_code=400, detail="Envelope too short — not a valid passport")

        payload_bytes = envelope_bytes[:-64]
        raw_claims = msgpack.unpackb(payload_bytes, raw=False)
        issuer_pub = raw_claims.get("issuer_public_key", "")

        if not issuer_pub:
            raise HTTPException(status_code=400, detail="Passport missing issuer_public_key field")

        # Now do proper verification with signature check
        from lastbastion.passport import AgentPassport
        try:
            passport = AgentPassport.from_signed_bytes(envelope_bytes, issuer_pub)
        except ValueError as e:
            # Signature failed — still parse fields for display, but mark as failed
            passport = AgentPassport(**raw_claims)
            passport._signature_valid = False
        else:
            passport._signature_valid = True

    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=400, detail=f"Failed to parse passport: {e}")

    # Save to DB as PENDING
    from core.database import save_agent_verification
    record = save_agent_verification(
        agent_id=passport.agent_id,
        agent_name=passport.agent_name or agent_name,
        public_key=passport.public_key,
        capabilities=[],
        agent_metadata={
            "passport_id": passport.passport_id,
            "company_name": passport.company_name,
            "company_domain": passport.company_domain,
            "trust_score_claimed": passport.trust_score,
            "trust_level_claimed": passport.trust_level,
            "verdict_claimed": passport.verdict,
            "issuer": passport.issuer,
            "issued_at": passport.issued_at,
            "expires_at": passport.expires_at,
            "signature_valid": getattr(passport, "_signature_valid", False),
        },
    )

    # Run the 10-check agent verification pipeline
    from core.agent_verifier import AgentVerifier
    verifier = AgentVerifier()

    try:
        result = await verifier.verify_agent(
            agent_id=passport.agent_id,
            agent_name=passport.agent_name,
            public_key=passport.public_key,
            capabilities=getattr(passport, "capabilities", []),
            metadata={
                "passport": passport.to_dict(),
                "signature_valid": getattr(passport, "_signature_valid", False),
                "envelope_size": len(envelope_bytes),
            },
        )
    except Exception as e:
        logger.error("Passport verification failed: %s", e, exc_info=True)
        result = {
            "verdict": "ERROR",
            "trust_score": 0.0,
            "checks": {},
            "risk_flags": [f"verification_error: {e}"],
        }

    # Update DB record with verification results
    from core.database import update_agent_verification
    update_agent_verification(
        verification_id=record.id,
        verdict="PENDING_REVIEW",
        trust_score=result.get("trust_score", 0.0),
        checks_passed=result.get("checks", {}),
        risk_flags=result.get("risk_flags", []),
        proof_hash=result.get("proof_hash", ""),
        passport_fingerprint=passport.crypto_hash,
    )

    # Store passport data for later approval
    _pending_passports[record.id] = {
        "passport_data": passport.to_dict(),
        "envelope_b64": passport_b64,
        "issuer_public_key": issuer_pub,
        "verification_result": result,
    }

    # Build per-check response for the verification theatre
    checks_display = {}
    raw_checks = result.get("checks", {})
    for check_name, check_data in raw_checks.items():
        checks_display[check_name] = {
            "score": check_data.get("score", 0.0),
            "passed": check_data.get("passed", False),
            "detail": check_data.get("detail", ""),
            "veto": check_data.get("veto", False),
        }

    return {
        "id": record.id,
        "agent_id": passport.agent_id,
        "passport_id": passport.passport_id,
        "status": "pending_review",
        "verdict": result.get("verdict", "UNKNOWN"),
        "trust_score": result.get("trust_score", 0.0),
        "trust_level": result.get("trust_level", "NONE"),
        "risk_category": result.get("risk_category", "UNKNOWN"),
        "checks": checks_display,
        "risk_flags": result.get("risk_flags", []),
        "recommendations": result.get("recommendations", []),
        "message": (
            "Verification complete. You are the security admin — review the checks "
            "and click APPROVE or REJECT."
        ),
    }


@sandbox_router.post("/passport/{verification_id}/approve")
async def approve_passport(verification_id: int):
    """
    Developer approves a passport after reviewing verification results.
    The passport becomes ACTIVE — the agent can now connect via binary protocol.
    """
    from core.database import update_agent_verification, SessionLocal, AgentVerification

    db = SessionLocal()
    try:
        record = db.query(AgentVerification).filter(
            AgentVerification.id == verification_id
        ).first()
        if not record:
            raise HTTPException(status_code=404, detail="Passport not found")
        if record.verdict not in ("PENDING_REVIEW", "PENDING"):
            raise HTTPException(
                status_code=400,
                detail=f"Passport already processed (verdict: {record.verdict})"
            )

        record.verdict = "APPROVED"
        record.verified_at = datetime.utcnow()
        db.commit()

        return {
            "id": record.id,
            "agent_id": record.agent_id,
            "status": "approved",
            "message": (
                "Passport approved. The agent can now connect to the Border Police "
                "on port 9200 via the binary protocol."
            ),
        }
    finally:
        db.close()


@sandbox_router.post("/passport/auto-approve")
async def auto_approve_passport(request: PassportUploadRequest):
    """
    Upload + approve in one step — for automated demo flows.

    Combines /passport/upload and /passport/{id}/approve into a single call
    so external demo agents can get verified and approved without human clicks.
    """
    # Step 1: Upload (runs the 10-check verification)
    upload_result = await upload_passport(request)
    verification_id = upload_result.get("id")

    if not verification_id:
        raise HTTPException(status_code=500, detail="Upload succeeded but no verification ID returned")

    # Step 2: Auto-approve
    from core.database import SessionLocal, AgentVerification

    db = SessionLocal()
    try:
        record = db.query(AgentVerification).filter(
            AgentVerification.id == verification_id
        ).first()
        if not record:
            raise HTTPException(status_code=500, detail="Verification record not found after upload")

        record.verdict = "APPROVED"
        record.verified_at = datetime.utcnow()
        db.commit()
    finally:
        db.close()

    return {
        **upload_result,
        "status": "auto_approved",
        "verdict": "APPROVED",
        "message": "Passport verified and auto-approved. Agent can now connect to Border Police on port 9200.",
    }


@sandbox_router.post("/passport/{verification_id}/reject")
async def reject_passport(verification_id: int):
    """
    Developer rejects a passport after reviewing verification results.
    Educational — shows what happens when a security admin rejects an agent.
    """
    from core.database import SessionLocal, AgentVerification

    db = SessionLocal()
    try:
        record = db.query(AgentVerification).filter(
            AgentVerification.id == verification_id
        ).first()
        if not record:
            raise HTTPException(status_code=404, detail="Passport not found")
        if record.verdict not in ("PENDING_REVIEW", "PENDING"):
            raise HTTPException(
                status_code=400,
                detail=f"Passport already processed (verdict: {record.verdict})"
            )

        record.verdict = "REJECTED"
        record.verified_at = datetime.utcnow()
        db.commit()

        return {
            "id": record.id,
            "agent_id": record.agent_id,
            "status": "rejected",
            "message": (
                "Passport rejected. The agent will be denied access if it tries "
                "to connect via binary protocol."
            ),
        }
    finally:
        db.close()


@sandbox_router.get("/passport/pending")
async def list_pending_passports():
    """List all passports awaiting review — used by the frontend dashboard."""
    from core.database import SessionLocal, AgentVerification

    db = SessionLocal()
    try:
        records = db.query(AgentVerification).filter(
            AgentVerification.verdict.in_(["PENDING_REVIEW", "PENDING"])
        ).order_by(AgentVerification.submitted_at.desc()).limit(50).all()

        results = []
        for r in records:
            results.append({
                "id": r.id,
                "agent_id": r.agent_id,
                "agent_name": r.agent_name,
                "public_key": r.public_key[:16] + "..." if r.public_key else "",
                "trust_score": r.trust_score,
                "checks_passed": r.checks_passed or {},
                "risk_flags": r.risk_flags or [],
                "submitted_at": r.submitted_at.isoformat() if r.submitted_at else None,
                "passport_id": (r.agent_metadata or {}).get("passport_id", ""),
            })
        return results
    finally:
        db.close()


@sandbox_router.get("/passport/approved")
async def list_approved_passports():
    """List all approved passports — used by Border Police to check access."""
    from core.database import SessionLocal, AgentVerification

    db = SessionLocal()
    try:
        records = db.query(AgentVerification).filter(
            AgentVerification.verdict == "APPROVED"
        ).order_by(AgentVerification.verified_at.desc()).limit(100).all()

        results = []
        for r in records:
            results.append({
                "id": r.id,
                "agent_id": r.agent_id,
                "agent_name": r.agent_name,
                "public_key": r.public_key,
                "trust_score": r.trust_score,
                "verified_at": r.verified_at.isoformat() if r.verified_at else None,
                "passport_fingerprint": r.passport_fingerprint,
            })
        return results
    finally:
        db.close()


@sandbox_router.get("/passport/all")
async def list_all_passports():
    """List all passport verifications — used by the frontend dashboard."""
    from core.database import SessionLocal, AgentVerification

    db = SessionLocal()
    try:
        records = db.query(AgentVerification).order_by(
            AgentVerification.submitted_at.desc()
        ).limit(100).all()

        results = []
        for r in records:
            results.append({
                "id": r.id,
                "agent_id": r.agent_id,
                "agent_name": r.agent_name,
                "public_key": r.public_key[:16] + "..." if r.public_key else "",
                "verdict": r.verdict,
                "trust_score": r.trust_score,
                "checks_passed": r.checks_passed or {},
                "risk_flags": r.risk_flags or [],
                "submitted_at": r.submitted_at.isoformat() if r.submitted_at else None,
                "verified_at": r.verified_at.isoformat() if r.verified_at else None,
                "passport_id": (r.agent_metadata or {}).get("passport_id", ""),
            })
        return results
    finally:
        db.close()
