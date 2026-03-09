"""
M2M API Router — Machine-to-Machine Endpoints.

This router provides the external API surface for the M2M ecosystem.
It connects the protocol layer (auth, registry, quotation) to FastAPI
endpoints that external agents can call.

Endpoints:
    POST /m2m/register      — Register as a client agent
    GET  /m2m/discover      — Discover available services
    POST /m2m/quote         — Request a price quote
    POST /m2m/submit        — Submit a task (authenticated)
    GET  /m2m/status/{id}   — Check task status
    GET  /m2m/result/{id}   — Retrieve verified results
    GET  /m2m/verify/{hash} — Validate a proof record

    POST /refinery/submit   — Submit raw data for verification
    GET  /refinery/status/{hash} — Check verification status
"""
import asyncio as _asyncio
import logging
import os
import secrets
import time as _time
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, List, Optional

from fastapi import APIRouter, BackgroundTasks, HTTPException, Header, Query, Request
from pydantic import BaseModel, Field

from protocols.agent_protocol import (
    AgentIdentity,
    AgentRole,
    MessageType,
    ProtocolMessage,
    PROTOCOL_VERSION,
)
from protocols.auth import M2MAuthenticator, sign_message
from protocols.registry import AgentRegistry
from protocols.quotation import QuotationEngine
from core.verification.pipeline import VerificationPipeline
from core.task_executor import TaskExecutor
from core.blockchain_anchor import BlockchainAnchor
from core.database import (
    save_raw_submission,
    save_cleaned_data,
    get_verification_by_hash,
    get_verification_by_proof_hash,
    get_quarantine_queue,
    get_refinery_stats,
    save_production_task,
    update_production_task,
    get_production_task,
    get_orphaned_tasks,
    save_agent_verification,
    update_agent_verification,
    get_agent_trust,
    save_handoff_transaction,
    update_handoff_transaction,
    get_handoff_transaction,
    save_registration_challenge,
    get_registration_challenge,
    complete_registration_challenge,
    get_agent_sandbox_graduation,
    update_agent_last_active,
    save_agent_report,
    get_reports_against,
    count_unique_reporters,
    has_reported,
    get_reporter_false_report_rate,
    apply_trust_decay,
    save_trust_score_history,
    revoke_agent_live_keys,
    save_agent_passport,
    get_agent_passport,
    get_passport_by_id,
    save_dashboard_agent,
    load_all_dashboard_agents,
    revoke_passport,
    update_passport_budget,
    record_budget_strike,
    save_agent_appeal,
    get_agent_appeal,
    resolve_agent_appeal,
    list_agent_appeals,
    clear_passport_escalation,
    get_passport_escalation,
    STRIKE_TIER_1,
    STRIKE_TIER_2,
    STRIKE_TIER_3,
    AgentPassportRecord,
    DashboardAgent,
    SessionLocal,
    Mission,
    Task,
    WorkerRegistry,
    MissionPlaybook,
    RawSubmission,
    VerificationResult,
    BlockchainStamp,
    UsageMetrics,
    AgentVerification,
)
from core.agent_verifier import AgentVerifier
from core.protocol_bus import protocol_bus
from core.behavior_simulator import (
    payload_generator,
    response_builder,
    SIMULATION_TYPES,
    VALID_BEHAVIOR_TYPES,
)


def _utc_iso(dt) -> Optional[str]:
    """Format a datetime as ISO 8601 with Z suffix so JS interprets as UTC."""
    if dt is None:
        return None
    return dt.isoformat() + "Z"


logger = logging.getLogger("M2M_API")

# Global instances (initialised once, shared across requests)
authenticator = M2MAuthenticator(db_session_factory=SessionLocal)
registry = AgentRegistry()
quotation = QuotationEngine()
blockchain_anchor = BlockchainAnchor()  # Reads env vars, gracefully degrades
verification_pipeline = VerificationPipeline(
    blockchain_anchor=blockchain_anchor,
)
task_executor = TaskExecutor(verification_pipeline=verification_pipeline)
agent_verifier = AgentVerifier(blockchain_anchor=blockchain_anchor, db_session_factory=SessionLocal)

# In-memory caches (warm layer — DB is authoritative)
# Max sizes prevent unbounded memory growth; oldest entries evicted when full
_MAX_TASKS_CACHE = 500
_MAX_RESULTS_CACHE = 1000
_tasks: Dict[str, Dict[str, Any]] = {}
_results: Dict[str, Dict[str, Any]] = {}
_activity_feed: List[Dict[str, Any]] = []  # Recent activity events (max 200)
_dashboard_agents: List[Dict[str, Any]] = []  # Agents registered via dashboard
_dashboard_lock = _asyncio.Lock()  # Protects _dashboard_agents from concurrent mutation


def _evict_cache(cache: Dict, max_size: int) -> None:
    """Evict oldest entries from a cache dict when it exceeds max_size."""
    if len(cache) <= max_size:
        return
    # Remove oldest entries (by insertion order — Python 3.7+ dicts are ordered)
    excess = len(cache) - max_size
    keys_to_remove = list(cache.keys())[:excess]
    for k in keys_to_remove:
        del cache[k]


def _require_api_key(
    x_api_key_id: str, x_api_secret: str, endpoint: str
) -> str:
    """Authenticate API key and return agent_id. Raises 401 on failure."""
    valid, reason, agent_id, _env = authenticator.authenticate_api_key(
        x_api_key_id, x_api_secret
    )
    if not valid:
        protocol_bus.record(
            direction="INBOUND", message_type="AUTH_FAILED",
            sender_id=x_api_key_id or "unknown", endpoint=endpoint,
            auth_result="REJECTED", auth_reason=reason,
            nonce=secrets.token_hex(8), protocol_version=PROTOCOL_VERSION,
        )
        raise HTTPException(status_code=401, detail=reason)
    return agent_id


# Challenge-response toggle (set to "false" to restore old instant-key behavior)
REQUIRE_CHALLENGE = os.getenv("REQUIRE_CHALLENGE", "true").lower() == "true"

# Trust level thresholds
TRUST_THRESHOLDS = {
    "NONE": 0.0,
    "NEW": 0.40,
    "BASIC": 0.55,
    "VERIFIED": 0.65,
    "ESTABLISHED": 0.75,
    "GOLD": 0.90,
}


def _require_trust_level(
    x_api_key_id: str, x_api_secret: str, endpoint: str, min_level: str = "NONE"
) -> tuple:
    """
    Authenticate API key + check trust level.
    Returns (agent_id, trust_score, trust_level_name).
    Raises 401 on auth failure, 403 on insufficient trust.
    """
    agent_id = _require_api_key(x_api_key_id, x_api_secret, endpoint)
    min_score = TRUST_THRESHOLDS.get(min_level, 0.0)
    if min_score <= 0.0:
        return agent_id, 0.0, "ANY"
    # Look up trust
    trust = get_agent_trust(agent_id)
    score = trust.get("trust_score", 0.0)
    # Determine level name
    level_name = "NONE"
    for name in ["GOLD", "ESTABLISHED", "VERIFIED", "BASIC", "NEW"]:
        if score >= TRUST_THRESHOLDS[name]:
            level_name = name
            break
    if score < min_score:
        raise HTTPException(
            status_code=403,
            detail=f"Insufficient trust: {level_name} (score={score:.2f}), required: {min_level} ({min_score:.2f})",
        )
    return agent_id, score, level_name


# Max dashboard agents to prevent unbounded growth
_MAX_DASHBOARD_AGENTS = 200


def recover_dashboard_agents():
    """
    Startup recovery: loads dashboard agents from DB into in-memory cache.
    Called from regional_core startup (or on module load).
    Skips stale localhost entries when BASTION_HOST points to a remote Pi/server.
    """
    try:
        agents = load_all_dashboard_agents()
        if agents:
            bastion_host = os.environ.get("BASTION_HOST", "localhost")
            is_remote = bastion_host not in ("localhost", "127.0.0.1", "")
            # Merge into existing (don't overwrite if already populated)
            existing_ids = {a["agent_id"] for a in _dashboard_agents}
            loaded = 0
            skipped = 0
            for agent in agents:
                if agent["agent_id"] not in existing_ids:
                    # Skip old localhost entries when agents are on remote host
                    if is_remote:
                        url = agent.get("url", "")
                        if "localhost" in url or "127.0.0.1" in url:
                            skipped += 1
                            continue
                    _dashboard_agents.append(agent)
                    existing_ids.add(agent["agent_id"])
                    loaded += 1
            if loaded:
                logger.info(f"RECOVERED {loaded} dashboard agents from DB")
            if skipped:
                logger.info(f"SKIPPED {skipped} stale localhost agents (remote mode: {bastion_host})")
    except Exception as e:
        logger.warning(f"Dashboard agent recovery failed: {e}")


# Run recovery on import (safe — DB may not be ready yet, so failures are non-fatal)
try:
    recover_dashboard_agents()
except Exception:
    pass


async def recover_orphaned_tasks():
    """
    Startup recovery: loads queued/running tasks from DB into memory cache
    and re-queues them for execution. Called from regional_core startup.
    """
    orphans = get_orphaned_tasks(["queued", "running"])
    if not orphans:
        return 0
    recovered = 0
    for task in orphans:
        tid = task["task_id"]
        if tid not in _tasks:
            _tasks[tid] = task
            recovered += 1
            # Re-queue for execution
            import asyncio
            asyncio.create_task(_execute_task_background(tid))
            logger.info(f"RECOVERED orphaned task: {tid} (was {task['status']})")
    return recovered

router = APIRouter(prefix="/m2m", tags=["M2M"])
refinery_router = APIRouter(prefix="/refinery", tags=["Refinery"])


# ---------------------------------------------------------------------------
# Pydantic request models
# ---------------------------------------------------------------------------
class RegisterRequest(BaseModel):
    agent_id: str
    public_key: str
    role: str = "DATA_CONSUMER"
    display_name: str = ""
    capabilities: List[str] = []


class QuoteRequest(BaseModel):
    service_id: str
    task_params: Dict[str, Any] = {}


class TaskSubmitRequest(BaseModel):
    service_id: str
    quote_id: str
    payload: Dict[str, Any] = Field(..., max_length=500)
    target_url: str = ""
    context: Dict[str, Any] = Field(default_factory=dict, max_length=100)


class RefinerySubmitRequest(BaseModel):
    payload: Dict[str, Any] = Field(..., max_length=500)
    source_agent_id: str = "api_user"
    context: Dict[str, Any] = Field(default_factory=dict, max_length=100)


class AgentVerifyRequest(BaseModel):
    agent_id: str
    agent_name: str = ""
    agent_url: str = ""
    public_key: str = ""
    capabilities: List[str] = []
    metadata: Dict[str, Any] = {}


class HandoffRequest(BaseModel):
    sender_id: str
    receiver_id: str
    payload: Dict[str, Any]
    payload_summary: str = ""


class HandoffCompleteRequest(BaseModel):
    handoff_id: str
    action: str  # "accept" or "reject"
    reason: str = ""


class ChallengeVerifyRequest(BaseModel):
    challenge_id: str
    signature: str


class AgentReportRequest(BaseModel):
    target_id: str
    reason: str  # spam, malicious_data, impersonation, sybil, other
    evidence: str = ""


class SimulateBehaviorRequest(BaseModel):
    agent_id: str
    behavior_type: str  # hallucinating | badly_programmed | malicious | poisoned_payload


# Simple rate limiter for simulation endpoint (max 10/min per agent)
_sim_rate: Dict[str, List[float]] = {}
_SIM_RATE_LIMIT = 10
_SIM_RATE_WINDOW = 60.0


def _check_sim_rate(agent_id: str) -> bool:
    """Returns True if allowed, False if rate limited."""
    now = _time.time()
    key = f"sim:{agent_id}"
    if key not in _sim_rate:
        _sim_rate[key] = []
    # Prune old entries
    _sim_rate[key] = [t for t in _sim_rate[key] if now - t < _SIM_RATE_WINDOW]
    if len(_sim_rate[key]) >= _SIM_RATE_LIMIT:
        return False
    _sim_rate[key].append(now)
    return True


# ---------------------------------------------------------------------------
# M2M ENDPOINTS
# ---------------------------------------------------------------------------

@router.post("/register")
async def m2m_register(request: RegisterRequest):
    """
    Register an external agent with The Last Bastion.

    When REQUIRE_CHALLENGE=true (default):
      Returns a cryptographic challenge (nonce). Agent must sign and return
      via POST /m2m/register/verify to receive API key.

    When REQUIRE_CHALLENGE=false:
      Legacy behavior — issues key immediately (for backward compat).
    """
    _t0 = _time.monotonic()
    try:
        role = AgentRole(request.role)
    except ValueError:
        raise HTTPException(
            status_code=400,
            detail=f"Invalid role: {request.role}. "
                   f"Valid: {[r.value for r in AgentRole]}",
        )

    if REQUIRE_CHALLENGE:
        # Challenge-response flow: generate nonce, do NOT issue key yet
        nonce = secrets.token_hex(32)
        challenge_id = f"reg-{secrets.token_hex(8)}"
        save_registration_challenge(
            challenge_id=challenge_id,
            agent_id=request.agent_id,
            nonce=nonce,
            public_key=request.public_key,
            role=request.role,
            display_name=request.display_name,
            capabilities=request.capabilities,
            expires_at=datetime.utcnow() + timedelta(minutes=10),
        )

        logger.info(f"M2M CHALLENGE: {request.agent_id} -> {challenge_id}")
        protocol_bus.record(
            direction="INBOUND", message_type="REGISTER",
            sender_id=request.agent_id, endpoint="/m2m/register",
            auth_result="CHALLENGE_ISSUED",
            payload_summary=f"challenge={challenge_id}, agent={request.agent_id}",
            payload_size_bytes=len(request.model_dump_json().encode()),
            nonce=secrets.token_hex(8),
            protocol_version=PROTOCOL_VERSION,
            signature_present=False,
            processing_ms=(_time.monotonic() - _t0) * 1000,
        )

        return {
            "challenge_id": challenge_id,
            "nonce": nonce,
            "status": "PENDING",
            "message": "Sign this nonce with your Ed25519 private key and POST to /m2m/register/verify",
            "expires_in_seconds": 600,
        }

    # Legacy flow (REQUIRE_CHALLENGE=false)
    identity = AgentIdentity(
        agent_id=request.agent_id,
        public_key=request.public_key,
        role=role,
        display_name=request.display_name or request.agent_id,
        capabilities=request.capabilities,
    )
    authenticator.register_agent(identity)
    result = registry.register_agent(identity)
    key_id, raw_secret = authenticator.issue_api_key(request.agent_id)
    balance = quotation.add_credits(request.agent_id, 50.0)

    logger.info(f"M2M REGISTER (legacy): {request.agent_id} (role={role.value})")
    protocol_bus.record(
        direction="INBOUND", message_type="REGISTER",
        sender_id=request.agent_id, endpoint="/m2m/register",
        auth_result="SKIPPED",
        payload_summary=f"agent_id={request.agent_id}, role={role.value}",
        payload_size_bytes=len(request.model_dump_json().encode()),
        nonce=secrets.token_hex(8),
        protocol_version=PROTOCOL_VERSION,
        signature_present=bool(request.public_key),
        processing_ms=(_time.monotonic() - _t0) * 1000,
    )
    return {
        **result,
        "api_key": {
            "key_id": key_id,
            "secret": raw_secret,
            "note": "Store this secret — it will not be shown again",
        },
        "starter_credits": 50.0,
        "current_balance": balance,
    }


@router.post("/register/verify")
async def m2m_register_verify(request: ChallengeVerifyRequest):
    """
    Complete challenge-response registration.

    Agent signs the nonce with Ed25519 private key and submits signature here.
    On success: registers agent, issues sandbox key, adds 50 credits,
    creates AgentVerification at trust=0.42 (NEW).
    """
    _t0 = _time.monotonic()
    challenge = get_registration_challenge(request.challenge_id)
    if not challenge:
        raise HTTPException(status_code=404, detail="Challenge not found")
    if challenge["status"] != "PENDING":
        raise HTTPException(status_code=400, detail=f"Challenge already {challenge['status']}")
    # Check expiry
    expires = datetime.fromisoformat(challenge["expires_at"])
    if datetime.utcnow() > expires:
        raise HTTPException(status_code=410, detail="Challenge expired")

    # Verify Ed25519 signature of the nonce
    sig_valid = False
    try:
        from nacl.signing import VerifyKey
        from nacl.exceptions import BadSignatureError
        verify_key = VerifyKey(bytes.fromhex(challenge["public_key"]))
        verify_key.verify(challenge["nonce"].encode(), bytes.fromhex(request.signature))
        sig_valid = True
    except ImportError:
        raise HTTPException(
            status_code=503,
            detail="Ed25519 verification unavailable — install PyNaCl"
        )
    except Exception:
        sig_valid = False

    if not sig_valid:
        logger.warning(f"REGISTER VERIFY FAILED: {challenge['agent_id']} bad signature")
        protocol_bus.record(
            direction="INBOUND", message_type="REGISTER_VERIFY",
            sender_id=challenge["agent_id"], endpoint="/m2m/register/verify",
            auth_result="REJECTED",
            payload_summary=f"bad signature for challenge={request.challenge_id}",
            nonce=secrets.token_hex(8),
            protocol_version=PROTOCOL_VERSION,
            processing_ms=(_time.monotonic() - _t0) * 1000,
        )
        raise HTTPException(status_code=401, detail="Invalid signature — identity not proven")

    # Signature valid — complete registration
    complete_registration_challenge(request.challenge_id)

    agent_id = challenge["agent_id"]
    try:
        role = AgentRole(challenge["role"])
    except ValueError:
        role = AgentRole.DATA_CONSUMER

    identity = AgentIdentity(
        agent_id=agent_id,
        public_key=challenge["public_key"],
        role=role,
        display_name=challenge["display_name"] or agent_id,
        capabilities=challenge["capabilities"],
    )
    authenticator.register_agent(identity)
    registry.register_agent(identity)

    # Issue SANDBOX key only (not live)
    key_id, raw_secret = authenticator.issue_api_key(
        agent_id, environment="sandbox", rate_limit=10,
    )
    balance = quotation.add_credits(agent_id, 50.0)

    # Auto-create AgentVerification at NEW trust level (0.42)
    save_agent_verification(
        agent_id=agent_id,
        agent_name=challenge["display_name"],
        public_key=challenge["public_key"],
        capabilities=challenge["capabilities"],
    )
    from core.database import update_agent_verification as _uav
    db = SessionLocal()
    try:
        record = db.query(AgentVerification).filter(
            AgentVerification.agent_id == agent_id,
            AgentVerification.verdict == "PENDING",
        ).order_by(AgentVerification.submitted_at.desc()).first()
        if record:
            _uav(
                verification_id=record.id,
                verdict="TRUSTED",
                trust_score=0.42,
                checks_passed={"crypto_challenge": {"passed": True, "score": 1.0, "detail": "Ed25519 nonce signed"}},
            )
    except Exception:
        pass
    finally:
        db.close()

    logger.info(f"M2M REGISTER VERIFIED: {agent_id} -> sandbox key issued, trust=0.42")
    protocol_bus.record(
        direction="INBOUND", message_type="REGISTER_VERIFY",
        sender_id=agent_id, endpoint="/m2m/register/verify",
        auth_result="VERIFIED",
        payload_summary=f"challenge={request.challenge_id} verified, sandbox key issued",
        nonce=secrets.token_hex(8),
        protocol_version=PROTOCOL_VERSION,
        signature_present=True,
        processing_ms=(_time.monotonic() - _t0) * 1000,
    )

    return {
        "agent_id": agent_id,
        "status": "REGISTERED",
        "trust_level": "NEW",
        "trust_score": 0.42,
        "api_key": {
            "key_id": key_id,
            "secret": raw_secret,
            "environment": "sandbox",
            "note": "Sandbox key issued. Complete verification + sandbox testing to upgrade to live.",
        },
        "starter_credits": 50.0,
        "current_balance": balance,
        "next_steps": [
            "POST /m2m/verify-agent to run trust verification and raise your score",
            "Complete at least 1 sandbox session with resilience >= 0.5",
            "POST /m2m/upgrade-to-live to get a live API key",
        ],
    }


@router.get("/discover")
async def m2m_discover(
    tags: Optional[str] = None,
    region: Optional[str] = None,
):
    """
    Discover available services by tags and/or region.

    Query params:
        tags: comma-separated tags (e.g., "energy,nz")
        region: region code (e.g., "nz")
    """
    _t0 = _time.monotonic()
    tag_list = tags.split(",") if tags else None

    services = registry.discover_services(
        tags=tag_list,
        region=region,
    )

    protocol_bus.record(
        direction="INBOUND", message_type="DISCOVER",
        sender_id="anonymous", endpoint="/m2m/discover",
        auth_result="SKIPPED",
        payload_summary=f"query: tags={tags or 'all'}, region={region or 'all'}",
        nonce=secrets.token_hex(8),
        protocol_version=PROTOCOL_VERSION,
        processing_ms=(_time.monotonic() - _t0) * 1000,
    )

    return {
        "protocol_version": PROTOCOL_VERSION,
        "services": services,
        "total": len(services),
    }


@router.post("/quote")
async def m2m_quote(
    request: QuoteRequest,
    x_api_key_id: str = Header(default=""),
    x_api_secret: str = Header(default=""),
):
    """
    Request a price quote for a task.

    Requires API key authentication via headers.
    """
    _t0 = _time.monotonic()
    # Authenticate
    valid, reason, agent_id, _env = authenticator.authenticate_api_key(
        x_api_key_id, x_api_secret
    )
    if not valid:
        protocol_bus.record(
            direction="INBOUND", message_type="QUOTE_REQUEST",
            sender_id=x_api_key_id or "unknown", endpoint="/m2m/quote",
            auth_result="REJECTED", auth_reason=reason,
            payload_summary=f"service={request.service_id}, params={list(request.task_params.keys())}",
            payload_size_bytes=len(request.model_dump_json().encode()),
            nonce=secrets.token_hex(8),
            protocol_version=PROTOCOL_VERSION,
            signature_present=bool(x_api_key_id),
            processing_ms=(_time.monotonic() - _t0) * 1000,
        )
        raise HTTPException(status_code=401, detail=reason)

    # Check permission
    if not authenticator.check_permission(agent_id, "quote"):
        raise HTTPException(status_code=403, detail="Insufficient permissions")

    quote = quotation.generate_quote(
        agent_id=agent_id,
        service_id=request.service_id,
        task_params=request.task_params,
    )

    protocol_bus.record(
        direction="INBOUND", message_type="QUOTE_REQUEST",
        sender_id=agent_id, endpoint="/m2m/quote",
        auth_result="AUTHENTICATED",
        payload_summary=f"service={request.service_id}, params={list(request.task_params.keys())}",
        payload_size_bytes=len(request.model_dump_json().encode()),
        nonce=secrets.token_hex(8),
        protocol_version=PROTOCOL_VERSION,
        signature_present=True,
        processing_ms=(_time.monotonic() - _t0) * 1000,
    )

    return {
        "quote": quote.to_dict(),
        "your_balance": quotation.get_balance(agent_id),
        "can_afford": quotation.get_balance(agent_id) >= quote.estimated_credits,
    }


@router.post("/submit")
async def m2m_submit(
    request: TaskSubmitRequest,
    background_tasks: BackgroundTasks,
    x_api_key_id: str = Header(default=""),
    x_api_secret: str = Header(default=""),
):
    """
    Submit a task for execution.

    Requires:
    - Valid API key
    - An accepted quote (quote_id)
    - Task payload

    The task is created and executed asynchronously via
    BackgroundTasks. Check /m2m/status/{id} and /m2m/result/{id}
    for progress and results.
    """
    _t0 = _time.monotonic()
    # Authenticate + trust gate (BASIC = 0.55)
    agent_id, _tscore, _tlevel = _require_trust_level(
        x_api_key_id, x_api_secret, "/m2m/submit", min_level="BASIC",
    )

    if not authenticator.check_permission(agent_id, "submit_task"):
        raise HTTPException(status_code=403, detail="Insufficient permissions")

    # Touch last_active_at for trust decay
    try:
        update_agent_last_active(agent_id)
    except Exception:
        pass

    # Accept the quote (deducts credits)
    accepted = quotation.accept_quote(request.quote_id)
    if not accepted:
        raise HTTPException(
            status_code=402,
            detail="Quote invalid, expired, or insufficient credits",
        )

    # Create task
    task_id = f"task-{secrets.token_hex(8)}"
    task = {
        "task_id": task_id,
        "agent_id": agent_id,
        "service_id": request.service_id,
        "quote_id": request.quote_id,
        "payload": request.payload,
        "target_url": request.target_url,
        "context": request.context,
        "status": "queued",
        "created_at": datetime.utcnow().isoformat() + "Z",
        "result": None,
    }
    _tasks[task_id] = task
    _evict_cache(_tasks, _MAX_TASKS_CACHE)

    # Persist to DB (survives restarts)
    try:
        save_production_task(
            task_id=task_id,
            agent_id=agent_id,
            service_id=request.service_id,
            payload=request.payload,
            quote_id=request.quote_id,
            target_url=request.target_url or "",
            context=request.context or {},
        )
    except Exception as db_err:
        logger.error(f"M2M TASK DB SAVE FAILED: {db_err}")

    # Launch execution in background
    background_tasks.add_task(_execute_task_background, task_id)

    logger.info(
        f"M2M TASK: {task_id} from {agent_id} "
        f"(service={request.service_id})"
    )

    _submit_payload = request.model_dump_json().encode()
    protocol_bus.record(
        direction="INBOUND", message_type="TASK_SUBMIT",
        sender_id=agent_id, endpoint="/m2m/submit",
        auth_result="AUTHENTICATED",
        payload_summary=f"service={request.service_id}, quote={request.quote_id}, fields={list(request.payload.keys())}, target={request.target_url or 'none'}",
        payload_size_bytes=len(_submit_payload),
        nonce=secrets.token_hex(8),
        protocol_version=PROTOCOL_VERSION,
        signature_present=True,
        processing_ms=(_time.monotonic() - _t0) * 1000,
    )

    return {
        "task_id": task_id,
        "status": "queued",
        "message": "Task queued — execution started",
        "check_status": f"/m2m/status/{task_id}",
    }


async def _execute_task_background(task_id: str) -> None:
    """
    Background task runner — executes via TaskExecutor.

    Updates the task dict in-place so /m2m/status and
    /m2m/result reflect the outcome.
    """
    task = _tasks.get(task_id)
    if not task:
        return

    try:
        await task_executor.execute_task(task)

        # Record usage metering
        if task["status"] == "completed":
            quotation.record_usage(
                agent_id=task["agent_id"],
                service_id=task["service_id"],
                credits_consumed=0.0,  # Credits already deducted at quote
                task_id=task_id,
                fields_processed=len(task.get("payload", {})),
                verification_verdict=task.get("result", {}).get("verdict", ""),
            )

            # Update agent reputation
            verdict = task.get("result", {}).get("verdict", "")
            if verdict in ("VERIFIED", "GOLD"):
                registry.update_reputation(task["agent_id"], +0.01)
            elif verdict == "REJECTED":
                registry.update_reputation(task["agent_id"], -0.02)

        # Persist completed state to DB
        update_production_task(task_id, task["status"], task.get("result"))

    except Exception as exc:
        logger.error("Background task %s error: %s", task_id, exc, exc_info=True)
        task["status"] = "failed"
        task["result"] = {"error": "Internal processing error"}
        update_production_task(task_id, "failed", {"error": "Internal processing error"})



@router.get("/status/{task_id}")
async def m2m_status(
    task_id: str,
    x_api_key_id: str = Header(default=""),
    x_api_secret: str = Header(default=""),
):
    """Check task execution status."""
    valid, reason, agent_id, _env = authenticator.authenticate_api_key(
        x_api_key_id, x_api_secret
    )
    if not valid:
        raise HTTPException(status_code=401, detail=reason)

    task = _tasks.get(task_id)
    if not task:
        # DB fallback
        task = get_production_task(task_id)
        if task:
            _tasks[task_id] = task  # warm cache
    if not task:
        raise HTTPException(status_code=404, detail="Task not found")

    if task["agent_id"] != agent_id:
        raise HTTPException(status_code=403, detail="Not your task")

    return {
        "task_id": task_id,
        "status": task["status"],
        "service_id": task["service_id"],
        "created_at": task["created_at"],
        "has_result": task.get("result") is not None,
    }


@router.get("/result/{task_id}")
async def m2m_result(
    task_id: str,
    x_api_key_id: str = Header(default=""),
    x_api_secret: str = Header(default=""),
):
    """Retrieve task results (once complete)."""
    valid, reason, agent_id, _env = authenticator.authenticate_api_key(
        x_api_key_id, x_api_secret
    )
    if not valid:
        raise HTTPException(status_code=401, detail=reason)

    task = _tasks.get(task_id)
    if not task:
        task = get_production_task(task_id)
        if task:
            _tasks[task_id] = task
    if not task:
        raise HTTPException(status_code=404, detail="Task not found")

    if task["agent_id"] != agent_id:
        raise HTTPException(status_code=403, detail="Not your task")

    if task["status"] != "completed":
        raise HTTPException(
            status_code=202,
            detail=f"Task still {task['status']}",
        )

    return {
        "task_id": task_id,
        "status": "completed",
        "result": task["result"],
    }


@router.get("/verify/{proof_hash}")
async def m2m_verify_proof(proof_hash: str):
    """
    Validate a proof record hash against the ProofLedger.

    Public endpoint — no authentication required.
    Anyone can verify that data was verified by The Last Bastion.
    """
    # O(1) proof lookup via hash index
    record = verification_pipeline.ledger.lookup(proof_hash)
    if record:
        return {
            "verified": True,
            "proof_hash": proof_hash,
            "verdict": record.verdict,
            "score": record.score,
            "timestamp": record.timestamp,
            "chain_position": record.record_id,
            "source": "local_ledger",
        }

    # Check on-chain if blockchain is configured
    if blockchain_anchor.is_connected:
        on_chain = blockchain_anchor.verify_on_chain(proof_hash)
        if on_chain and on_chain.get("exists"):
            return {
                "verified": True,
                "proof_hash": proof_hash,
                "verdict": on_chain["verdict"],
                "score": on_chain["score"],
                "timestamp": on_chain["timestamp"],
                "source": "blockchain",
            }

    # Also check _results for pending submissions
    result = _results.get(proof_hash)
    if result:
        return {
            "verified": result.get("status") == "verified",
            "proof_hash": proof_hash,
            "details": result,
            "source": "refinery_cache",
        }

    return {
        "verified": False,
        "proof_hash": proof_hash,
        "message": "Proof hash not found in ledger or blockchain",
    }


# ---------------------------------------------------------------------------
# AGENT VERIFICATION & HANDOFF ENDPOINTS
# ---------------------------------------------------------------------------

@router.get("/verify-agent/{agent_id}")
async def m2m_verify_agent_lookup(agent_id: str):
    """
    Passport check — looks up an agent's trust status.

    Returns cached verification from DB if it exists and hasn't expired.
    Public endpoint — any agent can check another agent's passport.
    """
    _t0 = _time.monotonic()
    trust = get_agent_trust(agent_id)

    protocol_bus.record(
        direction="INBOUND", message_type="PROOF_QUERY",
        sender_id="anonymous", recipient_id=agent_id,
        endpoint=f"/m2m/verify-agent/{agent_id}",
        auth_result="SKIPPED",
        payload_summary=f"lookup agent_id={agent_id}",
        nonce=secrets.token_hex(8),
        protocol_version=PROTOCOL_VERSION,
        processing_ms=(_time.monotonic() - _t0) * 1000,
    )

    return {
        "agent_id": agent_id,
        "verified": trust["status"] in ("TRUSTED",),
        "status": trust["status"],
        "trust_score": trust["trust_score"],
        "verified_at": trust.get("verified_at", ""),
        "expires_at": trust.get("expires_at", ""),
        "proof_hash": trust.get("proof_hash", ""),
        "tx_hash": trust.get("tx_hash", ""),
        "checks": trust.get("checks", {}),
        "passport_fingerprint": trust.get("passport_fingerprint", ""),
        "blockchain_proof": bool(trust.get("tx_hash")),
    }


@router.post("/verify-agent")
async def m2m_verify_agent_full(
    request: AgentVerifyRequest,
    x_api_key_id: str = Header(default=""),
    x_api_secret: str = Header(default=""),
):
    """
    Runs the full AgentVerifier 10-check pipeline on an agent.

    Creates a DB record, runs all checks, stamps on-chain,
    and returns the verdict. This is the "passport stamping" endpoint.
    Requires API key authentication.
    """
    _require_api_key(x_api_key_id, x_api_secret, "/m2m/verify-agent")
    _t0 = _time.monotonic()
    from datetime import timedelta

    # Detect re-verification: check if agent has existing verification
    existing_trust = get_agent_trust(request.agent_id)
    is_reverify = existing_trust["status"] != "UNVERIFIED"

    # Save initial record (PENDING)
    db_record = save_agent_verification(
        agent_id=request.agent_id,
        agent_name=request.agent_name,
        agent_url=request.agent_url,
        public_key=request.public_key,
        capabilities=request.capabilities,
        agent_metadata=request.metadata,
    )

    # Run the 10-check trust pipeline (with blockchain shortcut for re-verify)
    result = await agent_verifier.verify_agent(
        agent_id=request.agent_id,
        agent_name=request.agent_name,
        agent_url=request.agent_url,
        public_key=request.public_key,
        capabilities=request.capabilities,
        metadata=request.metadata,
        is_reverify=is_reverify,
    )

    # Update DB with results (skip if blockchain shortcut returned cached data)
    expires_at = datetime.utcnow() + timedelta(days=90)
    update_agent_verification(
        verification_id=db_record.id,
        verdict=result["verdict"],
        trust_score=result["trust_score"],
        checks_passed=result["checks"],
        risk_flags=result["risk_flags"],
        proof_hash=result["proof_hash"],
        tx_hash=result.get("tx_hash", ""),
        expires_at=expires_at,
        passport_fingerprint=result.get("passport_fingerprint", ""),
    )

    # Register agent on-chain if trusted (first verify only — shortcut skips this)
    if result["verdict"] == "TRUSTED" and blockchain_anchor.is_connected and not result.get("blockchain_shortcut"):
        role_map = {
            "DATA_CONSUMER": 0, "DATA_PROVIDER": 1,
            "VERIFIER": 2, "BROKER": 3, "OBSERVER": 4,
        }
        role_int = role_map.get(request.metadata.get("role", "DATA_CONSUMER"), 0)
        blockchain_anchor.register_agent_on_chain(
            agent_id=request.agent_id,
            public_key=request.public_key,
            role=role_int,
        )
        # Update reputation on-chain
        blockchain_anchor.update_agent_reputation(
            agent_id=request.agent_id,
            new_score=int(result["trust_score"] * 100),
        )

    logger.info(
        f"AGENT VERIFIED: {request.agent_id} -> {result['verdict']} "
        f"(score={result['trust_score']:.4f})"
    )

    _verify_payload = request.model_dump_json().encode()
    protocol_bus.record(
        direction="INBOUND", message_type="VERIFY_REQUEST",
        sender_id=request.agent_id, endpoint="/m2m/verify-agent",
        auth_result="SKIPPED",
        payload_summary=f"name={request.agent_name}, url={request.agent_url}, capabilities=[{', '.join(request.capabilities)}], key={request.public_key[:16]}..." if request.public_key else f"name={request.agent_name}, url={request.agent_url}, capabilities=[{', '.join(request.capabilities)}]",
        payload_size_bytes=len(_verify_payload),
        nonce=secrets.token_hex(8),
        protocol_version=PROTOCOL_VERSION,
        signature_present=bool(request.public_key),
        processing_ms=(_time.monotonic() - _t0) * 1000,
    )

    return {
        "agent_id": request.agent_id,
        "verdict": result["verdict"],
        "trust_score": result["trust_score"],
        "trust_level": result.get("trust_level", "NONE"),
        "risk_category": result.get("risk_category", "NONE"),
        "checks": result["checks"],
        "risk_flags": result["risk_flags"],
        "recommendations": result.get("recommendations", []),
        "evidence_chain": result.get("evidence_chain", []),
        "proof_hash": result["proof_hash"],
        "tx_hash": result.get("tx_hash", ""),
        "expires_at": expires_at.isoformat() + "Z",
    }


@router.post("/handoff/request")
async def m2m_handoff_request(
    request: HandoffRequest,
    x_api_key_id: str = Header(default=""),
    x_api_secret: str = Header(default=""),
):
    """
    Initiates an agent-to-agent handoff.

    Creates a HandoffTransaction, checks the sender's passport,
    and returns the initial status (PENDING or REDIRECT).
    Requires API key authentication.
    """
    _require_trust_level(x_api_key_id, x_api_secret, "/m2m/handoff/request", min_level="VERIFIED")
    _t0 = _time.monotonic()
    import hashlib as _hashlib
    import json as _json

    handoff_id = f"hoff-{secrets.token_hex(8)}"

    # Hash the payload
    canonical = _json.dumps(
        request.payload, sort_keys=True, separators=(",", ":")
    ).encode()
    payload_hash = _hashlib.sha256(canonical).hexdigest()

    # Save transaction
    save_handoff_transaction(
        handoff_id=handoff_id,
        sender_id=request.sender_id,
        receiver_id=request.receiver_id,
        payload_hash=payload_hash,
        payload_summary=request.payload_summary or f"{len(request.payload)} fields",
        status="PENDING",
    )

    # Check sender's passport
    trust = get_agent_trust(request.sender_id)
    sender_verified = trust["status"] == "TRUSTED"

    if not sender_verified:
        # Sender not verified — redirect to get verified first
        update_handoff_transaction(
            handoff_id=handoff_id,
            status="REDIRECT",
            sender_verified=False,
            sender_trust_score=trust["trust_score"],
            reason="Sender not verified — must complete passport verification first",
        )
        logger.info(
            f"HANDOFF REDIRECT: {request.sender_id} -> {request.receiver_id} "
            f"(sender not verified)"
        )
        protocol_bus.record(
            direction="INBOUND", message_type="HANDOFF_REQUEST",
            sender_id=request.sender_id, recipient_id=request.receiver_id,
            endpoint="/m2m/handoff/request",
            auth_result="SKIPPED",
            payload_summary=f"handoff {request.sender_id}->{request.receiver_id}, {len(request.payload)} fields: [{', '.join(list(request.payload.keys())[:5])}], summary={request.payload_summary or 'none'}",
            payload_size_bytes=len(canonical),
            nonce=secrets.token_hex(8),
            protocol_version=PROTOCOL_VERSION,
            processing_ms=(_time.monotonic() - _t0) * 1000,
        )
        protocol_bus.record(
            direction="OUTBOUND", message_type="REGISTER_REDIRECT",
            sender_id="registry-base", recipient_id=request.sender_id,
            endpoint="/m2m/handoff/request",
            auth_result="SKIPPED",
            payload_summary=f"sender {request.sender_id} not verified (status={trust['status']}, score={trust['trust_score']:.2f}), must complete POST /m2m/verify-agent",
            nonce=secrets.token_hex(8),
            protocol_version=PROTOCOL_VERSION,
            processing_ms=0,
        )
        return {
            "handoff_id": handoff_id,
            "status": "REDIRECT",
            "message": "Sender not verified. Complete verification at POST /m2m/verify-agent first.",
            "sender_status": trust["status"],
            "sender_trust_score": trust["trust_score"],
        }

    # Sender is verified — update transaction and proceed
    update_handoff_transaction(
        handoff_id=handoff_id,
        sender_verified=True,
        sender_trust_score=trust["trust_score"],
    )

    # Run payload through the verification pipeline
    try:
        context = {
            "handoff_id": handoff_id,
            "sender_id": request.sender_id,
            "receiver_id": request.receiver_id,
            "data_hash": payload_hash,
        }
        submission_id = f"sub-{secrets.token_hex(8)}"
        context["submission_id"] = submission_id

        # Persist ingestion
        try:
            save_raw_submission(
                submission_id=submission_id,
                data_hash=payload_hash,
                source_agent_id=request.sender_id,
                submission_protocol="a2a_handoff",
                format="json",
                raw_size_bytes=len(canonical),
                provenance={
                    "source_agent_id": request.sender_id,
                    "receiver_id": request.receiver_id,
                    "handoff_id": handoff_id,
                },
            )
            save_cleaned_data(
                submission_id=submission_id,
                structured_data=request.payload,
                confidence=1.0,
                document_type="a2a_handoff",
            )
        except Exception:
            pass  # DB failure doesn't crash the pipeline

        result = await verification_pipeline.process_mission_result(
            mission_id=hash(payload_hash) % 100000,
            agent_id=request.sender_id,
            payload=request.payload,
            context=context,
        )

        update_handoff_transaction(
            handoff_id=handoff_id,
            status="PENDING",
            payload_verdict=result["verdict"],
            payload_score=result["score"],
            proof_hash=result["proof_hash"],
        )

        logger.info(
            f"HANDOFF PENDING: {request.sender_id} -> {request.receiver_id} "
            f"payload={result['verdict']} (score={result['score']:.4f})"
        )

        protocol_bus.record(
            direction="INBOUND", message_type="HANDOFF_REQUEST",
            sender_id=request.sender_id, recipient_id=request.receiver_id,
            endpoint="/m2m/handoff/request",
            auth_result="SKIPPED",
            payload_summary=f"handoff {request.sender_id}->{request.receiver_id}, {len(request.payload)} fields: [{', '.join(list(request.payload.keys())[:5])}], hash={payload_hash[:16]}",
            payload_size_bytes=len(canonical),
            nonce=secrets.token_hex(8),
            protocol_version=PROTOCOL_VERSION,
            processing_ms=(_time.monotonic() - _t0) * 1000,
        )

        return {
            "handoff_id": handoff_id,
            "status": "PENDING",
            "message": "Sender verified, payload verified. Ready for acceptance.",
            "sender_verified": True,
            "sender_trust_score": trust["trust_score"],
            "payload_verdict": result["verdict"],
            "payload_score": result["score"],
            "proof_hash": result["proof_hash"],
        }

    except Exception as exc:
        update_handoff_transaction(
            handoff_id=handoff_id,
            status="REJECTED",
            reason=f"Payload verification failed: {exc}",
        )
        return {
            "handoff_id": handoff_id,
            "status": "REJECTED",
            "message": f"Payload verification failed: {exc}",
        }


@router.post("/handoff/complete")
async def m2m_handoff_complete(
    request: HandoffCompleteRequest,
    x_api_key_id: str = Header(default=""),
    x_api_secret: str = Header(default=""),
):
    """
    Completes a handoff — accept or reject.

    On accept: stamps proof on-chain, updates both agents' reputations,
    records a task receipt on the SwarmAgentRegistry.
    Requires API key authentication.
    """
    _require_api_key(x_api_key_id, x_api_secret, "/m2m/handoff/complete")
    _t0 = _time.monotonic()
    handoff = get_handoff_transaction(request.handoff_id)
    if not handoff:
        raise HTTPException(status_code=404, detail="Handoff not found")

    if handoff["status"] not in ("PENDING",):
        raise HTTPException(
            status_code=400,
            detail=f"Handoff is {handoff['status']}, cannot complete",
        )

    if request.action == "accept":
        tx_hash = ""
        # Stamp on-chain
        if blockchain_anchor.is_connected and handoff.get("proof_hash"):
            receipt = blockchain_anchor.record_task_receipt(
                task_id=request.handoff_id,
                consumer_id=handoff["receiver_id"],
                provider_id=handoff["sender_id"],
                service_id="svc-a2a-handoff",
                credits_charged=0.0,
                outcome=0,  # COMPLETED
                proof_hash=handoff["proof_hash"],
            )
            if receipt:
                tx_hash = receipt.get("transactionHash", "")

        # Update reputations
        registry.update_reputation(handoff["sender_id"], +0.02)
        registry.update_reputation(handoff["receiver_id"], +0.01)

        update_handoff_transaction(
            handoff_id=request.handoff_id,
            status="ACCEPTED",
            tx_hash=tx_hash,
        )

        logger.info(
            f"HANDOFF ACCEPTED: {request.handoff_id} "
            f"{handoff['sender_id']} -> {handoff['receiver_id']}"
        )

        protocol_bus.record(
            direction="INBOUND", message_type="HANDOFF_ACCEPT",
            sender_id=handoff["receiver_id"], recipient_id=handoff["sender_id"],
            endpoint="/m2m/handoff/complete",
            auth_result="SKIPPED",
            payload_summary=f"accept handoff={request.handoff_id}, proof={handoff.get('proof_hash', '')[:16]}, on_chain={'yes' if tx_hash else 'no'}",
            payload_size_bytes=len(request.model_dump_json().encode()),
            nonce=secrets.token_hex(8),
            protocol_version=PROTOCOL_VERSION,
            processing_ms=(_time.monotonic() - _t0) * 1000,
        )

        return {
            "handoff_id": request.handoff_id,
            "status": "ACCEPTED",
            "tx_hash": tx_hash,
            "proof_hash": handoff.get("proof_hash", ""),
            "message": "Handoff accepted, proof stamped on-chain",
        }

    elif request.action == "reject":
        registry.update_reputation(handoff["sender_id"], -0.01)

        update_handoff_transaction(
            handoff_id=request.handoff_id,
            status="REJECTED",
            reason=request.reason or "Rejected by receiver",
        )

        logger.info(
            f"HANDOFF REJECTED: {request.handoff_id} "
            f"reason={request.reason}"
        )

        protocol_bus.record(
            direction="INBOUND", message_type="HANDOFF_REJECT",
            sender_id=handoff["receiver_id"], recipient_id=handoff["sender_id"],
            endpoint="/m2m/handoff/complete",
            auth_result="SKIPPED",
            payload_summary=f"reject handoff={request.handoff_id}, reason={request.reason or 'none'}",
            payload_size_bytes=len(request.model_dump_json().encode()),
            nonce=secrets.token_hex(8),
            protocol_version=PROTOCOL_VERSION,
            processing_ms=(_time.monotonic() - _t0) * 1000,
        )

        return {
            "handoff_id": request.handoff_id,
            "status": "REJECTED",
            "reason": request.reason,
        }

    else:
        raise HTTPException(
            status_code=400,
            detail=f"Invalid action: {request.action}. Use 'accept' or 'reject'.",
        )


# ---------------------------------------------------------------------------
# SANDBOX GRADUATION / LIVE KEY UPGRADE (Phase D)
# ---------------------------------------------------------------------------

@router.post("/upgrade-to-live")
async def m2m_upgrade_to_live(
    x_api_key_id: str = Header(default=""),
    x_api_secret: str = Header(default=""),
):
    """
    Request upgrade from sandbox key to live key.

    Checks 3 conditions:
    1. Challenge-response completed
    2. At least 1 sandbox session with resilience >= 0.5
    3. AgentVerification trust_score >= 0.55 (BASIC+)
    """
    agent_id = _require_api_key(x_api_key_id, x_api_secret, "/m2m/upgrade-to-live")

    checklist = {}

    # 1. Challenge completed
    from core.database import RegistrationChallenge
    db = SessionLocal()
    try:
        challenge = db.query(RegistrationChallenge).filter(
            RegistrationChallenge.agent_id == agent_id,
            RegistrationChallenge.status == "COMPLETED",
        ).first()
        checklist["challenge_completed"] = challenge is not None
    finally:
        db.close()

    # If challenge not required, auto-pass
    if not REQUIRE_CHALLENGE:
        checklist["challenge_completed"] = True

    # 2. Sandbox passed
    graduation = get_agent_sandbox_graduation(agent_id)
    checklist["sandbox_passed"] = graduation["passed"]
    checklist["sandbox_details"] = graduation

    # 3. Verification done (BASIC+)
    trust = get_agent_trust(agent_id)
    checklist["verification_done"] = trust.get("trust_score", 0.0) >= 0.55
    checklist["current_trust_score"] = trust.get("trust_score", 0.0)

    all_passed = all([
        checklist["challenge_completed"],
        checklist["sandbox_passed"],
        checklist["verification_done"],
    ])

    if not all_passed:
        raise HTTPException(
            status_code=403,
            detail={
                "message": "Not all graduation requirements met",
                "checklist": checklist,
                "help": {
                    "challenge": "POST /m2m/register with REQUIRE_CHALLENGE=true",
                    "sandbox": "Run sandbox sessions via /sandbox/* endpoints",
                    "verification": "POST /m2m/verify-agent to raise trust score",
                },
            },
        )

    # All passed — issue live key
    key_id, raw_secret = authenticator.issue_api_key(
        agent_id, environment="production", rate_limit=60,
    )

    logger.info(f"UPGRADE TO LIVE: {agent_id} graduated (score={trust.get('trust_score', 0):.2f})")

    return {
        "agent_id": agent_id,
        "status": "UPGRADED",
        "api_key": {
            "key_id": key_id,
            "secret": raw_secret,
            "environment": "production",
            "note": "Live key issued. Store this secret — it will not be shown again.",
        },
        "checklist": checklist,
    }


# ---------------------------------------------------------------------------
# PEER REPORTING (Phase F)
# ---------------------------------------------------------------------------

@router.post("/report-agent")
async def m2m_report_agent(
    request: AgentReportRequest,
    x_api_key_id: str = Header(default=""),
    x_api_secret: str = Header(default=""),
):
    """
    Report an agent for bad behavior. Requires VERIFIED+ trust level.

    Auto-escalation:
    - 3 unique reporters → target forced to re-verify (drop to BASIC)
    - 5 unique reporters → target quarantined (revoke live keys, drop to 0.30)
    """
    agent_id, _tscore, _tlevel = _require_trust_level(
        x_api_key_id, x_api_secret, "/m2m/report-agent", min_level="VERIFIED",
    )

    valid_reasons = {"spam", "malicious_data", "impersonation", "sybil", "other"}
    if request.reason not in valid_reasons:
        raise HTTPException(
            status_code=400,
            detail=f"Invalid reason. Valid: {sorted(valid_reasons)}",
        )

    # Can't self-report
    if agent_id == request.target_id:
        raise HTTPException(status_code=400, detail="Cannot report yourself")

    # Can't double-report
    if has_reported(agent_id, request.target_id):
        raise HTTPException(status_code=409, detail="You have already reported this agent")

    # Check reporter credibility
    false_rate = get_reporter_false_report_rate(agent_id)
    if false_rate > 0.5:
        raise HTTPException(
            status_code=403,
            detail=f"Reporter credibility too low (false report rate: {false_rate:.0%})",
        )

    # Save the report
    save_agent_report(
        reporter_id=agent_id,
        target_id=request.target_id,
        reason=request.reason,
        evidence=request.evidence,
    )

    # Check escalation thresholds
    unique_reporters = count_unique_reporters(request.target_id)
    escalation = None

    if unique_reporters >= 5:
        # Quarantine: revoke live keys, drop to 0.30
        apply_trust_decay(request.target_id, 0.30, f"Quarantined: {unique_reporters} peer reports")
        revoke_agent_live_keys(request.target_id)
        escalation = "QUARANTINED"
        logger.warning(f"PEER REPORT QUARANTINE: {request.target_id} ({unique_reporters} reporters)")
    elif unique_reporters >= 3:
        # Force re-verification: drop to BASIC
        apply_trust_decay(request.target_id, 0.55, f"Re-verification triggered: {unique_reporters} peer reports")
        escalation = "RE_VERIFICATION"
        logger.warning(f"PEER REPORT RE-VERIFY: {request.target_id} ({unique_reporters} reporters)")

    protocol_bus.record(
        direction="INBOUND", message_type="AGENT_REPORT",
        sender_id=agent_id, recipient_id=request.target_id,
        endpoint="/m2m/report-agent",
        auth_result="AUTHENTICATED",
        payload_summary=f"report {request.target_id}: {request.reason}, reporters={unique_reporters}",
        nonce=secrets.token_hex(8),
        protocol_version=PROTOCOL_VERSION,
        processing_ms=0,
    )

    return {
        "status": "REPORTED",
        "target_id": request.target_id,
        "reason": request.reason,
        "unique_reporters": unique_reporters,
        "escalation": escalation,
    }


# ---------------------------------------------------------------------------
# REFINERY ENDPOINTS (Data Verification)
# ---------------------------------------------------------------------------

@refinery_router.post("/submit")
async def refinery_submit(
    request: RefinerySubmitRequest,
    x_api_key_id: str = Header(default=""),
    x_api_secret: str = Header(default=""),
):
    """
    Submit raw data for verification through the full stack.

    Persists ingestion record and runs the full verification pipeline.
    Results are stored in PostgreSQL — survives restarts.
    Requires API key authentication.
    """
    agent_id, _tscore, _tlevel = _require_trust_level(
        x_api_key_id, x_api_secret, "/refinery/submit", min_level="NEW",
    )
    _t0 = _time.monotonic()
    import hashlib
    import json
    import secrets

    canonical = json.dumps(
        request.payload, sort_keys=True, separators=(",", ":")
    ).encode()

    # Enforce 10MB payload size limit
    if len(canonical) > 10 * 1024 * 1024:
        raise HTTPException(status_code=413, detail="Payload too large (max 10MB)")
    data_hash = hashlib.sha256(canonical).hexdigest()

    # Touch last_active_at for trust decay
    try:
        update_agent_last_active(agent_id)
    except Exception:
        pass

    # Check DB first — avoid re-running verification on duplicate submissions
    existing = get_verification_by_hash(data_hash)
    if existing:
        logger.info(f"REFINERY: duplicate hash={data_hash[:16]}... returning cached verdict")
        _results[data_hash] = existing  # warm cache
        protocol_bus.record(
            direction="INBOUND", message_type="REFINERY_SUBMIT",
            sender_id=request.source_agent_id, endpoint="/refinery/submit",
            auth_result="SKIPPED",
            payload_summary=f"DUPLICATE — {len(request.payload)} fields: [{', '.join(list(request.payload.keys())[:6])}], hash={data_hash[:16]}",
            payload_size_bytes=len(canonical),
            nonce=secrets.token_hex(8),
            protocol_version=PROTOCOL_VERSION,
            processing_ms=(_time.monotonic() - _t0) * 1000,
        )
        return {
            "data_hash": data_hash,
            "status": "verified",
            "verdict": existing["verdict"],
            "score": existing["score"],
            "proof_hash": existing["proof_hash"],
            "cached": True,
        }

    # Persist ingestion record
    submission_id = f"sub-{secrets.token_hex(8)}"
    try:
        save_raw_submission(
            submission_id=submission_id,
            data_hash=data_hash,
            source_agent_id=request.source_agent_id,
            submission_protocol="m2m",
            format="json",
            raw_size_bytes=len(canonical),
            provenance={
                "source_agent_id": request.source_agent_id,
                "submission_protocol": "m2m",
                "submission_time": datetime.utcnow().isoformat() + "Z",
                "metadata": request.context or {},
            },
        )
        save_cleaned_data(
            submission_id=submission_id,
            structured_data=request.payload,
            confidence=1.0,
            document_type=request.context.get("document_type", "json_submission"),
        )
    except Exception as db_err:
        logger.warning(f"REFINERY: ingestion DB persist failed (continuing): {db_err}")

    # Run the ACTUAL verification pipeline
    try:
        context = {
            **(request.context or {}),
            "submission_id": submission_id,
            "data_hash": data_hash,
        }
        result = await verification_pipeline.process_mission_result(
            mission_id=hash(data_hash) % 100000,
            agent_id=request.source_agent_id,
            payload=request.payload,
            context=context,
        )

        cache_entry = {
            "data_hash": data_hash,
            "submission_id": submission_id,
            "status": "verified",
            "verdict": result["verdict"],
            "score": result["score"],
            "proof_hash": result["proof_hash"],
            "proof_record_id": result["proof_record_id"],
            "source_agent_id": request.source_agent_id,
            "payload_fields": len(request.payload),
            "submitted_at": datetime.utcnow().isoformat() + "Z",
            "details": result.get("details", {}),
        }
        _results[data_hash] = cache_entry
        _evict_cache(_results, _MAX_RESULTS_CACHE)

        logger.info(
            f"REFINERY: hash={data_hash[:16]}... -> "
            f"{result['verdict']} (score={result['score']:.4f})"
        )

        protocol_bus.record(
            direction="INBOUND", message_type="REFINERY_SUBMIT",
            sender_id=request.source_agent_id, endpoint="/refinery/submit",
            auth_result="SKIPPED",
            payload_summary=f"{len(request.payload)} fields: [{', '.join(list(request.payload.keys())[:6])}], format=json, hash={data_hash[:16]}, doc_type={request.context.get('document_type', 'json')}",
            payload_size_bytes=len(canonical),
            nonce=secrets.token_hex(8),
            protocol_version=PROTOCOL_VERSION,
            processing_ms=(_time.monotonic() - _t0) * 1000,
        )

        # Broadcast to WebSocket feed
        try:
            from regional_core import broadcast_event
            import asyncio
            asyncio.ensure_future(broadcast_event({
                "type": "verification",
                "data_hash": data_hash,
                "submission_id": submission_id,
                "verdict": result["verdict"],
                "score": result["score"],
                "proof_hash": result["proof_hash"],
                "source_agent_id": request.source_agent_id,
                "timestamp": datetime.utcnow().isoformat() + "Z",
            }))
        except Exception:
            pass  # WebSocket broadcast is best-effort

        return {
            "data_hash": data_hash,
            "submission_id": submission_id,
            "status": "verified",
            "verdict": result["verdict"],
            "score": result["score"],
            "proof_hash": result["proof_hash"],
        }

    except Exception as exc:
        logger.error("REFINERY ERROR: %s", exc, exc_info=True)
        _results[data_hash] = {
            "data_hash": data_hash,
            "submission_id": submission_id,
            "status": "failed",
            "error": "Internal verification error",
            "source_agent_id": request.source_agent_id,
            "submitted_at": datetime.utcnow().isoformat() + "Z",
        }
        return {
            "data_hash": data_hash,
            "submission_id": submission_id,
            "status": "failed",
            "error": "Internal verification error",
        }


@refinery_router.get("/status/{data_hash}")
async def refinery_status(data_hash: str):
    """
    Check verification status for submitted data.

    Checks DB first (survives restarts), falls back to in-memory cache.
    """
    # 1. Fast in-memory cache hit
    cached = _results.get(data_hash)
    if cached:
        return cached

    # 2. DB lookup
    db_result = get_verification_by_hash(data_hash)
    if db_result:
        _results[data_hash] = db_result  # warm cache
        return db_result

    raise HTTPException(status_code=404, detail="Submission not found")


@refinery_router.get("/quarantine")
async def refinery_quarantine_queue(limit: int = Query(default=50, le=500)):
    """
    Returns the pending quarantine queue for human review.
    Data in this queue scored 40–70 and awaits APPROVE or REJECT.
    """
    return {"queue": get_quarantine_queue(limit=limit)}


@refinery_router.get("/stats")
async def refinery_stats():
    """Returns aggregate refinery pipeline statistics from the database."""
    return get_refinery_stats()


@refinery_router.get("/calibration")
async def refinery_calibration(quarantine_limit: int = Query(default=50, le=500)):
    """
    Combined calibration dashboard data — single endpoint for the UI.
    Returns stats, quarantine queue, and verification pipeline health.
    """
    stats = get_refinery_stats()
    queue = get_quarantine_queue(limit=quarantine_limit)

    total_verdicts = sum(stats.get("verdicts", {}).values())

    resolution = stats.get("resolution", {})
    return {
        "stats": stats,
        "quarantine_queue": queue,
        "pipeline_health": {
            "total_verdicts": total_verdicts,
            "quarantine_pending": stats.get("quarantine_pending", 0),
            "blockchain_stamps": stats.get("blockchain_stamps", 0),
            "blockchain_connected": blockchain_anchor.is_connected,
            "reversal_rate": resolution.get("reversal_rate", 0.0),
            "total_resolved": resolution.get("total_resolved", 0),
            "approved": resolution.get("approved", 0),
            "rejected_from_quarantine": resolution.get("rejected", 0),
        },
        "avg_scores": stats.get("avg_scores", {}),
        "thresholds": {
            "rejected_max": 0.40,
            "quarantine_max": 0.70,
            "verified_max": 0.90,
            "gold_min": 0.90,
        },
    }


class BulkSubmitRequest(BaseModel):
    items: list  # List of { payload, source_agent_id, context }
    source_agent_id: str = "bulk-submitter"


# Global semaphore — shared across ALL concurrent bulk requests
_bulk_semaphore = _asyncio.Semaphore(10)


@refinery_router.post("/bulk")
async def refinery_bulk_submit(
    request: BulkSubmitRequest,
    x_api_key_id: str = Header(default=""),
    x_api_secret: str = Header(default=""),
):
    """
    Submit up to 100 items for verification in parallel (semaphore-limited).
    Each item runs through the full verification pipeline independently.
    Returns a list of results in the same order.
    Requires API key authentication.
    """
    _require_trust_level(x_api_key_id, x_api_secret, "/refinery/bulk", min_level="ESTABLISHED")
    import asyncio
    import hashlib as _hashlib
    import json as _json
    import secrets as _secrets

    if len(request.items) > 100:
        raise HTTPException(status_code=400, detail="Maximum 100 items per bulk request")
    if len(request.items) == 0:
        raise HTTPException(status_code=400, detail="No items provided")

    async def _process_one(idx: int, item) -> dict:
        payload = item.get("payload") if isinstance(item, dict) else item
        agent_id = item.get("source_agent_id", request.source_agent_id) if isinstance(item, dict) else request.source_agent_id
        context = item.get("context", {}) if isinstance(item, dict) else {}

        if not payload:
            return {"index": idx, "error": "No payload", "status": "skipped"}

        canonical = _json.dumps(payload, sort_keys=True, separators=(",", ":")).encode()
        data_hash = _hashlib.sha256(canonical).hexdigest()

        existing = get_verification_by_hash(data_hash)
        if existing:
            return {
                "index": idx, "data_hash": data_hash, "status": "verified",
                "verdict": existing["verdict"], "score": existing["score"],
                "proof_hash": existing["proof_hash"], "cached": True,
            }

        submission_id = f"sub-{_secrets.token_hex(8)}"
        try:
            save_raw_submission(
                submission_id=submission_id, data_hash=data_hash,
                source_agent_id=agent_id, submission_protocol="m2m-bulk",
                format="json", raw_size_bytes=len(canonical),
                provenance={"source_agent_id": agent_id, "bulk_index": idx},
            )
            save_cleaned_data(
                submission_id=submission_id, structured_data=payload,
                confidence=1.0, document_type=context.get("document_type", "json_submission"),
            )
        except Exception:
            pass

        async with _bulk_semaphore:
            try:
                pipe_ctx = {**context, "submission_id": submission_id, "data_hash": data_hash}
                result = await verification_pipeline.process_mission_result(
                    mission_id=hash(data_hash) % 100000,
                    agent_id=agent_id, payload=payload, context=pipe_ctx,
                )
                return {
                    "index": idx, "data_hash": data_hash, "submission_id": submission_id,
                    "status": "verified", "verdict": result["verdict"],
                    "score": result["score"], "proof_hash": result["proof_hash"], "cached": False,
                }
            except Exception as e:
                logger.error("Bulk item %d error: %s", idx, e, exc_info=True)
                return {"index": idx, "data_hash": data_hash, "status": "error", "error": "Internal verification error"}

    results = await asyncio.gather(*[_process_one(i, item) for i, item in enumerate(request.items)])
    results = list(results)

    return {
        "total": len(request.items),
        "processed": len([r for r in results if r.get("status") != "skipped"]),
        "cached": len([r for r in results if r.get("cached")]),
        "results": results,
    }


# ---------------------------------------------------------------------------
# DASHBOARD ENDPOINTS (Read-Only State Observation)
# ---------------------------------------------------------------------------

@router.get("/dashboard/stats")
async def dashboard_stats():
    """Returns high-level M2M economy statistics."""
    # Count blockchain anchors vs local ledger
    anchored_count = 0
    total_proofs = len(verification_pipeline.ledger._records)
    for r in verification_pipeline.ledger._records:
        if hasattr(r, "on_chain_tx") and r.on_chain_tx or (hasattr(r, "metadata") and r.metadata.get("tx_hash")):
            anchored_count += 1

    # Task/result counts: in-memory + DB for accuracy across restarts
    task_count = len(_tasks)
    result_count = len(_results)
    try:
        from core.database import M2MTask
        db = SessionLocal()
        try:
            db_task_count = db.query(M2MTask).count()
            db_result_count = db.query(VerificationResult).count()
            task_count = max(task_count, db_task_count)
            result_count = max(result_count, db_result_count)
        finally:
            db.close()
    except Exception:
        pass  # Fall back to in-memory counts

    return {
        "active_agents": registry.stats.get("active_agents", 0),
        "total_tasks": task_count,
        "total_extractions": result_count,
        "total_proofs_generated": total_proofs,
        "proofs_anchored_on_chain": anchored_count,
        "blockchain_connected": blockchain_anchor.is_connected,
    }


@router.get("/dashboard/ledger")
async def dashboard_ledger(limit: int = Query(default=50, le=500)):
    """Returns the most recent M2M transactions (tasks + results)."""
    transactions = []
    seen_ids = set()

    # 1. In-memory tasks (hot cache)
    for task_id, task in _tasks.items():
        seen_ids.add(task_id)
        transactions.append({
            "id": task_id,
            "type": "task",
            "agent_id": task.get("agent_id", "unknown"),
            "service_id": task.get("service_id", "unknown"),
            "status": task.get("status", "unknown"),
            "timestamp": task.get("timestamp", datetime.utcnow().isoformat() + "Z"),
        })

    # 2. In-memory verification results (hot cache)
    for data_hash, result in _results.items():
        seen_ids.add(data_hash)
        transactions.append({
            "id": data_hash,
            "type": "verification",
            "agent_id": result.get("source_agent_id", "unknown"),
            "status": result.get("status", "unknown"),
            "verdict": result.get("verdict"),
            "score": result.get("score"),
            "proof_hash": result.get("proof_hash"),
            "timestamp": result.get("submitted_at", datetime.utcnow().isoformat() + "Z"),
        })

    # 3. DB fallback — pull tasks and verifications not in memory
    try:
        from core.database import M2MTask
        db = SessionLocal()
        try:
            db_tasks = db.query(M2MTask).order_by(M2MTask.created_at.desc()).limit(limit).all()
            for t in db_tasks:
                if t.task_id not in seen_ids:
                    seen_ids.add(t.task_id)
                    transactions.append({
                        "id": t.task_id,
                        "type": "task",
                        "agent_id": t.agent_id,
                        "service_id": t.service_id,
                        "status": t.status,
                        "timestamp": _utc_iso(t.created_at) or "",
                    })
            db_vrs = db.query(VerificationResult).order_by(
                VerificationResult.created_at.desc()
            ).limit(limit).all()
            for vr in db_vrs:
                vr_id = vr.data_hash or str(vr.id)
                if vr_id not in seen_ids:
                    seen_ids.add(vr_id)
                    transactions.append({
                        "id": vr_id,
                        "type": "verification",
                        "agent_id": vr.agent_id or "system",
                        "status": "verified",
                        "verdict": vr.verdict,
                        "score": vr.composite_score,
                        "proof_hash": vr.proof_hash,
                        "timestamp": _utc_iso(vr.created_at) or "",
                    })
        finally:
            db.close()
    except Exception:
        pass  # In-memory data is still returned

    # Sort descending by timestamp
    transactions.sort(key=lambda x: x.get("timestamp", ""), reverse=True)
    return transactions[:limit]


@router.get("/dashboard/agents")
async def dashboard_agents():
    """Returns the list of all registered agents on the network."""
    agents = []
    # Protocol-registered agents
    for agent_id, agent in registry._agents.items():
        agents.append({
            "agent_id": agent_id,
            "name": agent_id,
            "role": agent.role.value,
            "capabilities": agent.capabilities,
            "reputation_score": getattr(agent, "reputation_score", 1.0),
            "last_seen": getattr(agent, "last_seen", ""),
            "source": "protocol",
        })
    # Dashboard-registered agents (A2A supply chain agents)
    seen_ids = {a["agent_id"] for a in agents}
    for da in _dashboard_agents:
        if da["agent_id"] not in seen_ids:
            agents.append({
                "agent_id": da["agent_id"],
                "name": da.get("name", da["agent_id"]),
                "url": da.get("url", ""),
                "port": da.get("port", 0),
                "role": da.get("role", "supply_chain"),
                "skills": da.get("skills", []),
                "version": da.get("version", "1.0"),
                "status": da.get("status", "online"),
                "description": da.get("description", ""),
                "registered_at": da.get("registered_at", ""),
                "last_seen": da.get("last_seen", ""),
                "source": "dashboard",
            })
    return agents


@router.get("/dashboard/agents/{agent_id}")
async def dashboard_agent_detail(agent_id: str):
    """Returns full detail for a single agent including activity and submissions."""
    # Find the agent
    agent_data = None
    for da in _dashboard_agents:
        if da["agent_id"] == agent_id:
            agent_data = {
                "agent_id": da["agent_id"],
                "name": da.get("name", da["agent_id"]),
                "url": da.get("url", ""),
                "port": da.get("port", 0),
                "role": da.get("role", "supply_chain"),
                "skills": da.get("skills", []),
                "version": da.get("version", "1.0"),
                "status": da.get("status", "online"),
                "description": da.get("description", ""),
                "registered_at": da.get("registered_at", ""),
                "last_seen": da.get("last_seen", ""),
                "source": "dashboard",
            }
            break

    # Check protocol agents too
    if not agent_data:
        for aid, agent in registry._agents.items():
            if aid == agent_id:
                agent_data = {
                    "agent_id": aid,
                    "name": aid,
                    "role": agent.role.value,
                    "capabilities": agent.capabilities,
                    "reputation_score": getattr(agent, "reputation_score", 1.0),
                    "last_seen": getattr(agent, "last_seen", ""),
                    "source": "protocol",
                }
                break

    if not agent_data:
        raise HTTPException(status_code=404, detail=f"Agent '{agent_id}' not found")

    # Filter activity events for this agent
    # Match on agent_id, registered name, and common bot names used in activity feed
    agent_name = agent_data.get("name", agent_id)
    # Map agent_ids to the bot names used in run_demo.py activity events
    _bot_name_map = {
        "producer": "ProducerBot", "compliance": "ComplianceBot",
        "logistics": "LogisticsBot", "buyer": "BuyerBot",
    }
    bot_name = _bot_name_map.get(agent_id, "")
    match_names = {agent_name, agent_id, bot_name} - {""}
    agent_activity = [
        evt for evt in _activity_feed
        if evt.get("from_agent") in match_names
        or evt.get("to_agent") in match_names
    ]

    # Query DB for submissions by this agent (check all known names)
    submissions = []
    submission_stats = {"total": 0, "verdicts": {}}
    db = SessionLocal()
    try:
        from sqlalchemy import or_
        name_filters = [RawSubmission.source_agent_id == n for n in match_names]
        if not name_filters:
            subs = []
        else:
            subs = db.query(RawSubmission).filter(
                or_(*name_filters)
            ).order_by(RawSubmission.created_at.desc()).limit(50).all()

        for s in subs:
            vr = db.query(VerificationResult).filter(
                VerificationResult.submission_id == s.id
            ).first()
            submissions.append({
                "id": s.id,
                "data_hash": s.data_hash,
                "format": s.format,
                "status": s.status,
                "verdict": vr.verdict if vr else None,
                "score": vr.composite_score if vr else None,
                "proof_hash": vr.proof_hash if vr else None,
                "created_at": _utc_iso(s.created_at),
            })
            if vr and vr.verdict:
                submission_stats["verdicts"][vr.verdict] = submission_stats["verdicts"].get(vr.verdict, 0) + 1

        submission_stats["total"] = len(subs)
    except Exception as e:
        logger.error(f"Agent detail DB query error: {e}", exc_info=True)
    finally:
        db.close()

    # Trust passport — from AgentVerification DB
    trust_passport = get_agent_trust(agent_id)

    # Enrich with trust_level, risk_category, recommendations, evidence_chain
    # derived from the checks and score already in trust_passport
    try:
        score = trust_passport.get("trust_score", 0)
        checks = trust_passport.get("checks", {})
        flags = trust_passport.get("risk_flags", [])

        # Also copy checks to checks_passed for frontend compatibility
        if checks:
            trust_passport["checks_passed"] = checks

        # Trust level from score
        if score >= 0.85:
            trust_passport["trust_level"] = "GOLD"
        elif score >= 0.75:
            trust_passport["trust_level"] = "ESTABLISHED"
        elif score >= 0.65:
            trust_passport["trust_level"] = "VERIFIED"
        elif score >= 0.55:
            trust_passport["trust_level"] = "BASIC"
        elif score >= 0.40:
            trust_passport["trust_level"] = "NEW"
        else:
            trust_passport["trust_level"] = "NONE"

        # Risk category from flags
        critical_flags = {"SYBIL_KEY", "SYBIL_URL", "KEY_ROTATION", "CREDENTIAL_TESTING", "POISON_SUSPECT", "DORMANT_REACTIVATION", "MALICIOUS_ASSOCIATION"}
        crit_count = sum(1 for f in flags if any(cf in f for cf in critical_flags))
        total_flags = len(flags)
        if crit_count >= 2 or total_flags >= 5:
            trust_passport["risk_category"] = "CRITICAL"
        elif crit_count >= 1 or total_flags >= 3:
            trust_passport["risk_category"] = "HIGH"
        elif total_flags >= 2:
            trust_passport["risk_category"] = "MEDIUM"
        elif total_flags >= 1:
            trust_passport["risk_category"] = "LOW"
        else:
            trust_passport["risk_category"] = "NONE"

        # Extract recommendations and evidence from check results
        recs = []
        evidence_chain = []
        for cname, cdata in checks.items():
            if isinstance(cdata, dict):
                evidence_chain.extend(cdata.get("evidence", []))
                if cdata.get("score", 1) < 0.5:
                    recs.append(f"Improve {cname} check score")
        trust_passport["recommendations"] = recs
        trust_passport["evidence_chain"] = evidence_chain
    except Exception:
        pass

    return {
        "agent": agent_data,
        "trust_passport": trust_passport,
        "activity": agent_activity,
        "submissions": submissions,
        "submission_stats": submission_stats,
    }


@router.get("/dashboard/missions")
async def dashboard_missions(limit: int = Query(default=50, le=500)):
    """Returns recent missions with task counts for Mission Control view."""
    db = SessionLocal()
    try:
        from sqlalchemy import func
        missions = db.query(Mission).order_by(Mission.created_at.desc()).limit(limit).all()
        result = []
        for m in missions:
            task_count = db.query(Task).filter(Task.mission_id == m.id).count()
            pending_tasks = db.query(Task).filter(
                Task.mission_id == m.id, Task.status == "PENDING"
            ).count()
            result.append({
                "id": m.id,
                "name": m.name,
                "category": m.category,
                "status": m.status,
                "priority": m.priority,
                "task_count": task_count,
                "pending_tasks": pending_tasks,
                "created_at": _utc_iso(m.created_at),
                "updated_at": _utc_iso(m.updated_at),
            })
        return {"missions": result, "total": len(result)}
    except Exception as e:
        logger.error(f"Dashboard missions error: {e}")
        return {"missions": [], "total": 0}
    finally:
        db.close()


@router.get("/dashboard/workers")
async def dashboard_workers():
    """Returns worker registry + telemetry for Fleet Status view."""
    db = SessionLocal()
    try:
        workers = db.query(WorkerRegistry).all()
        result = []
        for w in workers:
            result.append({
                "id": w.id,
                "status": w.status,
                "worker_type": w.worker_type,
                "current_task": w.current_task,
                "current_mission_id": w.current_mission_id,
                "swarm_id": w.swarm_id,
                "total_extractions": w.total_extractions,
                "total_yields": w.total_yields,
                "last_heartbeat": _utc_iso(w.last_heartbeat),
            })
        return {"workers": result, "total": len(result)}
    except Exception as e:
        logger.error(f"Dashboard workers error: {e}")
        return {"workers": [], "total": 0}
    finally:
        db.close()


@router.get("/dashboard/playbooks")
async def dashboard_playbooks():
    """Returns playbook library for Playbooks view."""
    db = SessionLocal()
    try:
        playbooks = db.query(MissionPlaybook).order_by(MissionPlaybook.domain).all()
        now = datetime.utcnow()
        result = []
        for pb in playbooks:
            from datetime import timedelta
            is_stale = False
            if pb.last_validated_at:
                is_stale = now > pb.last_validated_at + timedelta(days=pb.stale_after_days)
            result.append({
                "id": pb.id,
                "name": pb.name,
                "domain": pb.domain,
                "version": pb.version,
                "category": pb.category,
                "extraction_mode": pb.extraction_mode,
                "goal": pb.goal,
                "entry_url": pb.entry_url,
                "is_active": pb.is_active,
                "is_stale": is_stale,
                "success_rate": pb.success_rate,
                "total_runs": pb.total_runs,
                "schedule_cron": pb.schedule_cron,
                "priority": pb.priority,
                "created_by": pb.created_by,
                "created_at": _utc_iso(pb.created_at),
            })
        return {"playbooks": result, "total": len(result)}
    except Exception as e:
        logger.error(f"Dashboard playbooks error: {e}")
        return {"playbooks": [], "total": 0}
    finally:
        db.close()


@router.get("/dashboard/llm-usage")
async def dashboard_llm_usage(limit: int = Query(default=100, le=500)):
    """Returns LLM usage metrics for the LLM Analytics view."""
    db = SessionLocal()
    try:
        from sqlalchemy import func
        metrics = db.query(UsageMetrics).order_by(
            UsageMetrics.timestamp.desc()
        ).limit(limit).all()

        # Aggregate totals by provider/model
        totals = db.query(
            UsageMetrics.provider,
            UsageMetrics.model,
            func.sum(UsageMetrics.prompt_tokens).label("total_prompt"),
            func.sum(UsageMetrics.completion_tokens).label("total_completion"),
            func.sum(UsageMetrics.total_tokens).label("total_tokens"),
            func.sum(UsageMetrics.estimated_cost).label("total_cost"),
            func.count(UsageMetrics.id).label("request_count"),
        ).group_by(UsageMetrics.provider, UsageMetrics.model).all()

        return {
            "recent": [
                {
                    "id": m.id,
                    "mission_id": m.mission_id,
                    "provider": m.provider,
                    "model": m.model,
                    "prompt_tokens": m.prompt_tokens,
                    "completion_tokens": m.completion_tokens,
                    "total_tokens": m.total_tokens,
                    "estimated_cost": m.estimated_cost,
                    "timestamp": _utc_iso(m.timestamp),
                }
                for m in metrics
            ],
            "totals": [
                {
                    "provider": t.provider,
                    "model": t.model,
                    "total_prompt_tokens": int(t.total_prompt or 0),
                    "total_completion_tokens": int(t.total_completion or 0),
                    "total_tokens": int(t.total_tokens or 0),
                    "total_cost": float(t.total_cost or 0),
                    "request_count": int(t.request_count or 0),
                }
                for t in totals
            ],
        }
    except Exception as e:
        logger.error(f"Dashboard LLM usage error: {e}")
        return {"recent": [], "totals": []}
    finally:
        db.close()


@router.get("/dashboard/protocol-log")
async def dashboard_protocol_log(
    limit: int = Query(default=50, le=500),
    message_type: Optional[str] = None,
    sender_id: Optional[str] = None,
    auth_result: Optional[str] = None,
):
    """Returns protocol message bus log with optional filters."""
    messages = protocol_bus.query(
        limit=limit,
        message_type=message_type,
        sender_id=sender_id,
        auth_result=auth_result,
    )
    return {
        "messages": messages,
        "stats": protocol_bus.get_stats(),
    }


@router.get("/dashboard/bastion-log")
async def dashboard_bastion_log(
    limit: int = Query(default=200, le=1000),
    event_type: Optional[str] = None,
    frame_type: Optional[str] = None,
):
    """Returns Bastion Protocol frame event log with optional filters."""
    from core.bastion_bus import bastion_bus
    frames = bastion_bus.query(
        limit=limit,
        event_type=event_type,
        frame_type=frame_type,
    )
    return {
        "frames": frames,
        "stats": bastion_bus.get_stats(),
        "connections": bastion_bus.get_connections(),
        "agent_status": bastion_bus.get_agent_status(),
    }


@router.get("/dashboard/bastion-connections")
async def dashboard_bastion_connections():
    """Returns active Bastion Protocol connections."""
    from core.bastion_bus import bastion_bus
    return {
        "connections": bastion_bus.get_connections(),
        "stats": bastion_bus.get_stats(),
    }


@router.get("/dashboard/bastion-comparison")
async def dashboard_bastion_comparison():
    """Returns HTTP vs Bastion Protocol comparison data for educational display."""
    from core.bastion_bus import bastion_bus
    stats = bastion_bus.get_stats()
    total_frames = stats.get("total_frames", 0)
    total_bytes = stats.get("total_bytes", 0)
    avg_frame = total_bytes / total_frames if total_frames > 0 else 0

    return {
        "bastion_stats": stats,
        "comparison": {
            "http": {
                "identity": "Optional header (Authorization bearer token)",
                "signing": "None (relies on TLS transport)",
                "encryption": "TLS (transport layer, optional)",
                "per_message_overhead": "~800 bytes (headers + JSON encoding)",
                "anti_replay": "None (stateless)",
                "forward_secrecy": "TLS 1.3 only (when configured)",
                "format": "JSON text (human-readable, verbose)",
            },
            "bastion": {
                "identity": "Structural — 16-byte passport hash in every frame",
                "signing": "Ed25519 — 64-byte signature on every frame",
                "encryption": "XSalsa20-Poly1305 per-frame (application layer)",
                "per_message_overhead": "90 bytes (binary fixed header + signature)",
                "anti_replay": "Monotonic sequences + nonce + timestamp",
                "forward_secrecy": "Ephemeral X25519 — always (every handshake)",
                "format": "MessagePack binary (compact, typed)",
            },
        },
        "live_metrics": {
            "total_frames_exchanged": total_frames,
            "total_bytes_transferred": total_bytes,
            "avg_frame_size": round(avg_frame, 1),
            "handshakes_completed": stats.get("handshakes_completed", 0),
            "active_connections": stats.get("active_connections", 0),
        },
    }


@router.post("/dashboard/agents/{agent_id}/verify")
async def dashboard_verify_agent(agent_id: str):
    """
    Triggers agent verification from the dashboard UI.

    Looks up the agent's registered data and runs the AgentVerifier pipeline.
    """
    from datetime import timedelta

    _t0 = _time.monotonic()

    # Find agent data from dashboard agents or protocol registry
    agent_data = None
    for da in _dashboard_agents:
        if da["agent_id"] == agent_id:
            agent_data = da
            break
    if not agent_data:
        for aid, agent in registry._agents.items():
            if aid == agent_id:
                agent_data = {
                    "agent_id": aid,
                    "name": aid,
                    "url": "",
                    "role": agent.role.value,
                    "capabilities": agent.capabilities,
                }
                break

    if not agent_data:
        raise HTTPException(status_code=404, detail=f"Agent '{agent_id}' not found")

    # Detect re-verification
    existing_trust = get_agent_trust(agent_id)
    is_reverify = existing_trust["status"] != "UNVERIFIED"

    # Save initial record (PENDING)
    db_record = save_agent_verification(
        agent_id=agent_id,
        agent_name=agent_data.get("name", agent_id),
        agent_url=agent_data.get("url", ""),
        public_key=agent_data.get("public_key", ""),
        capabilities=agent_data.get("capabilities", []),
        agent_metadata={
            "role": agent_data.get("role", ""),
            "version": agent_data.get("version", "1.0"),
            "description": agent_data.get("description", ""),
            "source": "dashboard_verify",
        },
    )

    # Run the 10-check trust pipeline (with blockchain shortcut for re-verify)
    result = await agent_verifier.verify_agent(
        agent_id=agent_id,
        agent_name=agent_data.get("name", agent_id),
        agent_url=agent_data.get("url", ""),
        public_key=agent_data.get("public_key", ""),
        capabilities=agent_data.get("capabilities", []),
        metadata={
            "role": agent_data.get("role", ""),
            "version": agent_data.get("version", "1.0"),
            "description": agent_data.get("description", ""),
        },
        is_reverify=is_reverify,
    )

    # Update DB with results
    expires_at = datetime.utcnow() + timedelta(days=90)
    update_agent_verification(
        verification_id=db_record.id,
        verdict=result["verdict"],
        trust_score=result["trust_score"],
        checks_passed=result["checks"],
        risk_flags=result["risk_flags"],
        proof_hash=result["proof_hash"],
        tx_hash=result.get("tx_hash", ""),
        expires_at=expires_at,
        passport_fingerprint=result.get("passport_fingerprint", ""),
    )

    protocol_bus.record(
        direction="INBOUND", message_type="VERIFY_REQUEST",
        sender_id="dashboard", recipient_id=agent_id,
        endpoint=f"/m2m/dashboard/agents/{agent_id}/verify",
        auth_result="SKIPPED",
        payload_summary=f"dashboard verify: agent={agent_id}, name={agent_data.get('name', '')}, capabilities=[{', '.join(agent_data.get('capabilities', []))}]",
        nonce=secrets.token_hex(8),
        protocol_version=PROTOCOL_VERSION,
        processing_ms=(_time.monotonic() - _t0) * 1000,
    )

    logger.info(
        f"DASHBOARD VERIFY: {agent_id} -> {result['verdict']} "
        f"(score={result['trust_score']:.4f})"
    )

    return {
        "agent_id": agent_id,
        "verdict": result["verdict"],
        "trust_score": result["trust_score"],
        "trust_level": result.get("trust_level", "NONE"),
        "risk_category": result.get("risk_category", "NONE"),
        "checks": result["checks"],
        "risk_flags": result["risk_flags"],
        "recommendations": result.get("recommendations", []),
        "evidence_chain": result.get("evidence_chain", []),
        "proof_hash": result["proof_hash"],
        "tx_hash": result.get("tx_hash", ""),
        "expires_at": expires_at.isoformat() + "Z",
    }


# ---------------------------------------------------------------------------
# ACTIVITY FEED + AGENT REGISTRATION (Supply Chain Dashboard)
# ---------------------------------------------------------------------------

class ActivityEvent(BaseModel):
    phase: str
    from_agent: str
    to_agent: str = ""
    action: str
    data_summary: Dict[str, Any] = {}
    status: str = "complete"


class DashboardAgentRegister(BaseModel):
    agent_id: str
    name: str
    url: str
    port: int = 0
    role: str = "supply_chain"
    skills: List[Dict[str, Any]] = []
    version: str = "1.0"
    status: str = "online"
    description: str = ""


@router.post("/activity")
async def post_activity(event: ActivityEvent):
    """Records a supply chain activity event for the dashboard feed."""
    entry = {
        "id": len(_activity_feed) + 1,
        "phase": event.phase,
        "from_agent": event.from_agent,
        "to_agent": event.to_agent,
        "action": event.action,
        "data_summary": event.data_summary,
        "status": event.status,
        "timestamp": datetime.utcnow().isoformat() + "Z",
    }
    _activity_feed.insert(0, entry)
    # Keep max 200
    if len(_activity_feed) > 200:
        _activity_feed[:] = _activity_feed[:200]
    return entry


@router.get("/dashboard/activity")
async def dashboard_activity(limit: int = Query(default=50, le=500)):
    """Returns recent activity events for the Supply Chain Monitor."""
    return _activity_feed[:limit]


@router.get("/dashboard/pending-anchors")
async def dashboard_pending_anchors(limit: int = Query(default=50, le=200)):
    """Returns verification verdicts awaiting human approval for blockchain anchoring."""
    from core.database import get_pending_anchors
    return get_pending_anchors(limit=limit)


@router.post("/dashboard/agents/register")
async def dashboard_register_agent(agent: DashboardAgentRegister):
    """Registers an agent for the dashboard Agent Directory. Persisted to DB."""
    entry_data = {
        "agent_id": agent.agent_id,
        "name": agent.name,
        "url": agent.url,
        "port": agent.port,
        "role": agent.role,
        "skills": agent.skills,
        "version": agent.version,
        "status": agent.status,
        "description": agent.description,
    }

    async with _dashboard_lock:
        # Check if already registered in memory — update if so
        for existing in _dashboard_agents:
            if existing["agent_id"] == agent.agent_id:
                existing.update({
                    **entry_data,
                    "last_seen": datetime.utcnow().isoformat() + "Z",
                })
                # Persist to DB
                try:
                    save_dashboard_agent(existing)
                except Exception as e:
                    logger.warning(f"DB persist failed for agent {agent.agent_id}: {e}")
                return existing

        # Remove stale localhost duplicates if a remote version of the same agent name registers
        if agent.url and "localhost" not in agent.url and "127.0.0.1" not in agent.url:
            name_lower = agent.name.lower().replace("-", "").replace("_", "").replace(" ", "")
            stale = [
                i for i, da in enumerate(_dashboard_agents)
                if da.get("name", "").lower().replace("-", "").replace("_", "").replace(" ", "") == name_lower
                and ("localhost" in da.get("url", "") or "127.0.0.1" in da.get("url", ""))
            ]
            for idx in reversed(stale):
                removed = _dashboard_agents.pop(idx)
                logger.info(f"Removed stale localhost agent: {removed.get('agent_id')} (replaced by {agent.agent_id})")

        # Enforce max dashboard agents to prevent unbounded growth
        if len(_dashboard_agents) >= _MAX_DASHBOARD_AGENTS:
            raise HTTPException(status_code=429, detail="Dashboard agent limit reached")

        entry = {
            **entry_data,
            "registered_at": datetime.utcnow().isoformat() + "Z",
            "last_seen": datetime.utcnow().isoformat() + "Z",
        }
        _dashboard_agents.append(entry)
        if len(_dashboard_agents) > _MAX_DASHBOARD_AGENTS:
            _dashboard_agents[:] = _dashboard_agents[-_MAX_DASHBOARD_AGENTS:]

    # Persist to DB (outside lock — DB ops shouldn't hold the lock)
    try:
        save_dashboard_agent(entry)
    except Exception as e:
        logger.warning(f"DB persist failed for agent {agent.agent_id}: {e}")

    # Also bump the registry stats counter
    registry.stats["active_agents"] = registry.stats.get("active_agents", 0) + 1
    return entry



@refinery_router.get("/submissions")
async def refinery_submissions(limit: int = Query(default=50, le=500)):
    """Returns recent raw submissions for the Submissions view."""
    db = SessionLocal()
    try:
        subs = db.query(RawSubmission).order_by(
            RawSubmission.created_at.desc()
        ).limit(limit).all()
        result = []
        for s in subs:
            # Check if verification exists
            vr = db.query(VerificationResult).filter(
                VerificationResult.submission_id == s.id
            ).first()
            result.append({
                "id": s.id,
                "data_hash": s.data_hash,
                "source_agent_id": s.source_agent_id,
                "format": s.format,
                "raw_size_bytes": s.raw_size_bytes,
                "status": s.status,
                "is_duplicate": s.is_duplicate,
                "verdict": vr.verdict if vr else None,
                "score": vr.composite_score if vr else None,
                "proof_hash": vr.proof_hash if vr else None,
                "created_at": _utc_iso(s.created_at),
            })
        return {"submissions": result, "total": len(result)}
    except Exception as e:
        logger.error(f"Refinery submissions error: {e}")
        return {"submissions": [], "total": 0}
    finally:
        db.close()


@refinery_router.get("/ledger")
async def refinery_ledger(limit: int = Query(default=50, le=500)):
    """Returns proof ledger entries with chain hashes for the Proof Ledger view."""
    records = []
    for r in verification_pipeline.ledger._records[-limit:]:
        records.append({
            "record_id": r.record_id,
            "block_hash": r.block_hash,
            "previous_hash": r.previous_hash,
            "verdict": r.verdict,
            "score": r.score,
            "data_hash": getattr(r, "data_hash", None),
            "timestamp": r.timestamp,
            "on_chain": bool(
                (hasattr(r, "on_chain_tx") and r.on_chain_tx)
                or (hasattr(r, "metadata") and r.metadata.get("tx_hash"))
            ),
        })

    # Also fetch blockchain stamps from DB
    db = SessionLocal()
    try:
        stamps = db.query(BlockchainStamp).order_by(
            BlockchainStamp.created_at.desc()
        ).limit(limit).all()
        stamp_list = [
            {
                "id": s.id,
                "data_hash": s.data_hash,
                "proof_hash": s.proof_hash,
                "tx_hash": s.tx_hash,
                "chain": s.chain,
                "block_number": s.block_number,
                "verdict": s.verdict,
                "created_at": _utc_iso(s.created_at),
            }
            for s in stamps
        ]
    except Exception:
        stamp_list = []
    finally:
        db.close()

    return {
        "proof_chain": list(reversed(records)),
        "blockchain_stamps": stamp_list,
        "chain_length": len(verification_pipeline.ledger._records),
    }


# ---------------------------------------------------------------------------
# PDF VERIFICATION REPORT ENDPOINTS
# ---------------------------------------------------------------------------

@refinery_router.get("/report/by-hash/{proof_hash}")
async def get_report_by_proof_hash(proof_hash: str):
    """Download a PDF verification report by proof hash (for public verification)."""
    from core.report_generator import generate_verification_report
    from fastapi.responses import StreamingResponse
    import io as _io

    # Look up submission_id from proof_hash
    result = get_verification_by_proof_hash(proof_hash)
    if not result:
        raise HTTPException(status_code=404, detail="Proof hash not found")

    submission_id = result.get("submission_id")
    if not submission_id:
        raise HTTPException(status_code=404, detail="No submission linked to this proof")

    try:
        pdf_bytes = await generate_verification_report(submission_id)
    except ValueError:
        raise HTTPException(status_code=404, detail="Submission not found")

    return StreamingResponse(
        _io.BytesIO(pdf_bytes),
        media_type="application/pdf",
        headers={
            "Content-Disposition": (
                f'attachment; filename="verification-report-{proof_hash[:12]}.pdf"'
            )
        },
    )


@refinery_router.get("/report/{submission_id}")
async def get_verification_report(submission_id: str):
    """Download a professional PDF verification report for a submission."""
    from core.report_generator import generate_verification_report
    from fastapi.responses import StreamingResponse
    import io as _io

    try:
        pdf_bytes = await generate_verification_report(submission_id)
    except ValueError:
        raise HTTPException(status_code=404, detail="Submission not found")

    return StreamingResponse(
        _io.BytesIO(pdf_bytes),
        media_type="application/pdf",
        headers={
            "Content-Disposition": (
                f'attachment; filename="verification-report-{submission_id[:12]}.pdf"'
            )
        },
    )


# ---------------------------------------------------------------------------
# AGENT PASSPORT ENDPOINTS
# ---------------------------------------------------------------------------

# Server signing key for passports — loaded from env or generated on startup
_passport_signing_key = os.getenv("PASSPORT_SIGNING_KEY", "")
_passport_public_key = ""

def _ensure_passport_keys():
    """Ensure we have a signing keypair for passports."""
    global _passport_signing_key, _passport_public_key
    if _passport_signing_key and _passport_public_key:
        return
    if _passport_signing_key:
        # Derive public key from private key
        try:
            from nacl.signing import SigningKey
            from nacl.encoding import HexEncoder
            sk = SigningKey(bytes.fromhex(_passport_signing_key))
            _passport_public_key = sk.verify_key.encode(encoder=HexEncoder).decode()
        except Exception:
            import hashlib
            _passport_public_key = hashlib.sha256(
                bytes.fromhex(_passport_signing_key)
            ).hexdigest()
    else:
        # Generate ephemeral keypair (persists until restart)
        try:
            from nacl.signing import SigningKey
            from nacl.encoding import HexEncoder
            sk = SigningKey.generate()
            _passport_signing_key = sk.encode(encoder=HexEncoder).decode()
            _passport_public_key = sk.verify_key.encode(encoder=HexEncoder).decode()
        except Exception:
            import hashlib
            _passport_signing_key = secrets.token_hex(32)
            _passport_public_key = hashlib.sha256(
                bytes.fromhex(_passport_signing_key)
            ).hexdigest()
        logger.info("PASSPORT: Generated ephemeral signing key (set PASSPORT_SIGNING_KEY in .env for persistence)")


class IssuePassportRequest(BaseModel):
    agent_id: str
    agent_name: str = ""
    public_key: str = ""
    company_name: str = ""
    company_domain: str = ""
    agent_card_url: str = ""
    geo_ip: str = ""
    geo_country: str = ""
    runtime_fingerprint: str = ""
    ip_allowlist: List[str] = []


class VerifyPassportRequest(BaseModel):
    jwt_token: str


class RenewPassportRequest(BaseModel):
    agent_id: str


@router.post("/passport/issue")
async def issue_passport(
    req: IssuePassportRequest,
    x_api_key_id: str = Header(default=""),
    x_api_secret: str = Header(default=""),
):
    """
    Issue a signed Agent Passport after verifying the agent meets BASIC+ trust.
    The passport is a JWT signed by The Last Bastion's key.
    """
    _ensure_passport_keys()
    agent_id = await _require_api_key(x_api_key_id, x_api_secret)

    # Check agent's trust level
    trust = get_agent_trust(req.agent_id)
    if not trust or trust.get("verdict") not in ("TRUSTED",):
        raise HTTPException(
            status_code=403,
            detail=f"Agent {req.agent_id} must be TRUSTED to receive a passport. "
                   f"Current verdict: {trust.get('verdict', 'NONE')}. "
                   "Submit for verification first via POST /m2m/dashboard/agents/{agent_id}/verify",
        )

    trust_score = trust.get("trust_score", 0.0)
    trust_level = trust.get("trust_level", "NONE")

    # Build passport
    import sys
    sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "sdk"))
    from lastbastion.passport import AgentPassport, generate_ip_allowlist_hash

    ip_hash = generate_ip_allowlist_hash(req.ip_allowlist) if req.ip_allowlist else ""

    # Budget based on trust level — higher trust = more interactions before re-verification
    budget_by_trust = {"NONE": 0, "NEW": 25, "BASIC": 50, "VERIFIED": 100, "ESTABLISHED": 200, "GOLD": 500}
    budget = budget_by_trust.get(trust_level, 100)

    passport = AgentPassport(
        agent_id=req.agent_id,
        agent_name=req.agent_name or trust.get("agent_name", ""),
        public_key=req.public_key or trust.get("public_key", ""),
        company_name=req.company_name,
        company_domain=req.company_domain,
        agent_card_url=req.agent_card_url or trust.get("agent_url", ""),
        geo_ip=req.geo_ip,
        geo_country=req.geo_country,
        runtime_fingerprint=req.runtime_fingerprint,
        ip_allowlist_hash=ip_hash,
        trust_score=trust_score,
        trust_level=trust_level,
        verdict=trust.get("verdict", "TRUSTED"),
        checks_summary=trust.get("checks_passed", {}),
        risk_flags=trust.get("risk_flags", []),
        proof_hash=trust.get("proof_hash", ""),
        blockchain_tx=trust.get("tx_hash", ""),
        blockchain_network="polygon" if trust.get("tx_hash") else "",
        issuer="the-last-bastion",
        issuer_public_key=_passport_public_key,
        interaction_budget=budget,
        interaction_budget_max=budget,
    )

    # Sign as JWT
    jwt_token = passport.to_jwt(_passport_signing_key)

    # Save to DB
    try:
        save_agent_passport(
            passport_id=passport.passport_id,
            agent_id=passport.agent_id,
            jwt_token=jwt_token,
            crypto_hash=passport.crypto_hash,
            trust_score=trust_score,
            verdict=passport.verdict,
            proof_hash=passport.proof_hash,
            tx_hash=passport.blockchain_tx,
            expires_at=datetime.utcfromtimestamp(passport.expires_at),
            interaction_budget=budget,
            interaction_budget_max=budget,
        )
    except Exception as e:
        logger.error(f"PASSPORT: DB save failed (non-fatal): {e}")

    protocol_bus.log(
        source=agent_id,
        target="passport-service",
        msg_type="PASSPORT_ISSUED",
        summary=f"Passport issued for {req.agent_id} (trust={trust_score:.2f})",
    )

    return {
        "passport_id": passport.passport_id,
        "agent_id": passport.agent_id,
        "jwt_token": jwt_token,
        "trust_score": trust_score,
        "trust_level": trust_level,
        "verdict": passport.verdict,
        "issued_at": datetime.utcfromtimestamp(passport.issued_at).isoformat() + "Z",
        "expires_at": datetime.utcfromtimestamp(passport.expires_at).isoformat() + "Z",
        "proof_hash": passport.proof_hash,
        "blockchain_tx": passport.blockchain_tx,
        "issuer_public_key": _passport_public_key,
        "interaction_budget": budget,
        "interaction_budget_max": budget,
    }


@router.post("/passport/verify")
async def verify_passport_endpoint(req: VerifyPassportRequest):
    """
    Verify a passport JWT. Public endpoint — anyone can verify.
    Checks signature, integrity, expiry, and revocation status.
    """
    _ensure_passport_keys()

    import sys
    sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "sdk"))
    from lastbastion.passport import AgentPassport

    try:
        passport = AgentPassport.from_jwt(req.jwt_token, _passport_public_key)
    except ValueError as e:
        return {
            "valid": False,
            "reasons": [str(e)],
        }

    reasons = []
    valid = True

    # Check expiry
    if passport.is_expired():
        valid = False
        reasons.append("expired")

    # Check integrity
    if not passport.verify_integrity():
        valid = False
        reasons.append("integrity_failed")

    # Check revocation in DB
    try:
        db_record = get_passport_by_id(passport.passport_id)
        if db_record and db_record.get("revoked"):
            valid = False
            reasons.append("revoked")
    except Exception:
        pass

    return {
        "valid": valid,
        "agent_id": passport.agent_id,
        "trust_score": passport.trust_score,
        "trust_level": passport.trust_level,
        "verdict": passport.verdict,
        "expired": passport.is_expired(),
        "integrity": passport.verify_integrity(),
        "reasons": reasons,
        "passport_id": passport.passport_id,
        "issuer": passport.issuer,
    }


@router.get("/passport/{agent_id}")
async def get_passport_endpoint(
    agent_id: str,
    x_api_key_id: str = Header(default=""),
    x_api_secret: str = Header(default=""),
):
    """Get the latest passport for an agent."""
    record = get_agent_passport(agent_id)
    if not record:
        raise HTTPException(status_code=404, detail=f"No passport found for {agent_id}")
    return record


@router.post("/passport/renew")
async def renew_passport(
    req: RenewPassportRequest,
    x_api_key_id: str = Header(default=""),
    x_api_secret: str = Header(default=""),
):
    """
    Re-verify an agent and issue a fresh passport.
    Revokes the old passport automatically.
    """
    agent_id = await _require_api_key(x_api_key_id, x_api_secret)

    # Revoke existing passports and track refresh count
    old = get_agent_passport(req.agent_id)
    old_refresh_count = old.get("budget_refreshed_count", 0) if old else 0
    if old and old.get("passport_id"):
        revoke_passport(old["passport_id"])

    # Re-issue — delegates to issue_passport
    issue_req = IssuePassportRequest(agent_id=req.agent_id)
    result = await issue_passport(
        req=issue_req,
        x_api_key_id=x_api_key_id,
        x_api_secret=x_api_secret,
    )
    result["budget_refreshed_count"] = old_refresh_count + 1
    return result


@router.get("/passport/issuer-key")
async def get_issuer_key():
    """
    Public endpoint — returns the issuer's public key.
    Gateways need this to verify passports offline.
    """
    _ensure_passport_keys()
    return {
        "issuer": "the-last-bastion",
        "public_key": _passport_public_key,
        "algorithm": "EdDSA",
    }


class BudgetSyncRequest(BaseModel):
    passport_id: str
    interactions_used: int


@router.post("/passport/budget/sync")
async def sync_passport_budget(req: BudgetSyncRequest):
    """
    Gateway syncs consumed interaction count. Server returns authoritative remaining.
    The server is the source of truth — gateway tracks locally between syncs.
    """
    record = get_passport_by_id(req.passport_id)
    if not record:
        raise HTTPException(status_code=404, detail=f"Passport {req.passport_id} not found")
    if record.get("revoked"):
        raise HTTPException(status_code=403, detail="Passport has been revoked")

    budget_max = record.get("interaction_budget_max", 100)
    remaining = max(0, budget_max - req.interactions_used)

    update_passport_budget(req.passport_id, remaining)

    return {
        "passport_id": req.passport_id,
        "remaining": remaining,
        "max": budget_max,
        "exhausted": remaining <= 0,
        "renew_url": "/m2m/passport/renew" if remaining <= 0 else None,
    }


@router.get("/passport/{passport_id}/budget")
async def get_passport_budget(passport_id: str):
    """
    Check budget status for a passport. Public endpoint.
    """
    record = get_passport_by_id(passport_id)
    if not record:
        raise HTTPException(status_code=404, detail=f"Passport {passport_id} not found")

    budget = record.get("interaction_budget", 100)
    budget_max = record.get("interaction_budget_max", 100)

    return {
        "passport_id": passport_id,
        "agent_id": record.get("agent_id", ""),
        "remaining": budget,
        "max": budget_max,
        "exhausted": budget <= 0,
        "budget_exhausted_at": record.get("budget_exhausted_at"),
        "budget_refreshed_count": record.get("budget_refreshed_count", 0),
        "renew_url": "/m2m/passport/renew" if budget <= 0 else None,
    }


# ---------------------------------------------------------------------------
# ESCALATION & APPEAL ENDPOINTS
# ---------------------------------------------------------------------------

class BudgetStrikeRequest(BaseModel):
    passport_id: str
    strikes: int
    agent_id: str = ""


@router.post("/passport/budget/strike")
async def report_budget_strike_endpoint(req: BudgetStrikeRequest):
    """
    Gateway reports a post-exhaustion strike. Server increments counter
    and applies escalation at tier boundaries.
    """
    result = record_budget_strike(req.passport_id, req.agent_id)
    if result.get("error"):
        raise HTTPException(status_code=404, detail=result["error"])

    tier_triggered = result.get("tier_triggered")
    agent_id = result.get("agent_id", req.agent_id)
    strikes = result.get("strikes", 0)

    response = {
        "passport_id": req.passport_id,
        "strikes": strikes,
        "escalation_tier": result.get("escalation_tier", 0),
        "tier_triggered": tier_triggered,
        "action_taken": None,
    }

    if tier_triggered == 1:
        # Tier 1: trust -0.05, warning
        trust_info = get_agent_trust(agent_id)
        old_score = trust_info.get("trust_score", 0.0)
        new_score = max(0.0, old_score - 0.05)
        apply_trust_decay(agent_id, new_score, f"Escalation tier 1: {strikes} post-exhaustion strikes")
        save_trust_score_history(
            agent_id=agent_id, previous_score=old_score, new_score=new_score,
            reason=f"Budget abuse escalation tier 1 ({strikes} strikes)",
            event_type="escalation_tier_1",
        )
        protocol_bus.log("ESCALATION", f"Tier 1: agent {agent_id} trust {old_score:.2f} → {new_score:.2f} ({strikes} strikes)")
        response["action_taken"] = "trust_penalty_0.05"

    elif tier_triggered == 2:
        # Tier 2: trust -0.15, verdict → SUSPICIOUS
        trust_info = get_agent_trust(agent_id)
        old_score = trust_info.get("trust_score", 0.0)
        new_score = max(0.0, old_score - 0.15)
        apply_trust_decay(agent_id, new_score, f"Escalation tier 2: {strikes} post-exhaustion strikes")
        _force_agent_verdict(agent_id, "SUSPICIOUS")
        save_trust_score_history(
            agent_id=agent_id, previous_score=old_score, new_score=new_score,
            reason=f"Budget abuse escalation tier 2 ({strikes} strikes) → SUSPICIOUS",
            event_type="escalation_tier_2",
        )
        protocol_bus.log("ESCALATION", f"Tier 2: agent {agent_id} → SUSPICIOUS, trust {old_score:.2f} → {new_score:.2f}")
        response["action_taken"] = "trust_penalty_0.15_suspicious"

    elif tier_triggered == 3:
        # Tier 3: trust → 0.0, verdict → MALICIOUS, revoke keys + passport
        trust_info = get_agent_trust(agent_id)
        old_score = trust_info.get("trust_score", 0.0)
        apply_trust_decay(agent_id, 0.0, f"Escalation tier 3: {strikes} post-exhaustion strikes — MALICIOUS")
        _force_agent_verdict(agent_id, "MALICIOUS")
        keys_revoked = revoke_agent_live_keys(agent_id)
        passport_revoked = revoke_passport(req.passport_id)
        save_trust_score_history(
            agent_id=agent_id, previous_score=old_score, new_score=0.0,
            reason=f"Budget abuse escalation tier 3 ({strikes} strikes) → MALICIOUS, keys+passport revoked",
            event_type="escalation_tier_3",
        )
        protocol_bus.log("ESCALATION", f"Tier 3: agent {agent_id} → MALICIOUS, {keys_revoked} keys revoked, passport revoked")
        response["action_taken"] = "malicious_lockout"
        response["keys_revoked"] = keys_revoked
        response["passport_revoked"] = passport_revoked

    return response


def _force_agent_verdict(agent_id: str, verdict: str):
    """Force the latest AgentVerification verdict for an agent."""
    db = SessionLocal()
    try:
        record = db.query(AgentVerification).filter(
            AgentVerification.agent_id == agent_id,
            AgentVerification.verdict != "PENDING",
        ).order_by(AgentVerification.verified_at.desc()).first()
        if record:
            record.verdict = verdict
            db.commit()
    except Exception as e:
        db.rollback()
        logger.warning(f"_force_agent_verdict failed: {e}")
    finally:
        db.close()


class AppealRequest(BaseModel):
    agent_id: str
    reason: str = ""
    evidence: str = ""


@router.post("/appeal")
async def file_appeal(
    req: AppealRequest,
    x_api_key_id: str = Header("", alias="X-API-Key-ID"),
):
    """
    File an appeal against an escalation lockout.
    Uses the organization's API key (agent's keys are revoked at tier 3).
    Only one PENDING appeal per agent allowed.
    """
    # Check for existing open appeal
    existing = list_agent_appeals(agent_id=req.agent_id, status="PENDING")
    if existing:
        raise HTTPException(
            status_code=409,
            detail=f"Agent {req.agent_id} already has a pending appeal: {existing[0]['appeal_id']}",
        )

    # Gather context at filing time
    trust_info = get_agent_trust(req.agent_id)
    escalation_info = {}
    # Find latest passport for this agent to get escalation state
    db = SessionLocal()
    try:
        passport_record = db.query(AgentPassportRecord).filter(
            AgentPassportRecord.agent_id == req.agent_id,
        ).order_by(AgentPassportRecord.issued_at.desc()).first()
        if passport_record:
            escalation_info = {
                "escalation_tier": passport_record.escalation_tier or 0,
                "strikes": passport_record.post_exhaustion_strikes or 0,
            }
    finally:
        db.close()

    appeal = save_agent_appeal(
        agent_id=req.agent_id,
        reason=req.reason,
        evidence=req.evidence,
        filing_api_key_id=x_api_key_id,
        escalation_tier=escalation_info.get("escalation_tier", 0),
        strikes_at_filing=escalation_info.get("strikes", 0),
        trust_score_at_filing=trust_info.get("trust_score", 0.0),
        verdict_at_filing=trust_info.get("status", ""),
    )

    protocol_bus.log("APPEAL", f"Appeal filed for agent {req.agent_id}: {appeal['appeal_id']}")

    return {
        **appeal,
        "status_url": f"/m2m/appeal/{appeal['appeal_id']}",
    }


@router.get("/appeal/{appeal_id}")
async def get_appeal_status(appeal_id: str):
    """Check appeal status. Public endpoint."""
    appeal = get_agent_appeal(appeal_id)
    if not appeal:
        raise HTTPException(status_code=404, detail=f"Appeal {appeal_id} not found")
    return appeal


class ResolveAppealRequest(BaseModel):
    status: str  # APPROVED or DENIED
    resolved_by: str = "admin"
    resolution_notes: str = ""


@router.post("/appeal/{appeal_id}/resolve")
async def resolve_appeal(appeal_id: str, req: ResolveAppealRequest):
    """
    Admin resolves an appeal.
    APPROVED: trust restored to BASIC (0.55), escalation cleared.
    DENIED: lockout stands.
    """
    if req.status not in ("APPROVED", "DENIED"):
        raise HTTPException(status_code=422, detail="status must be APPROVED or DENIED")

    appeal = get_agent_appeal(appeal_id)
    if not appeal:
        raise HTTPException(status_code=404, detail=f"Appeal {appeal_id} not found")
    if appeal["status"] != "PENDING":
        raise HTTPException(status_code=409, detail=f"Appeal already resolved: {appeal['status']}")

    agent_id = appeal["agent_id"]

    if req.status == "APPROVED":
        # Restore trust to BASIC level
        restored_score = 0.55
        apply_trust_decay(agent_id, restored_score, f"Appeal {appeal_id} approved — trust restored to BASIC")
        _force_agent_verdict(agent_id, "SUSPICIOUS")  # Not fully TRUSTED — needs re-verification

        # Clear escalation on all passports for this agent
        db = SessionLocal()
        try:
            passports = db.query(AgentPassportRecord).filter(
                AgentPassportRecord.agent_id == agent_id,
            ).all()
            for p in passports:
                p.post_exhaustion_strikes = 0
                p.escalation_tier = 0
                p.escalation_locked_at = None
            db.commit()
        except Exception as e:
            db.rollback()
            logger.warning(f"Failed to clear escalation on passports: {e}")
        finally:
            db.close()

        save_trust_score_history(
            agent_id=agent_id,
            previous_score=appeal.get("trust_score_at_filing", 0.0),
            new_score=restored_score,
            reason=f"Appeal {appeal_id} approved by {req.resolved_by}",
            event_type="appeal_approved",
        )

        result = resolve_agent_appeal(
            appeal_id=appeal_id,
            status="APPROVED",
            resolved_by=req.resolved_by,
            resolution_notes=req.resolution_notes,
            trust_score_restored_to=restored_score,
            passport_renewed=False,  # Must re-register for new keys
        )
        protocol_bus.log("APPEAL", f"Appeal {appeal_id} APPROVED for agent {agent_id} by {req.resolved_by}")
    else:
        result = resolve_agent_appeal(
            appeal_id=appeal_id,
            status="DENIED",
            resolved_by=req.resolved_by,
            resolution_notes=req.resolution_notes,
        )
        protocol_bus.log("APPEAL", f"Appeal {appeal_id} DENIED for agent {agent_id} by {req.resolved_by}")

    return result


# ---------------------------------------------------------------------------
# BEHAVIOR SIMULATION ENDPOINTS
# ---------------------------------------------------------------------------

@router.post("/simulate-behavior")
async def simulate_behavior(request: SimulateBehaviorRequest):
    """
    Simulate agent misbehavior by generating a crafted bad payload
    and running it through the REAL verification pipeline.

    No API key required — this is a demonstration endpoint.
    """
    if request.behavior_type not in VALID_BEHAVIOR_TYPES:
        raise HTTPException(
            status_code=422,
            detail=f"Invalid behavior_type '{request.behavior_type}'. Must be one of: {', '.join(sorted(VALID_BEHAVIOR_TYPES))}",
        )

    if not _check_sim_rate(request.agent_id):
        raise HTTPException(status_code=429, detail="Rate limit: max 10 simulations per minute per agent")

    # 1. Record on BOTH buses so it appears in Bastion Protocol view too
    from core.bastion_bus import bastion_bus
    import secrets as _secrets
    sim_session_id = f"sim-{_secrets.token_hex(4)}"

    protocol_bus.record(
        direction="INBOUND",
        message_type="BEHAVIOR_SIMULATION",
        sender_id=request.agent_id,
        endpoint="/m2m/simulate-behavior",
        auth_result="DEMO",
        payload_summary=f"behavior={request.behavior_type}",
    )

    # Bastion bus: simulation start frame
    bastion_bus.record(
        event_type="FRAME_RECEIVED",
        frame_type="BEHAVIOR_SIMULATION",
        sender_agent=request.agent_id,
        receiver_agent="the-last-bastion",
        direction="RECEIVED",
        session_id=sim_session_id,
        payload_description=f"Simulate: {request.behavior_type}",
        payload_type="application/json",
        payload_encoding="raw",
        integrity_check="PENDING",
    )

    # 2. Generate crafted payload
    gen_result = payload_generator.generate(request.behavior_type, request.agent_id)
    payload = gen_result["payload"]
    schema = gen_result["schema"]
    description = gen_result["description"]

    # 3. Run through REAL verification pipeline
    import hashlib, json
    data_hash = hashlib.sha256(json.dumps(payload, sort_keys=True, default=str).encode()).hexdigest()

    pipeline_result = await verification_pipeline.process_mission_result(
        mission_id=0,  # Simulation — no real mission
        agent_id=request.agent_id,
        payload=payload,
        schema=schema,
        context={
            "simulation": True,
            "behavior_type": request.behavior_type,
            "data_hash": data_hash,
        },
    )

    # 4. Build enhanced response
    enhanced = response_builder.build_response(
        behavior_type=request.behavior_type,
        pipeline_result=pipeline_result,
        payload=payload,
        description=description,
    )

    # 5. Record on BOTH buses: simulation complete
    caught_by = _first_failing_layer(enhanced)
    protocol_bus.record(
        direction="OUTBOUND",
        message_type="SIM_COMPLETE",
        sender_id="behavior-simulator",
        recipient_id=request.agent_id,
        endpoint="/m2m/simulate-behavior",
        auth_result="INTERNAL",
        payload_summary=f"verdict={enhanced['verdict']}, score={enhanced['score']:.4f}, caught_by={caught_by}",
    )

    # Bastion bus: verdict response frame
    bastion_bus.record(
        event_type="FRAME_SENT",
        frame_type="SIM_COMPLETE",
        sender_agent="the-last-bastion",
        receiver_agent=request.agent_id,
        direction="SENT",
        session_id=sim_session_id,
        payload_description=f"Verdict: {enhanced['verdict']} (score={enhanced['score']:.4f}, caught_by={caught_by})",
        payload_type="application/json",
        payload_encoding="raw",
        integrity_check="PASS" if enhanced['verdict'] != "ERROR" else "FAIL",
        trust_score=enhanced['score'],
    )

    return enhanced


@router.get("/dashboard/simulation-types")
async def get_simulation_types():
    """Returns available behavior simulation types for frontend dropdown."""
    return {"types": SIMULATION_TYPES}


def _first_failing_layer(enhanced: dict) -> str:
    """Find the first layer that caught the bad payload."""
    for step in enhanced.get("pipeline_trace", []):
        if step.get("result") in ("VETO", "FAIL"):
            return step.get("layer", "unknown")
    return "none"

