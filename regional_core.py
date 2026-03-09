import os
from fastapi import FastAPI, Header, HTTPException, WebSocket, WebSocketDisconnect
from sqlalchemy import text
from fastapi.middleware.cors import CORSMiddleware
import asyncio
import json
from pydantic import BaseModel
from typing import Set
from datetime import datetime, timedelta
from core.database import (
    init_db, SessionLocal,
    resolve_quarantine, get_refinery_stats,
    get_pending_anchors, approve_anchor, update_anchor_tx,
    ensure_agent_verification_columns,
    get_agents_for_decay, apply_trust_decay, get_agent_rejection_rate,
    revoke_agent_live_keys,
    AgentVerification, PersistentAPIKey,
)
from core.llm_client import LLMClient
from core.agent_simulator import AgentNetwork

# Pydantic models for API requests (were in root state.py)
class ChatRequest(BaseModel):
    message: str

# Global instances
llm = LLMClient()

app = FastAPI(title="The Last Bastion")

# CORS — credentials=False since we use API key headers, not cookies
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=False,
    allow_methods=["GET", "POST", "PUT", "DELETE", "OPTIONS", "PATCH"],
    allow_headers=["*"],
    expose_headers=["*"]
)

agent_network = AgentNetwork()

# M2M Protocol Routers
from core.m2m_router import router as m2m_router, refinery_router
app.include_router(m2m_router)
app.include_router(refinery_router)

# Sandbox Router
from core.sandbox_router import sandbox_router
app.include_router(sandbox_router)

# Demo Agent — expose chat/status/reset on main app via router
try:
    from fastapi import APIRouter as _APIRouter
    from demo_agent.agent import DemoAgent as _DemoAgent
    _demo_agent = _DemoAgent()
    _demo_router = _APIRouter(prefix="/demo-agent", tags=["demo"])

    class _NegotiateRequest(BaseModel):
        category: str
        user_context: str = ""

    @_demo_router.post("/chat")
    async def _demo_chat(request: ChatRequest):
        return await _demo_agent.chat(request.message)

    @_demo_router.post("/negotiate")
    async def _demo_negotiate(request: _NegotiateRequest):
        return await _demo_agent.negotiate(request.category, request.user_context)

    @_demo_router.get("/status")
    async def _demo_status():
        return _demo_agent.get_status()

    @_demo_router.post("/reset")
    async def _demo_reset():
        _demo_agent.reset()
        return {"message": "Conversation and state reset."}

    app.include_router(_demo_router)
    print("  Demo agent routes mounted at /demo-agent")
except Exception as e:
    print(f"  Demo agent not mounted (optional): {e}")

# MCP Server — remote Streamable HTTP for Claude.ai integration
try:
    from core.mcp_server import get_mcp_app
    app.mount("/mcp", get_mcp_app())
except Exception as e:
    print(f"  MCP server not mounted (optional): {e}")


@app.post("/refinery/quarantine/{quarantine_id}/resolve")
async def resolve_quarantine_item(
    quarantine_id: int,
    resolution: str,  # APPROVED or REJECTED
    resolved_by: str = "human",
    x_admin_key: str = Header(default=""),
):
    """
    Human calibration endpoint — resolve a quarantined submission.
    APPROVED: promotes to VERIFIED. REJECTED: discards the data.
    Protected by ADMIN_KEY when set in environment.
    """
    admin_key = os.getenv("ADMIN_KEY", "")
    if admin_key and x_admin_key != admin_key:
        raise HTTPException(status_code=401, detail="Admin authentication required")
    if resolution not in ("APPROVED", "REJECTED"):
        raise HTTPException(status_code=400, detail="resolution must be APPROVED or REJECTED")
    success = resolve_quarantine(quarantine_id, resolution, resolved_by)
    if not success:
        raise HTTPException(status_code=404, detail="Quarantine item not found")
    return {"id": quarantine_id, "resolution": resolution, "resolved_by": resolved_by}


# ---------------------------------------------------------------------------
# HUMAN-IN-THE-LOOP BLOCKCHAIN ANCHORING
# All verdicts queue here. Nothing goes on-chain without human approval.
# ---------------------------------------------------------------------------

@app.get("/anchoring/pending")
async def get_anchor_queue(limit: int = 50):
    """Returns all verification verdicts awaiting human approval for blockchain anchoring."""
    return get_pending_anchors(limit=limit)


@app.post("/anchoring/approve/{stamp_id}")
async def approve_and_anchor(
    stamp_id: int,
    approved_by: str = "human",
    x_admin_key: str = Header(default=""),
):
    """
    Human-in-the-loop: approve a verdict for on-chain anchoring.

    This is the ONLY path to blockchain. No automated stamping.
    The operator reviews the verdict, score, and evidence, then approves.
    The proof hash is then written to the smart contract on Polygon.
    """
    admin_key = os.getenv("ADMIN_KEY", "")
    if admin_key and x_admin_key != admin_key:
        raise HTTPException(status_code=401, detail="Admin authentication required")

    # Mark as approved in DB
    result = approve_anchor(stamp_id, approved_by=approved_by)
    if "error" in result:
        if result["error"] == "not_found":
            raise HTTPException(status_code=404, detail="Blockchain stamp not found")
        if result["error"] == "already_approved":
            return {"status": "already_approved", "tx_hash": result.get("tx_hash")}
        raise HTTPException(status_code=500, detail=result["error"])

    # Attempt the actual blockchain anchor
    tx_receipt = None
    try:
        from core.blockchain_anchor import BlockchainAnchor
        from core.verification.proof_ledger import ProofLedger

        anchor = BlockchainAnchor()
        if anchor.is_connected:
            # Build the ledger (loads from file if exists) and anchor
            ledger = ProofLedger(blockchain_anchor=anchor)
            tx_receipt = ledger.anchor_approved_record(result["proof_hash"])
            if tx_receipt:
                update_anchor_tx(
                    stamp_id,
                    tx_hash=tx_receipt["transactionHash"],
                    block_number=tx_receipt.get("blockNumber"),
                )
    except Exception as e:
        # Approval stands even if anchoring fails (can retry later)
        import logging
        logging.getLogger("Anchoring").error(f"Anchor tx failed (approval recorded): {e}")

    return {
        "status": "approved",
        "stamp_id": stamp_id,
        "approved_by": approved_by,
        "proof_hash": result["proof_hash"],
        "verdict": result["verdict"],
        "tx_hash": tx_receipt["transactionHash"] if tx_receipt else None,
        "blockchain_connected": tx_receipt is not None,
    }


# ---------------------------------------------------------------------------
# WEBSOCKET STREAMING FEED — real-time refinery + protocol events
# ---------------------------------------------------------------------------

_ws_clients: Set[WebSocket] = set()


async def broadcast_event(event: dict):
    """Broadcast a refinery/protocol event to all connected WebSocket clients."""
    global _ws_clients
    if not _ws_clients:
        return
    payload = json.dumps(event)
    dead = set()
    for ws in _ws_clients:
        try:
            await ws.send_text(payload)
        except Exception:
            dead.add(ws)
    _ws_clients -= dead


@app.websocket("/refinery/feed")
async def refinery_feed(websocket: WebSocket):
    """
    WebSocket streaming feed for real-time refinery + protocol events.
    Pushes verification verdicts, quarantine entries, and protocol messages.
    """
    await websocket.accept()
    _ws_clients.add(websocket)
    try:
        # Send initial snapshot
        try:
            stats = get_refinery_stats()
            await websocket.send_text(json.dumps({
                "type": "snapshot",
                "stats": stats,
                "timestamp": datetime.utcnow().isoformat(),
            }))
        except Exception:
            pass

        # Keep connection alive, listen for client pings
        while True:
            try:
                data = await asyncio.wait_for(websocket.receive_text(), timeout=30)
                if data == "ping":
                    await websocket.send_text(json.dumps({"type": "pong"}))
            except asyncio.TimeoutError:
                # Send heartbeat
                try:
                    await websocket.send_text(json.dumps({
                        "type": "heartbeat",
                        "timestamp": datetime.utcnow().isoformat(),
                    }))
                except Exception:
                    break
    except WebSocketDisconnect:
        pass
    finally:
        _ws_clients.discard(websocket)


async def trust_decay_loop():
    """
    Background task: decays trust for inactive agents.
    - Demo mode (DEMO_DECAY_MODE=1): 5-min cycle, 5-min inactivity, -0.05/cycle
    - Normal mode: 1-hour cycle, 7-day inactivity, -0.01/week
    """
    demo_mode = os.environ.get("DEMO_DECAY_MODE", "0") == "1"
    if demo_mode:
        cycle_seconds = 300       # 5 minutes
        inactivity_days = 0.0035  # ~5 minutes in days
        decay_per_cycle = 0.05
        print("TRUST_DECAY: DEMO mode — 5-min cycle, -0.05/cycle")
    else:
        cycle_seconds = 3600      # 1 hour
        inactivity_days = 7
        decay_per_cycle = None    # calculated from weeks
        print("TRUST_DECAY: Normal mode — 1-hour cycle, -0.01/week")

    while True:
        try:
            await asyncio.sleep(cycle_seconds)
            agents = get_agents_for_decay(inactive_days=inactivity_days)
            for agent in agents:
                agent_id = agent["agent_id"]
                current_score = agent["trust_score"]
                last_active = agent.get("last_active_at")

                if demo_mode:
                    decay = decay_per_cycle
                else:
                    # Calculate weeks of inactivity
                    if last_active:
                        inactive_days_actual = (datetime.utcnow() - last_active).days
                    else:
                        inactive_days_actual = 14
                    weeks_inactive = inactive_days_actual / 7
                    decay = 0.01 * weeks_inactive

                new_score = max(0.0, current_score - decay)

                if new_score < current_score:
                    apply_trust_decay(agent_id, new_score, f"Inactivity decay: {inactive_days} days idle")

                    # Auto-revoke if below NEW threshold
                    if new_score < 0.40:
                        revoked = revoke_agent_live_keys(agent_id)
                        if revoked:
                            print(f"TRUST_DECAY: Revoked {revoked} live keys for {agent_id} (score={new_score:.2f})")

            # Anomaly detection: high rejection rate
            db = SessionLocal()
            try:
                all_agents = db.query(AgentVerification).filter(
                    AgentVerification.verdict != "PENDING",
                    AgentVerification.trust_score > 0.40,
                ).all()
                checked_ids = set()
                for record in all_agents:
                    if record.agent_id in checked_ids:
                        continue
                    checked_ids.add(record.agent_id)
                    rejection_rate = get_agent_rejection_rate(record.agent_id, last_n=20)
                    if rejection_rate > 0.50:
                        apply_trust_decay(
                            record.agent_id, 0.42,
                            f"High rejection rate ({rejection_rate:.0%}) — forced re-verification"
                        )
                        print(f"TRUST_DECAY: Forced re-verify for {record.agent_id} (rejection rate={rejection_rate:.0%})")
            except Exception as e:
                print(f"TRUST_DECAY: Anomaly check failed: {e}")
            finally:
                db.close()

        except asyncio.CancelledError:
            break
        except Exception as e:
            print(f"TRUST_DECAY: Loop error: {e}")


def _grandfather_existing_agents():
    """
    Migration: existing agents with live_sk_ keys but no AgentVerification
    get grandfathered at BASIC level (0.55).
    """
    try:
        db = SessionLocal()
        try:
            # Find agents with live keys
            live_keys = db.query(PersistentAPIKey).filter(
                PersistentAPIKey.is_active == True,
                PersistentAPIKey.key_id.like("live_sk_%"),
            ).all()
            grandfathered = 0
            for key in live_keys:
                # Check if they have a verification record
                existing = db.query(AgentVerification).filter(
                    AgentVerification.agent_id == key.agent_id,
                    AgentVerification.verdict != "PENDING",
                ).first()
                if not existing:
                    record = AgentVerification(
                        agent_id=key.agent_id,
                        agent_name=key.agent_id,
                        verdict="TRUSTED",
                        trust_score=0.55,
                        checks_passed={"grandfathered": {"passed": True, "score": 0.55, "detail": "Pre-existing live key"}},
                        verified_at=datetime.utcnow(),
                    )
                    db.add(record)
                    grandfathered += 1
            if grandfathered:
                db.commit()
                print(f"STARTUP: Grandfathered {grandfathered} existing agents at BASIC trust level")
        finally:
            db.close()
    except Exception as e:
        print(f"STARTUP: Grandfather migration skipped: {e}")


@app.on_event("startup")
async def startup_event():
    init_db()
    # Ensure new columns exist on agent_verifications table
    try:
        ensure_agent_verification_columns()
    except Exception as e:
        print(f"STARTUP: Column migration skipped: {e}")
    # Grandfather existing agents
    _grandfather_existing_agents()
    # Warm-load persistent API keys from DB into authenticator cache
    try:
        from core.m2m_router import authenticator
        loaded = authenticator.warm_load_keys()
        if loaded:
            print(f"STARTUP: Warm-loaded {loaded} API keys from DB")
    except Exception as e:
        print(f"STARTUP: API key warm-load skipped: {e}")
    # Recover dashboard agents from DB
    try:
        from core.m2m_router import recover_dashboard_agents
        recover_dashboard_agents()
        print("STARTUP: Dashboard agents recovered from DB")
    except Exception as e:
        print(f"STARTUP: Dashboard agent recovery skipped: {e}")
    # Recover orphaned M2M tasks (queued/running from before restart)
    try:
        from core.m2m_router import recover_orphaned_tasks
        recovered = await recover_orphaned_tasks()
        if recovered:
            print(f"STARTUP: Recovered {recovered} orphaned M2M tasks")
    except Exception as e:
        print(f"STARTUP: Task recovery skipped: {e}")
    # Wire WebSocket broadcast into protocol bus
    try:
        from core.protocol_bus import protocol_bus
        protocol_bus.set_event_callback(broadcast_event)
        print("STARTUP: WebSocket broadcast wired to protocol bus")
    except Exception as e:
        print(f"STARTUP: WebSocket wiring skipped: {e}")
    # Start the live A2A agent network (real agents on ports 9001-9004)
    asyncio.create_task(agent_network.start())
    # Start the adversarial research loop (Red/Blue team, runs continuously)
    try:
        import core.research_loop as _rl
        _rl.research_arena = _rl.ResearchArena()
        asyncio.create_task(_rl.research_arena.start())
        print("STARTUP: Adversarial research loop initialized")
    except Exception as e:
        print(f"STARTUP: Research loop skipped: {e}")
    # Start trust decay background loop (Phase E)
    asyncio.create_task(trust_decay_loop())
    _decay_mode = "DEMO (5-min cycles)" if os.environ.get("DEMO_DECAY_MODE", "0") == "1" else "normal (hourly)"
    print(f"STARTUP: Trust decay loop initialized ({_decay_mode})")


@app.get("/")
def read_root():
    return {"status": "The Last Bastion — Running"}


@app.get("/health")
def health_check():
    """System health check — used by the frontend System Overview."""
    import redis as redis_lib
    db_ok = False
    redis_ok = False
    db = SessionLocal()
    try:
        db.execute(text("SELECT 1"))
        db_ok = True
    except Exception:
        pass
    finally:
        db.close()
    try:
        r = redis_lib.Redis(
            host=os.environ.get("REDIS_HOST", "localhost"),
            port=int(os.environ.get("REDIS_PORT", 6379)),
            socket_timeout=2,
        )
        r.ping()
        redis_ok = True
        r.close()
    except Exception:
        pass
    return {
        "status": "healthy" if db_ok else "degraded",
        "database": "connected" if db_ok else "disconnected",
        "redis": "connected" if redis_ok else "disconnected",
        "agent_network": "running" if hasattr(agent_network, "_running") and agent_network._running else "standby",
        "timestamp": datetime.utcnow().isoformat(),
    }


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)
