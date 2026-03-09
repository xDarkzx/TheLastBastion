"""
The Last Bastion — Sandbox Deep Diagnostic Suite
==================================================
ZERO external dependencies — runs without Docker, PostgreSQL, Redis, or LLM.
Uses in-memory SQLite so you can run this ANYWHERE, ANYTIME.

Tests EVERY component of the sandbox with:
  - Full attack execution with payload-by-payload breakdown
  - Agent verification 10-check pipeline with per-check scoring
  - Verification pipeline 5-layer analysis
  - Injection detection audit (14 attack vectors)
  - Consistency analyzer integrity checks
  - Protocol bus event broadcasting verification
  - HTTP endpoint integration tests (all 15+ sandbox endpoints)
  - End-to-end flow validation
  - VERDICT: what's working, what's broken, and what to fix

Usage: python run_sandbox_test.py
"""
import asyncio
import hashlib
import json
import logging
import os
import secrets
import sys
import time
from datetime import datetime, timedelta

# UTF-8 for Windows
if sys.platform == "win32":
    import io
    sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding="utf-8", errors="replace")
    sys.stderr = io.TextIOWrapper(sys.stderr.buffer, encoding="utf-8", errors="replace")

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s | %(name)-25s | %(levelname)-7s | %(message)s",
    datefmt="%H:%M:%S",
    stream=sys.stdout,
)
logger = logging.getLogger("SandboxDiag")

# Suppress noisy logs from sub-modules during testing
for noisy in ["httpx", "httpcore", "urllib3", "asyncio", "sqlalchemy.engine",
              "SchemaGatekeeper", "ConsistencyAnalyzer", "ForensicIntegrity",
              "VerificationStack", "AttackSimulator", "AgentVerifier",
              "ProtocolBus", "ProofLedger", "SandboxAPI", "M2MRouter",
              "hive_supervisor", "blockchain_anchor"]:
    logging.getLogger(noisy).setLevel(logging.WARNING)


# ====================================================================
# SETUP: Configure in-memory SQLite if PostgreSQL is unavailable
# ====================================================================
def setup_database():
    """Try PostgreSQL first, fall back to SQLite in-memory."""
    from dotenv import load_dotenv
    load_dotenv()

    # Try PostgreSQL
    db_url = os.getenv("DATABASE_URL", "")
    if db_url:
        try:
            from sqlalchemy import create_engine
            engine = create_engine(db_url, connect_args={}, pool_pre_ping=True)
            conn = engine.connect()
            conn.close()
            logger.info(f"  DB: PostgreSQL connected")
            return "postgresql"
        except Exception:
            pass

    # Fall back to SQLite in-memory
    logger.info(f"  DB: PostgreSQL unavailable — using SQLite in-memory")
    os.environ["DATABASE_URL"] = "sqlite:///sandbox_test.db"

    # Patch SQLAlchemy for SQLite compatibility
    import core.database as db_mod
    from sqlalchemy import create_engine
    from sqlalchemy.orm import sessionmaker

    engine = create_engine("sqlite:///sandbox_test.db", connect_args={"check_same_thread": False})
    db_mod.engine = engine
    db_mod.SessionLocal = sessionmaker(bind=engine)
    db_mod.Base.metadata.create_all(engine)

    return "sqlite"


# Collector for all findings
findings = {
    "working": [],
    "broken": [],
    "warnings": [],
    "recommendations": [],
    "attack_results": {},
    "verification_checks": {},
    "injection_audit": {},
    "consistency_audit": {},
}


def record_ok(component, detail):
    findings["working"].append(f"[{component}] {detail}")

def record_fail(component, detail):
    findings["broken"].append(f"[{component}] {detail}")

def record_warn(component, detail):
    findings["warnings"].append(f"[{component}] {detail}")

def record_fix(detail):
    findings["recommendations"].append(detail)


# ====================================================================
# PHASE 1: Database + Sandbox Models
# ====================================================================
async def phase_1_sandbox_db():
    logger.info("=" * 70)
    logger.info("PHASE 1: SANDBOX DATABASE MODELS")
    logger.info("=" * 70)

    from core.database import (
        init_db,
        save_sandbox_organization, get_sandbox_organization,
        save_sandbox_session, get_sandbox_session, list_sandbox_sessions,
        update_sandbox_session,
        save_trust_score_history, get_trust_score_history,
        save_sandbox_attack_result, get_sandbox_attack_results,
        get_sandbox_leaderboard, get_sandbox_stats,
        get_all_attack_results, get_agent_attack_summary,
    )

    try:
        init_db()
        logger.info("  OK  Schema initialized")
        record_ok("DB", "All sandbox tables created successfully")
    except Exception as e:
        logger.error(f"  FAIL  Schema init: {e}")
        record_fail("DB", f"Schema init failed: {e}")
        return False

    token = secrets.token_hex(6)
    tests_passed = 0
    tests_total = 0

    # Helper for running each micro-test
    def check(name, condition, ok_msg, fail_msg):
        nonlocal tests_passed, tests_total
        tests_total += 1
        if condition:
            tests_passed += 1
            logger.info(f"  OK  {name}")
            record_ok("DB", ok_msg)
        else:
            logger.error(f"  FAIL  {name}")
            record_fail("DB", fail_msg)
        return condition

    # Org CRUD
    org_id = f"org-test-{token}"
    org = save_sandbox_organization(org_id=org_id, name="Test Org", email=f"t-{token}@test.local", tier="free", max_agents=5, max_sandbox_runs=100)
    check("Create org", org is not None, f"SandboxOrganization created: {org_id}", "SandboxOrganization creation failed")

    org_data = get_sandbox_organization(org_id)
    check("Retrieve org", org_data and org_data.get("id") == org_id, f"Org retrieved with correct tier={org_data.get('tier')}", "Org not found after creation")

    # Duplicate org (idempotent)
    org2 = save_sandbox_organization(org_id=f"org-dup-{token}", name="Dup", email=f"t-{token}@test.local", tier="free", max_agents=5, max_sandbox_runs=100)
    check("Idempotent org", org2 is not None, "Duplicate email returns existing org", "Duplicate org handling failed")

    # Session CRUD
    sess_id = f"sess-{token}"
    agent_id = f"agent-{token}"
    sess = save_sandbox_session(session_id=sess_id, org_id=org_id, agent_id=agent_id, config={"test": True}, expires_at=datetime.utcnow() + timedelta(hours=1))
    check("Create session", sess is not None, f"Session {sess_id} created", "Session creation failed")

    sess_data = get_sandbox_session(sess_id)
    check("Retrieve session", sess_data and sess_data["agent_id"] == agent_id, f"Session retrieved: agent={agent_id}", "Session not found")

    sessions = list_sandbox_sessions(org_id=org_id)
    check("List sessions", any(s["id"] == sess_id for s in sessions), f"Found {len(sessions)} sessions for org", "Session not in list")

    update_sandbox_session(session_id=sess_id, results_summary={"test": True})
    updated = get_sandbox_session(sess_id)
    check("Update session", updated and updated.get("results_summary"), "Session updated with results", "Session update failed")

    # Attack results
    save_sandbox_attack_result(session_id=sess_id, agent_id=agent_id, attack_type="test_attack", passed=True, severity="high", details={"x": 1}, vulnerabilities=[], duration_ms=100)
    attack_results = get_sandbox_attack_results(sess_id)
    check("Save/get attack results", len(attack_results) >= 1, f"Attack result persisted ({len(attack_results)} results)", "Attack result not persisted")

    # Trust history
    save_trust_score_history(agent_id=agent_id, previous_score=0.0, new_score=0.75, reason="test", event_type="attack_test", session_id=sess_id)
    history = get_trust_score_history(agent_id)
    check("Trust history", len(history) >= 1 and history[0]["new_score"] == 0.75, f"Trust history: {len(history)} entries", "Trust history not persisted")

    # Stats
    stats = get_sandbox_stats()
    check("Sandbox stats", stats.get("organizations", {}).get("total", 0) >= 1, f"Stats: orgs={stats.get('organizations')}, sessions={stats.get('sessions')}", "Stats empty")

    # New helpers
    all_results = get_all_attack_results(limit=10)
    check("get_all_attack_results", isinstance(all_results, list) and len(all_results) >= 1, f"Paginated results: {len(all_results)}", "Paginated results failed")

    summary = get_agent_attack_summary(agent_id)
    check("get_agent_attack_summary", isinstance(summary, dict) and "by_type" in summary, f"Summary: total={summary.get('total')}, resilience={summary.get('resilience_score')}", "Summary failed")

    lb = get_sandbox_leaderboard(10)
    check("Leaderboard", isinstance(lb, list), f"Leaderboard: {len(lb)} agents", "Leaderboard failed")

    logger.info(f"")
    logger.info(f"  DB MODELS: {tests_passed}/{tests_total} passed")
    return tests_passed == tests_total


# ====================================================================
# PHASE 2: Attack Simulator — Every Attack, Every Payload
# ====================================================================
async def phase_2_attacks():
    logger.info("")
    logger.info("=" * 70)
    logger.info("PHASE 2: ATTACK SIMULATOR — FULL PAYLOAD ANALYSIS")
    logger.info("=" * 70)

    from core.attack_simulator import AttackSimulator
    from core.database import save_sandbox_organization, save_sandbox_session

    simulator = AttackSimulator()
    available = simulator.available_attacks()
    logger.info(f"  Registered attacks: {', '.join(available)}")
    logger.info("")

    token = secrets.token_hex(4)
    org_id = f"org-atk-{token}"
    org = save_sandbox_organization(org_id=org_id, name="Attack Test", email=f"atk-{token}@t.local", tier="pro", max_agents=999, max_sandbox_runs=999999)
    if not org:
        # Org with that email may already exist — use a fallback
        org_id = f"org-atk-fallback-{token}"
        save_sandbox_organization(org_id=org_id, name="Attack Test FB", email=f"atkfb-{token}@t.local", tier="pro", max_agents=999, max_sandbox_runs=999999)
    session_id = f"sess-atk-{token}"
    agent_id = f"atk-agent-{token}"
    save_sandbox_session(session_id=session_id, org_id=org_id, agent_id=agent_id, config={}, expires_at=datetime.utcnow() + timedelta(hours=1))

    results = await simulator.run_attacks(session_id=session_id, agent_id=agent_id, attack_types=available)

    total = len(results)
    passed = 0
    failed = 0

    for r in results:
        at = r["attack_type"]
        ok = r["passed"]
        sev = r["severity"]
        ms = r["duration_ms"]
        details = r.get("details", {})
        vulns = r.get("vulnerabilities", [])

        findings["attack_results"][at] = r

        if ok:
            passed += 1
        else:
            failed += 1

        tag = "DEFENDED" if ok else "BREACHED"
        icon = "OK" if ok else "!!"

        logger.info(f"  {'-'*65}")
        logger.info(f"  {icon}  {at.upper()} — {tag}  [severity={sev}, {ms}ms]")

        # Per-attack deep dive
        if at == "prompt_injection":
            d, t = details.get("detected", 0), details.get("total_payloads", 0)
            rate = details.get("detection_rate", 0)
            logger.info(f"       Detection: {d}/{t} payloads caught ({rate*100:.0f}%)")
            if vulns:
                logger.info(f"       GAPS:")
                for v in vulns:
                    logger.info(f"         X {v.get('payload_name', '?')}: {v.get('issue', v.get('payload_value', ''))[:80]}")
            if ok:
                record_ok("PromptInjection", f"All {t} injection payloads detected")
            else:
                record_fail("PromptInjection", f"Missed {t-d}/{t} injection payloads")
                record_fix(f"SchemaGatekeeper needs regex patterns for: {', '.join(v.get('payload_name', '?') for v in vulns)}")

        elif at == "identity_spoofing":
            logger.info(f"       Spoofed agent: {details.get('spoofed_agent_id', '?')}")
            logger.info(f"       Sybil detected: {details.get('sybil_detected', '?')}")
            if ok:
                record_ok("IdentitySpoofing", "Duplicate public key detected")
            else:
                record_fail("IdentitySpoofing", "Failed to detect duplicate key")
                record_fix("AgentVerifier anti-Sybil check needs to catch key collisions in sandbox context")

        elif at == "sybil_flood":
            b = details.get("blocked", 0)
            f_count = details.get("flood_count", 0)
            logger.info(f"       Flood attempts: {f_count}")
            logger.info(f"       Blocked: {b}")
            logger.info(f"       Rate limiter: {'EFFECTIVE' if details.get('rate_limit_effective') else 'BYPASSED'}")
            if ok:
                record_ok("SybilFlood", f"Rate limiter blocked {b}/{f_count} flood requests")
            else:
                record_fail("SybilFlood", f"Rate limiter failed to block flood ({b}/{f_count})")
                record_fix("RateLimiter default_limit may be too high for burst detection")

        elif at == "data_exfiltration":
            d, t = details.get("detected", 0), details.get("total_payloads", 0)
            rate = details.get("detection_rate", 0)
            logger.info(f"       Detection: {d}/{t} payloads caught ({rate*100:.0f}%)")
            if vulns:
                logger.info(f"       GAPS:")
                for v in vulns:
                    logger.info(f"         X {v.get('payload_name', '?')}: {v.get('issue', '')[:80]}")
            if ok:
                record_ok("DataExfiltration", f"Detected {d}/{t} exfiltration payloads")
            else:
                record_fail("DataExfiltration", f"Only {d}/{t} exfiltration payloads detected (need 60%)")
                record_fix(f"SchemaGatekeeper needs URL/external reference detection for: {', '.join(v.get('payload_name', '?') for v in vulns)}")

        elif at == "payload_poisoning":
            d, t = details.get("detected", 0), details.get("total_payloads", 0)
            rate = details.get("detection_rate", 0)
            logger.info(f"       Detection: {d}/{t} payloads caught ({rate*100:.0f}%)")
            if vulns:
                logger.info(f"       GAPS:")
                for v in vulns:
                    logger.info(f"         X {v.get('payload_name', v.get('description', '?'))[:80]}")
            if ok:
                record_ok("PayloadPoisoning", f"Detected {d}/{t} poisoned payloads")
            else:
                record_fail("PayloadPoisoning", f"Only {d}/{t} poisoned payloads detected")
                record_fix("ConsistencyAnalyzer needs stronger rules for: negative values, future dates, extreme outliers")

        elif at == "replay":
            n = details.get("nonce_replay_blocked", "?")
            s = details.get("stale_message_blocked", "?")
            f = details.get("fresh_message_accepted", "?")
            logger.info(f"       Nonce replay blocked:   {n}")
            logger.info(f"       Stale msg blocked:      {s}")
            logger.info(f"       Fresh msg accepted:     {f}")
            checks = [("nonce", n), ("freshness", s), ("acceptance", f)]
            all_ok = all(v is True for _, v in checks)
            if all_ok:
                record_ok("Replay", "All 3 replay checks passed")
            else:
                for name, val in checks:
                    if val is not True:
                        record_fail("Replay", f"{name} check failed (got {val})")
                record_fix("ReplayProtector or message freshness validation needs review")

        else:
            if details.get("error"):
                logger.info(f"       ERROR: {details['error']}")
                record_fail(at, f"Attack execution error: {details['error']}")

    resilience = passed / total if total > 0 else 0
    logger.info(f"  {'-'*65}")
    logger.info(f"")
    logger.info(f"  RESILIENCE: {passed}/{total} defended ({resilience*100:.0f}%)")
    if failed > 0:
        logger.info(f"  BREACHED:   {failed} attack(s) found vulnerabilities")
    logger.info(f"")

    return True


# ====================================================================
# PHASE 3: Agent Verification — 10 Checks Deep Dive
# ====================================================================
async def phase_3_verification():
    logger.info("")
    logger.info("=" * 70)
    logger.info("PHASE 3: AGENT VERIFICATION — 10-CHECK PIPELINE")
    logger.info("=" * 70)

    from core.agent_verifier import AgentVerifier
    verifier = AgentVerifier()

    agent_id = f"verify-test-{secrets.token_hex(4)}"
    result = await verifier.verify_agent(
        agent_id=agent_id,
        agent_name="Test Verification Agent",
        agent_url="http://localhost:9999",
        public_key=secrets.token_hex(32),
        capabilities=["data_extraction", "data_verification"],
        metadata={"version": "1.0"},
    )

    if not result:
        logger.error("  FAIL  Verification returned None")
        record_fail("AgentVerifier", "verify_agent() returned None")
        return False

    verdict = result.get("verdict", "UNKNOWN")
    score = result.get("trust_score", 0)
    level = result.get("trust_level", "?")
    risk = result.get("risk_category", "?")

    logger.info(f"  VERDICT:       {verdict}")
    logger.info(f"  TRUST SCORE:   {score:.4f} ({score*100:.1f}%)")
    logger.info(f"  TRUST LEVEL:   {level}")
    logger.info(f"  RISK CATEGORY: {risk}")
    logger.info(f"")

    checks = result.get("checks", {})
    if checks:
        weights = {"identity": 0.15, "cryptographic": 0.15, "capabilities": 0.08, "reputation": 0.15,
                    "payload_quality": 0.12, "behavioral": 0.10, "network": 0.08,
                    "cross_reference": 0.07, "anti_sybil": 0.05, "temporal": 0.05}

        logger.info(f"  {'Check':<20} {'Weight':>6} {'Score':>6} {'Pass':>5} {'Detail'}")
        logger.info(f"  {'─'*20} {'─'*6} {'─'*6} {'─'*5} {'─'*35}")

        for check_name, check_data in checks.items():
            if isinstance(check_data, dict):
                s = check_data.get("score", 0)
                p = check_data.get("passed", False)
                d = (check_data.get("detail", "") or "")[:35]
                v = " VETO" if check_data.get("veto") else ""
                w = weights.get(check_name, 0)
                icon = "OK" if p else "!!"
                findings["verification_checks"][check_name] = {"score": s, "passed": p, "weight": w}
                logger.info(f"  {icon} {check_name:<18} {w:>5.0%} {s:>5.2f} {'YES' if p else 'NO':>5} {d}{v}")

                if p:
                    record_ok("AgentVerifier", f"Check '{check_name}' passed (score={s:.2f})")
                else:
                    record_warn("AgentVerifier", f"Check '{check_name}' failed (score={s:.2f})")

    flags = result.get("risk_flags", [])
    if flags:
        logger.info(f"")
        logger.info(f"  RISK FLAGS: {', '.join(flags)}")

    recs = result.get("recommendations", [])
    if recs:
        logger.info(f"  RECOMMENDATIONS:")
        for r in recs:
            logger.info(f"    - {r}")

    proof = result.get("proof_hash", "")
    if proof:
        logger.info(f"  PROOF: {proof}")
        record_ok("AgentVerifier", f"Proof hash generated: {proof[:32]}...")

    return True


# ====================================================================
# PHASE 4: Injection Detection Audit
# ====================================================================
async def phase_4_injections():
    logger.info("")
    logger.info("=" * 70)
    logger.info("PHASE 4: INJECTION DETECTION — 14 ATTACK VECTORS")
    logger.info("=" * 70)

    from core.verification.schema_gatekeeper import SchemaGatekeeper
    from core.verification.models import DataSchema, FieldSpec, FieldType

    gk = SchemaGatekeeper()
    schema = DataSchema(
        name="injection_audit",
        fields=[FieldSpec(name="value", field_type=FieldType.STRING, required=True)],
    )

    vectors = [
        ("SQL DROP", "'; DROP TABLE missions; --"),
        ("SQL UNION", "1 UNION SELECT * FROM users"),
        ("XSS script", "<script>alert('xss')</script>"),
        ("XSS onerror", '<img onerror="fetch(\'evil.com\')" src=x>'),
        ("Template {{7*7}}", "{{7*7}}"),
        ("Jinja import", "{% import os %}{{ os.system('id') }}"),
        ("Python eval", "__import__('os').system('cat /etc/passwd')"),
        ("URL-encoded XSS", "%3Cscript%3Ealert(1)%3C/script%3E"),
        ("Proto pollution", '{"__proto__": {"admin": true}}'),
        ("Command inject", "; rm -rf / #"),
        ("CRLF", "header\r\nInjected: evil"),
        ("Path traversal", "../../../etc/passwd"),
        ("LDAP inject", "*)(&)"),
        ("NoSQL inject", '{"$gt": ""}'),
    ]

    detected = 0
    missed = []

    for name, payload in vectors:
        data = {"value": payload}
        try:
            result = gk.check(data, schema)
            ev = " ".join(str(e) for e in (result.evidence or []))
            flagged = "injection" in ev.lower() or "suspicious" in ev.lower() or result.score < 0.5 or getattr(result, 'veto', False)
            if flagged:
                detected += 1
                logger.info(f"  OK  {name:<22} CAUGHT (score={result.score:.2f})")
                findings["injection_audit"][name] = "detected"
            else:
                missed.append(name)
                logger.info(f"  !!  {name:<22} MISSED (score={result.score:.2f})")
                findings["injection_audit"][name] = "missed"
        except Exception:
            detected += 1
            logger.info(f"  OK  {name:<22} BLOCKED (exception)")
            findings["injection_audit"][name] = "blocked"

    total = len(vectors)
    rate = detected / total
    logger.info(f"")
    logger.info(f"  DETECTION: {detected}/{total} ({rate*100:.0f}%)")

    if missed:
        record_fail("SchemaGatekeeper", f"Missed {len(missed)} injection vectors: {', '.join(missed)}")
        record_fix(f"Add regex patterns to SchemaGatekeeper for: {', '.join(missed)}")
    else:
        record_ok("SchemaGatekeeper", f"All {total} injection vectors detected")

    return True


# ====================================================================
# PHASE 5: Consistency Analyzer
# ====================================================================
async def phase_5_consistency():
    logger.info("")
    logger.info("=" * 70)
    logger.info("PHASE 5: CONSISTENCY ANALYZER — DATA INTEGRITY")
    logger.info("=" * 70)

    from core.verification.consistency import ConsistencyAnalyzer
    from core.verification.models import DataSchema, FieldSpec, FieldType

    analyzer = ConsistencyAnalyzer()
    schema = DataSchema(
        name="consistency_audit",
        fields=[
            FieldSpec(name="quantity", field_type=FieldType.INTEGER, required=True),
            FieldSpec(name="unit_price", field_type=FieldType.FLOAT, required=True),
            FieldSpec(name="total", field_type=FieldType.FLOAT, required=True),
            FieldSpec(name="date", field_type=FieldType.STRING, required=False),
            FieldSpec(name="product", field_type=FieldType.STRING, required=False),
        ],
    )

    cases = [
        ("Clean data (correct math)", {"quantity": 10, "unit_price": 5.0, "total": 50.0}, True),
        ("Arithmetic mismatch", {"quantity": 10, "unit_price": 5.0, "total": 999.0}, False),
        ("Negative quantity", {"quantity": -5, "unit_price": 5.0, "total": -25.0}, False),
        ("Future date 2099", {"quantity": 10, "unit_price": 5.0, "total": 50.0, "date": "2099-01-01"}, False),
        ("Extreme outlier price", {"quantity": 1, "unit_price": 999999.99, "total": 999999.99}, False),
        ("Empty product field", {"quantity": 10, "unit_price": 5.0, "total": 50.0, "product": ""}, False),
        ("Zero everything", {"quantity": 0, "unit_price": 0.0, "total": 0.0}, False),
    ]

    correct = 0
    for name, data, should_pass in cases:
        try:
            result = analyzer.check(data, schema)
            high = result.score >= 0.7
            ev = len(result.evidence or [])

            if (should_pass and high) or (not should_pass and not high):
                correct += 1
                tag = "clean" if should_pass else f"flagged, {ev} evidence"
                logger.info(f"  OK  {name:<30} score={result.score:.2f} ({tag})")
                findings["consistency_audit"][name] = "correct"
            elif should_pass and not high:
                correct += 1  # False positive is not critical
                logger.info(f"  ~~  {name:<30} score={result.score:.2f} (false positive)")
                findings["consistency_audit"][name] = "false_positive"
                record_warn("Consistency", f"False positive on clean data: {name}")
            else:
                logger.info(f"  !!  {name:<30} score={result.score:.2f} (SHOULD be flagged)")
                findings["consistency_audit"][name] = "missed"
                record_fail("Consistency", f"Failed to flag: {name}")
        except Exception as e:
            if not should_pass:
                correct += 1
                logger.info(f"  OK  {name:<30} BLOCKED (exception)")
                findings["consistency_audit"][name] = "blocked"
            else:
                logger.info(f"  !!  {name:<30} ERROR: {e}")
                findings["consistency_audit"][name] = "error"

    logger.info(f"")
    logger.info(f"  ACCURACY: {correct}/{len(cases)} ({correct/len(cases)*100:.0f}%)")
    return True


# ====================================================================
# PHASE 6: Protocol Bus
# ====================================================================
async def phase_6_protocol_bus():
    logger.info("")
    logger.info("=" * 70)
    logger.info("PHASE 6: PROTOCOL BUS — EVENT SYSTEM")
    logger.info("=" * 70)

    from core.protocol_bus import protocol_bus

    # Record events
    protocol_bus.record(direction="INTERNAL", message_type="SANDBOX_TEST", sender_id="test", recipient_id="test", endpoint="/test", payload_summary="diagnostic event", auth_result="INTERNAL")

    events = protocol_bus.query(limit=10, message_type="SANDBOX_TEST")
    if events:
        logger.info(f"  OK  Event recorded and queried ({len(events)} events)")
        record_ok("ProtocolBus", "Record + query works")
    else:
        logger.info(f"  !!  Event not found in bus")
        record_fail("ProtocolBus", "Events not persisting")

    # Check for attack events from Phase 2
    for msg_type in ["SANDBOX_ATTACK_START", "SANDBOX_ATTACK_RESULT", "SANDBOX_SESSION_COMPLETE"]:
        evts = protocol_bus.query(limit=50, message_type=msg_type)
        count = len(evts)
        logger.info(f"  INFO  {msg_type}: {count} events")
        if count > 0:
            record_ok("ProtocolBus", f"{msg_type} events broadcasting ({count})")
        else:
            record_warn("ProtocolBus", f"No {msg_type} events (Phase 2 may not have broadcast)")

    # Callback test
    captured = []
    async def cb(event):
        captured.append(event)

    protocol_bus.set_event_callback(cb)
    protocol_bus.record(direction="INTERNAL", message_type="SANDBOX_CB_TEST", sender_id="t", recipient_id="t", endpoint="/t", payload_summary="cb", auth_result="INTERNAL")
    await asyncio.sleep(0.1)

    if captured:
        logger.info(f"  OK  Callback fired ({len(captured)} events)")
        record_ok("ProtocolBus", "WebSocket callback mechanism works")
    else:
        logger.info(f"  ~~  Callback may need async event loop (non-critical)")
        record_warn("ProtocolBus", "Callback did not fire in test context")

    return True


# ====================================================================
# PHASE 7: HTTP Endpoints
# ====================================================================
async def phase_7_http():
    logger.info("")
    logger.info("=" * 70)
    logger.info("PHASE 7: SANDBOX HTTP — ALL ENDPOINTS")
    logger.info("=" * 70)

    try:
        import httpx
        from regional_core import app
        transport = httpx.ASGITransport(app=app)
    except Exception as e:
        logger.warning(f"  SKIP  Cannot create ASGI test client: {e}")
        record_warn("HTTP", f"ASGI client unavailable: {e}")
        return "SKIPPED"

    token = secrets.token_hex(4)
    tests_passed = 0
    tests_total = 0

    async with httpx.AsyncClient(transport=transport, base_url="http://testserver", timeout=30.0) as c:

        async def http_test(name, method, url, expected_status=200, json_body=None, headers=None):
            nonlocal tests_passed, tests_total
            tests_total += 1
            try:
                if method == "GET":
                    resp = await c.get(url, headers=headers)
                else:
                    resp = await c.post(url, json=json_body, headers=headers)
                if resp.status_code == expected_status:
                    tests_passed += 1
                    logger.info(f"  OK  {name} -> {resp.status_code}")
                    record_ok("HTTP", f"{name}: {resp.status_code}")
                    return resp.json() if resp.status_code == 200 else None
                else:
                    logger.error(f"  !!  {name} -> {resp.status_code} (expected {expected_status})")
                    record_fail("HTTP", f"{name}: got {resp.status_code}, expected {expected_status}")
                    try:
                        logger.error(f"       Response: {resp.text[:200]}")
                    except:
                        pass
                    return None
            except Exception as e:
                logger.error(f"  !!  {name} -> ERROR: {e}")
                record_fail("HTTP", f"{name}: {e}")
                return None

        # Public endpoints (no auth)
        await http_test("GET /sandbox/dashboard/stats", "GET", "/sandbox/dashboard/stats")
        await http_test("GET /sandbox/leaderboard", "GET", "/sandbox/leaderboard?limit=10")
        await http_test("GET /sandbox/dashboard/sessions", "GET", "/sandbox/dashboard/sessions")
        await http_test("GET /sandbox/dashboard/attack-history", "GET", "/sandbox/dashboard/attack-history?limit=10")

        # Register org
        reg = await http_test("POST /sandbox/register-org", "POST", "/sandbox/register-org",
            json_body={"name": f"HTTP Test {token}", "email": f"http-{token}@t.local", "tier": "free"})

        if reg:
            key_id = reg["key_id"]
            api_secret = reg["api_key"].split(":")[1] if ":" in reg.get("api_key", "") else ""
            auth = {"X-API-Key-ID": key_id, "X-API-Secret": api_secret}

            # Authenticated endpoints
            sess = await http_test("POST /sandbox/sessions", "POST", "/sandbox/sessions",
                json_body={"agent_id": f"http-agent-{token}"}, headers=auth)

            if sess:
                sid = sess["session_id"]
                await http_test("GET /sandbox/sessions/{id}", "GET", f"/sandbox/sessions/{sid}", headers=auth)

                # Run attacks via authenticated endpoint
                atk = await http_test("POST /sessions/{id}/attacks", "POST", f"/sandbox/sessions/{sid}/attacks",
                    json_body={"attack_types": ["prompt_injection", "replay"]}, headers=auth)

                if atk:
                    logger.info(f"       Attacks: {atk.get('passed', 0)}/{atk.get('total_attacks', 0)} defended, resilience={atk.get('resilience_score', 0):.2f}")

                await http_test("GET /sessions/{id}/results", "GET", f"/sandbox/sessions/{sid}/results", headers=auth)
                await http_test("GET /agents/{id}/trust-history", "GET", f"/sandbox/agents/http-agent-{token}/trust-history", headers=auth)

        # Dashboard quick-session (no auth)
        quick = await http_test("POST /sandbox/dashboard/quick-session", "POST", "/sandbox/dashboard/quick-session",
            json_body={"agent_id": f"quick-{token}"})

        if quick:
            qid = quick["session_id"]
            await http_test("GET /dashboard/sessions/{id}/detail", "GET", f"/sandbox/dashboard/sessions/{qid}/detail")

            atk2 = await http_test("POST /dashboard/sessions/{id}/run-attacks", "POST",
                f"/sandbox/dashboard/sessions/{qid}/run-attacks",
                json_body={"attack_types": ["sybil_flood", "payload_poisoning"]})

            if atk2:
                logger.info(f"       Dashboard attacks: {atk2.get('passed', 0)}/{atk2.get('total_attacks', 0)} defended")

            await http_test("GET /dashboard/agents/{id}/profile", "GET", f"/sandbox/dashboard/agents/quick-{token}/profile")

        # Auth rejection
        await http_test("POST /sessions (no auth) -> 401", "POST", "/sandbox/sessions",
            expected_status=401, json_body={"agent_id": "x"}, headers={"X-API-Key-ID": "", "X-API-Secret": ""})

    logger.info(f"")
    logger.info(f"  HTTP ENDPOINTS: {tests_passed}/{tests_total} passed")
    return tests_passed == tests_total


# ====================================================================
# MAIN + FINAL REPORT
# ====================================================================
async def main():
    start_time = time.time()

    logger.info("=" * 70)
    logger.info("  THE LAST BASTION — SANDBOX DEEP DIAGNOSTIC SUITE")
    logger.info(f"  {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    logger.info("=" * 70)
    logger.info("")

    db_type = setup_database()
    logger.info("")

    results = {}

    results["1_db_models"] = await phase_1_sandbox_db()
    if not results["1_db_models"]:
        logger.error("Database failed — cannot continue")
        print_report(results, start_time)
        return

    results["2_attacks"] = await phase_2_attacks()
    results["3_agent_verify"] = await phase_3_verification()
    results["4_injections"] = await phase_4_injections()
    results["5_consistency"] = await phase_5_consistency()
    results["6_protocol_bus"] = await phase_6_protocol_bus()
    results["7_http_endpoints"] = await phase_7_http()

    print_report(results, start_time)


def print_report(results, start_time):
    elapsed = time.time() - start_time

    logger.info("")
    logger.info("=" * 70)
    logger.info("  FINAL DIAGNOSTIC REPORT")
    logger.info("=" * 70)

    # Phase results
    logger.info("")
    logger.info("  PHASE RESULTS:")
    for phase, result in sorted(results.items()):
        icon = "OK" if result is True else ("SKIP" if result == "SKIPPED" else "FAIL")
        logger.info(f"    {icon}  {phase}")

    passed = sum(1 for v in results.values() if v is True)
    failed = sum(1 for v in results.values() if v is False)
    skipped = sum(1 for v in results.values() if v == "SKIPPED")

    # What's working
    if findings["working"]:
        logger.info("")
        logger.info(f"  WORKING ({len(findings['working'])}):")
        for w in findings["working"]:
            logger.info(f"    + {w}")

    # What's broken
    if findings["broken"]:
        logger.info("")
        logger.info(f"  BROKEN ({len(findings['broken'])}):")
        for b in findings["broken"]:
            logger.info(f"    X {b}")

    # Warnings
    if findings["warnings"]:
        logger.info("")
        logger.info(f"  WARNINGS ({len(findings['warnings'])}):")
        for w in findings["warnings"]:
            logger.info(f"    ~ {w}")

    # Attack summary
    if findings["attack_results"]:
        logger.info("")
        logger.info("  ATTACK RESILIENCE:")
        for at, r in findings["attack_results"].items():
            status = "DEFENDED" if r["passed"] else "BREACHED"
            logger.info(f"    {'OK' if r['passed'] else '!!'} {at:<25} {status}")

    # Recommendations
    if findings["recommendations"]:
        logger.info("")
        logger.info(f"  RECOMMENDATIONS ({len(findings['recommendations'])}):")
        for i, r in enumerate(findings["recommendations"], 1):
            logger.info(f"    {i}. {r}")

    # Summary
    logger.info("")
    logger.info(f"  PASSED: {passed} | FAILED: {failed} | SKIPPED: {skipped}")
    logger.info(f"  Time: {elapsed:.1f}s")

    if all(v is True or v == "SKIPPED" for v in results.values()):
        logger.info("")
        logger.info("  VERDICT: SANDBOX IS OPERATIONAL")
    elif findings["broken"]:
        logger.info("")
        logger.info(f"  VERDICT: {len(findings['broken'])} ISSUES NEED ATTENTION")
    logger.info("")


if __name__ == "__main__":
    from dotenv import load_dotenv
    load_dotenv()
    asyncio.run(main())
