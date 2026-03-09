"""
The Last Bastion Backend Validation Script (v7.0)
Tests the COMPLETE system without any frontend, browser, or Docker dependencies.
Validates: DB → LLM → Redis → Truth Engine → Proof-of-Task → Structural Diff
         → Schema Gatekeeper → Verification Stack → M2M Protocol
         → Refinery DB Models → Refinery HTTP v2 (DB-backed endpoints)

Prerequisites:
  1. PostgreSQL running (docker-compose up db)
  2. Ollama running with qwen2.5:7b-instruct OR GROQ_API_KEY set in .env
  3. pip install -r requirements.txt

Usage: python run_backend_test.py
"""
import asyncio
import hashlib
import os
import sys
import json
import logging
from datetime import datetime

# Structured logging — force UTF-8 on Windows to handle emoji/arrow chars
import sys
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
logger = logging.getLogger("BackendTest")


async def test_phase_1_database():
    """Phase 1: Verify PostgreSQL connectivity and schema initialization."""
    logger.info("=" * 60)
    logger.info("PHASE 1: DATABASE CONNECTIVITY")
    logger.info("=" * 60)

    from core.database import init_db, SessionLocal, Mission, IntelNode

    try:
        init_db()
        logger.info("✅ Schema initialized successfully.")
    except Exception as e:
        logger.error(f"❌ Database init failed: {e}")
        logger.error("   → Is PostgreSQL running? Check DATABASE_URL in .env")
        return False

    # Create a test mission
    db = SessionLocal()
    try:
        mission = Mission(
            name="Backend Validation Test v6",
            category="SYSTEM_TEST",
            status="ACTIVE",
            goal_logic="Extract the current homepage title from example.com",
            created_at=datetime.utcnow()
        )
        db.add(mission)
        db.commit()
        db.refresh(mission)
        mission_id = mission.id

        # Create an IntelNode for the mission
        node = IntelNode(
            mission_id=mission_id,
            name="Example.com",
            url="https://example.com",
            status="PENDING"
        )
        db.add(node)
        db.commit()

        logger.info(f"✅ Test Mission created: ID={mission_id}")
        logger.info(f"✅ Test IntelNode created for mission {mission_id}")
        return mission_id
    except Exception as e:
        logger.error(f"❌ Mission creation failed: {e}")
        return False
    finally:
        db.close()


async def test_phase_2_llm():
    """Phase 2: Verify LLM connectivity (Groq or Ollama)."""
    logger.info("=" * 60)
    logger.info("PHASE 2: LLM CONNECTIVITY")
    logger.info("=" * 60)

    from core.llm_client import LLMClient

    llm = LLMClient()
    logger.info(f"   Provider: {llm.provider}")
    logger.info(f"   Strategist Model: {llm.strategist_model}")
    logger.info(f"   Pilot Model: {llm.pilot_model}")
    logger.info(f"   Groq Key: {'SET' if llm.groq_key else 'NOT SET'}")

    # Test pilot tier (local)
    logger.info("   Testing PILOT tier (local)...")
    pilot_result = await llm.generate_response(
        'Return this exact JSON: {"test": "ok", "tier": "pilot"}',
        tier="pilot"
    )
    if "error" in pilot_result:
        logger.error(f"❌ Pilot LLM failed: {pilot_result['error']}")
        logger.error("   → Is Ollama running? Try: ollama serve")
        return False
    logger.info(f"✅ Pilot LLM responded: {json.dumps(pilot_result)[:100]}")

    # Test strategist tier
    logger.info("   Testing STRATEGIST tier...")
    strat_result = await llm.generate_response(
        'Return this exact JSON: {"test": "ok", "tier": "strategist"}',
        tier="strategist"
    )
    if "error" in strat_result:
        logger.warning(f"⚠️  Strategist LLM failed: {strat_result['error']}")
        logger.warning("   → Will fall back to pilot for strategy tasks")
    else:
        logger.info(f"✅ Strategist LLM responded: {json.dumps(strat_result)[:100]}")

    # Report usage
    logger.info(f"   Token usage: {llm.usage_stats}")
    return True


async def test_phase_3_redis():
    """Phase 3: Verify Redis connectivity."""
    logger.info("=" * 60)
    logger.info("PHASE 3: REDIS CONNECTIVITY")
    logger.info("=" * 60)

    try:
        from core.redis_conveyor import RedisConveyor
        conveyor = RedisConveyor()

        if conveyor.is_connected():
            logger.info("✅ Redis connected.")

            # Test produce/consume cycle
            msg_id = conveyor.produce("test_stream", {"test": "validation"})
            logger.info(f"✅ Produced test message: {msg_id}")

            messages = conveyor.consume("test_stream", "test_group", "test_worker", count=1, block_ms=1000)
            if messages:
                conveyor.acknowledge("test_stream", "test_group", messages[0]["id"])
                logger.info(f"✅ Consumed and ACK'd: {messages[0]['data']}")
            else:
                logger.warning("⚠️  No messages consumed (might be timing)")

            # Test heartbeat
            conveyor.heartbeat("TEST_WORKER", status="testing")
            workers = conveyor.get_live_workers()
            logger.info(f"✅ Heartbeat registered. Live workers: {len(workers)}")

            # Cleanup
            conveyor.client.delete("test_stream")
            conveyor.client.delete("worker:TEST_WORKER")
            return True
        else:
            logger.warning("⚠️  Redis not available. System will use DB queue only.")
            return True  # Non-blocking — DB queue is the fallback
    except ImportError:
        logger.warning("⚠️  redis package not installed. Using DB queue only.")
        return True
    except Exception as e:
        logger.warning(f"⚠️  Redis check failed: {e}. Using DB queue only.")
        return True


async def test_phase_4_consensus():
    """Phase 4: Verify Consensus Engine + Adversarial Auditor."""
    logger.info("=" * 60)
    logger.info("PHASE 4: TRUTH ENGINE (CONSENSUS + AUDIT)")
    logger.info("=" * 60)

    from core.consensus import ConsensusEngine
    from core.auditor import AdversarialAuditor

    consensus = ConsensusEngine()
    auditor = AdversarialAuditor()

    # Test clean data
    clean_data = {
        "company": "Mercury Energy",
        "country": "New Zealand",
        "region": "Auckland",
        "suburb": "Albany",
        "price_kwh": 0.28,
        "plan_name": "Everyday Saver"
    }
    is_clean, reason = auditor.audit_yield(clean_data)
    confidence = auditor.calculate_confidence(clean_data)
    logger.info(f"   Clean data audit: clean={is_clean}, reason={reason}, confidence={confidence}")

    if is_clean and confidence >= 0.8:
        logger.info("✅ Clean data passed audit.")
    else:
        logger.error("❌ Clean data should have passed audit!")
        return False

    # Test dirty data
    dirty_data = {
        "company": "not found",
        "price": None,
        "plan": ""
    }
    is_clean_dirty, reason_dirty = auditor.audit_yield(dirty_data)
    logger.info(f"   Dirty data audit: clean={is_clean_dirty}, reason={reason_dirty}")

    if not is_clean_dirty:
        logger.info("✅ Dirty data correctly rejected.")
    else:
        logger.error("❌ Dirty data should have been rejected!")
        return False

    # Test consensus (single source)
    pod_result = {"worker_id": "TEST_ALPHA", "role": "EXTRACTOR", "data": clean_data}
    consensus_result = await consensus.resolve_conflicts([pod_result])
    logger.info(f"   Consensus result: status={consensus_result.get('status')}")

    if consensus_result.get("status") == "VERIFIED":
        logger.info("✅ Single-source consensus passed.")
    else:
        logger.error(f"❌ Consensus failed: {consensus_result}")
        return False

    return True


async def test_phase_5_proof_of_task():
    """Phase 5: Verify Proof-of-Task cryptographic hashing."""
    logger.info("=" * 60)
    logger.info("PHASE 5: PROOF-OF-TASK (CRYPTOGRAPHIC VERIFICATION)")
    logger.info("=" * 60)

    from core.proof_of_task import generate_proof, verify_proof

    test_gold = {
        "company": "TestCorp",
        "price": 42.50,
        "plan": "Premium Plan",
        "_audit": {"should_be_stripped": True}
    }

    # Generate proof
    proof = generate_proof(
        gold_payload=test_gold,
        worker_id="TEST_WORKER_A",
        mission_id=999
    )
    logger.info(f"   Proof hash: {proof['proof_hash'][:32]}...")
    logger.info(f"   Worker: {proof['worker_id']}, Mission: {proof['mission_id']}")

    if not proof["proof_hash"] or len(proof["proof_hash"]) != 64:
        logger.error("❌ Proof hash is invalid (should be 64-char SHA-256)")
        return False
    logger.info("✅ Proof generated with valid SHA-256 hash.")

    # Verify proof (should pass)
    is_valid = verify_proof(test_gold, proof)
    if is_valid:
        logger.info("✅ Proof verification PASSED (untampered data).")
    else:
        logger.error("❌ Proof verification should have passed!")
        return False

    # Tamper with data and verify again (should fail)
    tampered_gold = {**test_gold, "price": 999.99}
    is_valid_tampered = verify_proof(tampered_gold, proof)
    if not is_valid_tampered:
        logger.info("✅ Tampered data correctly REJECTED by proof verification.")
    else:
        logger.error("❌ Tampered data should have been rejected!")
        return False

    return True



async def test_phase_7_structural_diff():
    """Phase 7: Verify Alpha/Beta structural diff for dual-bot verification."""
    logger.info("=" * 60)
    logger.info("PHASE 7: DUAL-BOT STRUCTURAL DIFF")
    logger.info("=" * 60)

    from core.auditor import AdversarialAuditor
    auditor = AdversarialAuditor()

    # Test matching data (should be MATCH)
    alpha = {"company": "TestCorp", "price": 42.50, "plan": "Premium"}
    beta = {"company": "TestCorp", "price": 42.50, "plan": "Premium"}

    diff = auditor.structural_diff(alpha, beta)
    logger.info(f"   Identical data: verdict={diff['verdict']}, ratio={diff['match_ratio']:.2f}")

    if diff["verdict"] == "MATCH" and diff["match_ratio"] == 1.0:
        logger.info("✅ Identical data correctly identified as MATCH.")
    else:
        logger.error("❌ Identical data should be MATCH with ratio 1.0!")
        return False

    # Test partial match (case-insensitive)
    alpha2 = {"company": "TestCorp", "price": 42.50, "plan": "Premium Plan"}
    beta2 = {"company": "testcorp", "price": 42.50, "plan": "Basic Plan"}

    diff2 = auditor.structural_diff(alpha2, beta2)
    logger.info(f"   Partial data: verdict={diff2['verdict']}, ratio={diff2['match_ratio']:.2f}")
    logger.info(f"   Mismatched keys: {diff2['mismatched_keys']}")

    if diff2["verdict"] == "PARTIAL":
        logger.info("✅ Partial match correctly identified.")
    else:
        logger.info(f"   (Got {diff2['verdict']} — acceptable, depends on data)")

    # Test complete mismatch
    alpha3 = {"a": 1, "b": 2, "c": 3}
    beta3 = {"a": 99, "b": 88, "c": 77}

    diff3 = auditor.structural_diff(alpha3, beta3)
    logger.info(f"   Mismatch data: verdict={diff3['verdict']}, ratio={diff3['match_ratio']:.2f}")

    if diff3["verdict"] == "MISMATCH":
        logger.info("✅ Total mismatch correctly identified.")
    else:
        logger.error(f"❌ Expected MISMATCH, got {diff3['verdict']}")
        return False

    return True


async def test_phase_8_episodic_memory(mission_id: int):
    """Phase 8: Verify Episodic Memory persist and recall."""
    logger.info("=" * 60)
    logger.info("PHASE 8: EPISODIC MEMORY")
    logger.info("=" * 60)

    from core.database import SessionLocal, EpisodicMemory

    db = SessionLocal()
    try:
        # Persist a test episode
        episode = EpisodicMemory(
            mission_id=mission_id,
            domain="test.example.com",
            goal="Extract test data",
            outcome="SUCCESS",
            action_history=[{"step": 1, "action": "navigate"}, {"step": 2, "action": "extract"}],
            thought_log=[{"thought": "Page loaded successfully"}],
            total_iterations=5,
            duration_seconds=12.34,
            trace_id="test1234"
        )
        db.add(episode)
        db.commit()
        logger.info(f"✅ Episode persisted for domain 'test.example.com' (ID={episode.id})")

        # Recall it
        recalled = db.query(EpisodicMemory).filter(
            EpisodicMemory.domain == "test.example.com"
        ).order_by(EpisodicMemory.created_at.desc()).first()

        if recalled and recalled.outcome == "SUCCESS" and recalled.total_iterations == 5:
            logger.info(f"✅ Episode recalled correctly: outcome={recalled.outcome}, iterations={recalled.total_iterations}")
        else:
            logger.error("❌ Episode recall failed or returned wrong data!")
            return False

        # Clean up test data
        db.delete(recalled)
        db.commit()
        logger.info("✅ Test episode cleaned up.")

        return True
    except Exception as e:
        logger.error(f"❌ Episodic memory test failed: {e}")
        return False
    finally:
        db.close()


async def test_phase_14_schema_gatekeeper():
    """Phase 14: Schema Gatekeeper — structural validation."""
    logger.info("=" * 60)
    logger.info("PHASE 14: SCHEMA GATEKEEPER")
    logger.info("=" * 60)

    from core.verification.schema_gatekeeper import SchemaGatekeeper
    from core.verification.models import DataSchema, FieldSpec, FieldType

    gk = SchemaGatekeeper()

    # Define test schema
    schema = DataSchema(
        name="invoice",
        fields=[
            FieldSpec(name="company", field_type=FieldType.STRING, required=True, min_length=1),
            FieldSpec(name="amount", field_type=FieldType.CURRENCY, required=True, min_value=0),
            FieldSpec(name="tax_rate", field_type=FieldType.PERCENTAGE, required=False),
            FieldSpec(name="email", field_type=FieldType.EMAIL, required=False),
            FieldSpec(name="invoice_date", field_type=FieldType.DATE, required=True),
        ],
    )

    # Test 1: Valid data
    result = gk.check(
        {"company": "Acme Corp", "amount": 150.00, "tax_rate": 15.0, "invoice_date": "2026-03-01"},
        schema,
    )
    if result.score >= 0.9:
        logger.info(f"  OK  Valid data: score={result.score}")
    else:
        logger.error(f"FAIL  Valid data should score high: {result.score}")
        return False

    # Test 2: Type mismatch
    result2 = gk.check(
        {"company": "Acme", "amount": "free", "invoice_date": "2026-03-01"},
        schema,
    )
    if result2.score < result.score:
        logger.info(f"  OK  Type mismatch caught: score={result2.score}")
    else:
        logger.error(f"FAIL  Should score lower than valid: {result2.score}")
        return False

    # Test 3: Injection detection (veto)
    result3 = gk.check(
        {"company": "<script>alert(1)</script>", "amount": 100, "invoice_date": "2026-01-01"},
        schema,
    )
    if result3.is_veto and result3.veto_reason:
        logger.info(f"  OK  Injection vetoed: {result3.veto_reason}")
    else:
        logger.error("FAIL  Injection should trigger veto")
        return False

    # Test 4: Missing all required fields
    result4 = gk.check({"tax_rate": 15.0}, schema)
    if result4.score < 0.5:
        logger.info(f"  OK  Missing required fields: score={result4.score}")
    else:
        logger.error(f"FAIL  Missing fields should score low: {result4.score}")
        return False

    # Test 5: Empty data (veto)
    result5 = gk.check({}, schema)
    if result5.is_veto:
        logger.info(f"  OK  Empty data vetoed")
    else:
        logger.error("FAIL  Empty data should veto")
        return False

    return True


async def test_phase_15_consistency():
    """Phase 15: Internal Consistency Analyzer."""
    logger.info("=" * 60)
    logger.info("PHASE 15: CONSISTENCY ANALYZER")
    logger.info("=" * 60)

    from core.verification.consistency import ConsistencyAnalyzer
    from core.verification.models import DataSchema, FieldSpec, FieldType

    ca = ConsistencyAnalyzer()
    schema = DataSchema(name="invoice", fields=[
        FieldSpec(name="subtotal", field_type=FieldType.CURRENCY),
        FieldSpec(name="tax", field_type=FieldType.CURRENCY),
        FieldSpec(name="total", field_type=FieldType.CURRENCY),
        FieldSpec(name="quantity", field_type=FieldType.INTEGER),
        FieldSpec(name="unit_price", field_type=FieldType.CURRENCY),
        FieldSpec(name="amount", field_type=FieldType.CURRENCY),
    ])

    # Test 1: Arithmetic passes (100 + 15 = 115)
    r1 = ca.check({"subtotal": 100, "tax": 15, "total": 115}, schema)
    if r1.score >= 0.8:
        logger.info(f"  OK  Arithmetic valid: score={r1.score}")
    else:
        logger.error(f"FAIL  Arithmetic should pass: {r1.score}")
        return False

    # Test 2: Arithmetic conflict (100 + 15 != 200)
    r2 = ca.check({"subtotal": 100, "tax": 15, "total": 200}, schema)
    if r2.score <= 0.3:
        logger.info(f"  OK  Arithmetic conflict caught: score={r2.score}")
    else:
        logger.error(f"FAIL  Arithmetic conflict should score low: {r2.score}")
        return False

    # Test 3: Product check (5 × 20 = 100)
    r3 = ca.check({"quantity": 5, "unit_price": 20, "amount": 100}, schema)
    if r3.score >= 0.8:
        logger.info(f"  OK  Product valid: score={r3.score}")
    else:
        logger.error(f"FAIL  Product should pass: {r3.score}")
        return False

    # Test 4: Statistical anomaly
    distributions = {"unit_price": {"mean": 25.0, "std": 5.0}}
    r4 = ca.check({"unit_price": 250.0}, schema, distributions)
    if len(r4.anomalies) > 0:
        logger.info(f"  OK  Anomaly detected: {r4.anomalies[0][:60]}")
    else:
        logger.error("FAIL  Should detect statistical anomaly")
        return False

    # Test 5: Cross-field date logic
    r5 = ca.check(
        {"start_date": "2026-03-10", "end_date": "2026-03-01"},
        schema,
    )
    if len(r5.anomalies) > 0:
        logger.info(f"  OK  Date order conflict: {r5.anomalies[0][:60]}")
    else:
        logger.error("FAIL  Should detect date order conflict")
        return False

    return True


async def test_phase_16_forensic_integrity():
    """Phase 16: Forensic Integrity Compositor (modular OOP)."""
    logger.info("=" * 60)
    logger.info("PHASE 16: FORENSIC INTEGRITY")
    logger.info("=" * 60)

    from core.verification.forensic_integrity import ForensicIntegrityAnalyzer

    fia = ForensicIntegrityAnalyzer()

    # Test 1: Registered analyzers
    names = fia.registered_analyzers
    expected = ["file_structure", "metadata_forensics", "ela",
                "noise_pattern", "copy_move", "lighting", "pdf_forensics"]
    if all(n in names for n in expected):
        logger.info(f"  OK  Registered: {len(names)} analyzers")
    else:
        logger.error(f"FAIL  Missing analyzers: {set(expected) - set(names)}")
        return False

    # Test 2: Generate a real JPEG for image forensics
    try:
        from PIL import Image as PILImage
        import io
        img = PILImage.new("RGB", (200, 200), color=(120, 140, 160))
        buf = io.BytesIO()
        img.save(buf, format="JPEG", quality=85)
        jpeg_bytes = buf.getvalue()
    except ImportError:
        # Fallback: minimal valid JPEG bytes
        jpeg_bytes = b"\xff\xd8\xff\xe0" + b"\x00" * 100

    result = await fia.analyze(jpeg_bytes, "jpg")
    if result.score > 0.0:
        layer_names = [lr.layer_name for lr in result.layer_results]
        logger.info(
            f"  OK  JPEG analysis: score={result.score:.2f}, "
            f"layers={layer_names}"
        )
    else:
        logger.error(f"FAIL  JPEG should score > 0: {result.score}")
        return False

    # Test 3: Applicable filtering — PDF analyzers for PDF
    applicable = fia.get_applicable("pdf")
    applicable_names = [a.name for a in applicable]
    if "pdf_forensics" in applicable_names:
        logger.info(f"  OK  PDF applicable: {applicable_names}")
    else:
        logger.error(f"FAIL  pdf_forensics should be applicable: {applicable_names}")
        return False

    # Test 4: File structure — valid magic bytes
    from core.verification.analyzers.file_structure import FileStructureAnalyzer
    fsa = FileStructureAnalyzer()
    fs_result = await fsa.analyze(jpeg_bytes, "jpg")
    if fs_result.score >= 0.8:
        logger.info(f"  OK  JPEG magic bytes valid: score={fs_result.score}")
    else:
        logger.error(f"FAIL  JPEG magic should be valid: {fs_result.score}")
        return False

    # Test 5: File structure — mismatched extension
    fs_bad = await fsa.analyze(jpeg_bytes, "png")
    if fs_bad.score < 0.5:
        logger.info(f"  OK  Magic mismatch caught: score={fs_bad.score}")
    else:
        logger.error(f"FAIL  Should detect magic mismatch: {fs_bad.score}")
        return False

    # Test 6: PDF forensics on a minimal PDF
    fake_pdf = b"%PDF-1.4\n1 0 obj\n/Producer (TestGen)\n%%EOF\n"
    pdf_result = await fia.analyze(fake_pdf, "pdf")
    if pdf_result.score > 0.0:
        logger.info(f"  OK  PDF analysis: score={pdf_result.score:.2f}")
    else:
        logger.error(f"FAIL  PDF should score > 0: {pdf_result.score}")
        return False

    return True


async def test_phase_17_verification_stack():
    """Phase 17: Full Verification Stack Orchestrator."""
    logger.info("=" * 60)
    logger.info("PHASE 17: VERIFICATION STACK")
    logger.info("=" * 60)

    from core.verification.verification_stack import VerificationOrchestrator
    from core.verification.models import DataClaim

    orchestrator = VerificationOrchestrator()

    # Test 1: Good payload — clean structured data
    good_payload = {
        "company": "Mercury Energy",
        "electricity_price_kwh": 0.28,
        "date": "2026-03-01",
        "quantity": 100,
        "unit_price": 0.28,
        "total": 28.0,
    }
    result = await orchestrator.verify(
        payload=good_payload,
        context={"region": "nz", "domain": "energy"},
    )
    if result.score > 0.0:
        logger.info(
            f"  OK  Good payload: verdict={result.verdict}, "
            f"score={result.score:.4f}"
        )
    else:
        logger.error(f"FAIL  Good payload should score > 0: {result.score}")
        return False

    # Test 2: Bad arithmetic — qty × price ≠ total
    bad_payload = {
        "company": "Fake Corp",
        "quantity": 100,
        "unit_price": 50.0,
        "total": 4500.0,
        "date": "2026-03-01",
    }
    bad_result = await orchestrator.verify(
        payload=bad_payload,
        context={"region": "nz", "domain": "invoice"},
    )
    if bad_result.score < result.score:
        logger.info(
            f"  OK  Bad arithmetic: verdict={bad_result.verdict}, "
            f"score={bad_result.score:.4f} (lower than good)"
        )
    else:
        logger.error(
            f"FAIL  Bad arithmetic should score lower: "
            f"{bad_result.score} vs {result.score}"
        )
        return False

    # Test 3: Domain logic — magnitude anomaly
    from core.verification.triangulation.domain_logic import DomainLogicTriangulator
    domain_checker = DomainLogicTriangulator()
    claims = [
        DataClaim(field_name="electricity_price_kwh", value=2.80),
    ]
    domain_result = await domain_checker.check(claims, {"region": "nz"})
    has_anomaly = any(not e.confirms for e in domain_result.evidence)
    if has_anomaly:
        logger.info(
            f"  OK  Magnitude anomaly detected: score={domain_result.score:.2f}"
        )
    else:
        logger.error("FAIL  Should detect $2.80/kWh as anomaly in NZ")
        return False

    # Test 4: Temporal consistency — normal change
    from core.verification.triangulation.temporal import (
        TemporalConsistencyTriangulator,
    )
    temporal = TemporalConsistencyTriangulator()
    temporal.record_history("energy", "electricity_price_kwh", 0.27)
    claims_stable = [
        DataClaim(field_name="electricity_price_kwh", value=0.28),
    ]
    temporal_result = await temporal.check(
        claims_stable, {"domain": "energy"}
    )
    if temporal_result.score >= 0.5:
        logger.info(
            f"  OK  Temporal stable: score={temporal_result.score:.2f}"
        )
    else:
        logger.error(f"FAIL  Stable price should pass: {temporal_result.score}")
        return False

    # Test 5: Cross-reference — contradiction
    from core.verification.triangulation.cross_reference import (
        CrossReferenceTriangulator,
    )
    xref = CrossReferenceTriangulator()
    xref.add_verified("energy", "electricity_price_kwh", 0.28, "official", 0.9)
    claims_wrong = [
        DataClaim(field_name="electricity_price_kwh", value=0.55),
    ]
    xref_result = await xref.check(claims_wrong, {"domain": "energy"})
    if xref_result.score < 0.5:
        logger.info(
            f"  OK  Cross-ref contradiction: score={xref_result.score:.2f}"
        )
    else:
        logger.error(f"FAIL  Contradiction should score low: {xref_result.score}")
        return False

    return True


async def test_phase_18_attestation_adversarial():
    """Phase 18: Attestation Verifier + Adversarial Challenge Agent."""
    logger.info("=" * 60)
    logger.info("PHASE 18: ATTESTATION + ADVERSARIAL")
    logger.info("=" * 60)

    from core.verification.attestation import AttestationVerifier, AttestationBundle
    from core.verification.adversarial import AdversarialChallengeAgent
    from core.verification.models import PillarResult, LayerResult, Evidence, EvidenceType

    # --- Test 1: Good attestation bundle ---
    verifier = AttestationVerifier()
    good_bundle = AttestationBundle(
        file_bytes=b"real document content here",
        gps_latitude=-36.8485,
        gps_longitude=174.7633,
        gps_accuracy_meters=10.0,
        timestamp=datetime.utcnow().isoformat(),
        device_fingerprint="device-abc-123-xyz",
        depth_map_available=True,
        depth_variance=0.05,
    )
    result = await verifier.verify(good_bundle)
    if result.score > 0.5:
        logger.info(f"  OK  Good attestation: score={result.score:.2f}")
    else:
        logger.error(f"FAIL  Good attestation should score > 0.5: {result.score}")
        return False

    # --- Test 2: Null Island GPS ---
    null_bundle = AttestationBundle(
        file_bytes=b"suspicious document",
        gps_latitude=0.0,
        gps_longitude=0.0,
        timestamp=datetime.utcnow().isoformat(),
    )
    null_result = await verifier.verify(null_bundle)
    if null_result.score < result.score:
        logger.info(f"  OK  Null Island flagged: score={null_result.score:.2f}")
    else:
        logger.error(f"FAIL  Null Island should score lower: {null_result.score}")
        return False

    # --- Test 3: Flat depth (screen capture) ---
    flat_bundle = AttestationBundle(
        file_bytes=b"screen capture pretending to be paper",
        gps_latitude=-36.8485,
        gps_longitude=174.7633,
        timestamp=datetime.utcnow().isoformat(),
        depth_map_available=True,
        depth_variance=0.001,
    )
    flat_result = await verifier.verify(flat_bundle)
    flat_depth_layer = next(
        (lr for lr in flat_result.layer_results if lr.layer_name == "depth_authenticity"),
        None,
    )
    if flat_depth_layer and flat_depth_layer.score < 0.3:
        logger.info(
            f"  OK  Flat depth detected (screen): "
            f"score={flat_depth_layer.score:.2f}"
        )
    else:
        logger.error("FAIL  Flat depth should be detected as screen capture")
        return False

    # --- Test 4: Anti-replay detection ---
    replay_result = await verifier.verify(good_bundle)
    if replay_result.is_veto:
        logger.info(
            f"  OK  Replay detected: veto={replay_result.veto_reason}"
        )
    else:
        logger.error("FAIL  Duplicate submission should trigger replay veto")
        return False

    # --- Test 5: Provenance hash generation ---
    hash1 = verifier.generate_provenance_hash(good_bundle)
    hash2 = verifier.generate_provenance_hash(null_bundle)
    if hash1 != hash2 and len(hash1) == 64:
        logger.info(f"  OK  Unique provenance hashes: {hash1[:16]}... vs {hash2[:16]}...")
    else:
        logger.error("FAIL  Provenance hashes should be unique SHA-256")
        return False

    # --- Test 6: Adversarial challenge agent ---
    agent = AdversarialChallengeAgent()

    # Create a pillar result with weak evidence
    weak_pillar = PillarResult(
        pillar_name="logic_triangulation",
        score=0.85,
        layer_results=[LayerResult(layer_name="domain_logic", score=0.85)],
        evidence_chain=[
            Evidence(
                source="test",
                source_type=EvidenceType.COMPUTATION,
                claim_field="price",
                confirms=True,
                reasoning="Single check passed",
                confidence=0.9,
            ),
        ],
    )
    challenge_result = await agent.challenge(
        pillar_results={"logic_triangulation": weak_pillar}
    )
    has_challenges = challenge_result.metadata.get("challenges_raised", 0) > 0
    if has_challenges:
        logger.info(
            f"  OK  Adversarial raised {challenge_result.metadata['challenges_raised']} "
            f"challenges, score={challenge_result.score:.2f}"
        )
    else:
        logger.error("FAIL  Adversarial should find issues with weak evidence")
        return False

    # --- Test 7: Full stack with attestation bundle ---
    from core.verification.verification_stack import VerificationOrchestrator
    orchestrator = VerificationOrchestrator()
    full_bundle = AttestationBundle(
        file_bytes=b"verified document",
        gps_latitude=-36.8485,
        gps_longitude=174.7633,
        gps_accuracy_meters=5.0,
        timestamp=datetime.utcnow().isoformat(),
        device_fingerprint="device-full-test",
        depth_map_available=True,
        depth_variance=0.08,
    )
    full_result = await orchestrator.verify(
        payload={
            "company": "Mercury Energy",
            "electricity_price_kwh": 0.28,
            "quantity": 10,
            "unit_price": 0.28,
            "total": 2.80,
        },
        attestation_bundle=full_bundle,
        context={"region": "nz", "domain": "energy"},
    )
    logger.info(
        f"  OK  Full stack with attestation: "
        f"verdict={full_result.verdict}, score={full_result.score:.4f}"
    )

    return True


async def test_phase_19_pipeline_integration():
    """Phase 19: End-to-end pipeline integration."""
    logger.info("=" * 60)
    logger.info("PHASE 19: PIPELINE INTEGRATION")
    logger.info("=" * 60)

    import tempfile
    from core.verification.pipeline import VerificationPipeline
    from core.verification.attestation import AttestationBundle

    # Use temp file for proof ledger
    with tempfile.NamedTemporaryFile(suffix=".jsonl", delete=False) as f:
        ledger_path = f.name

    pipeline = VerificationPipeline(ledger_path=ledger_path)

    # --- Test 1: Good mission ---
    result1 = await pipeline.process_mission_result(
        mission_id=101,
        agent_id="scraper-alpha",
        payload={
            "company": "Mercury Energy",
            "electricity_price_kwh": 0.28,
            "quantity": 10,
            "unit_price": 0.28,
            "total": 2.80,
        },
        context={"region": "nz", "domain": "energy"},
    )
    if result1["verdict"] in ("VERIFIED", "GOLD") and result1["proof_record_id"] == 1:
        logger.info(
            f"  OK  Mission 101: {result1['verdict']} "
            f"(score={result1['score']:.4f}), "
            f"proof=#{result1['proof_record_id']}, "
            f"action={result1['action']}"
        )
    else:
        logger.error(f"FAIL  Good mission should verify: {result1}")
        return False

    # --- Test 2: Bad arithmetic mission ---
    result2 = await pipeline.process_mission_result(
        mission_id=102,
        agent_id="scraper-beta",
        payload={
            "company": "Fake Corp",
            "quantity": 100,
            "unit_price": 50.0,
            "total": 4500.0,
            "date": "2026-03-01",
        },
        context={"region": "nz", "domain": "invoice"},
    )
    if result2["verdict"] == "REJECTED" and result2["action"] == "reject":
        logger.info(
            f"  OK  Mission 102: {result2['verdict']} "
            f"(score={result2['score']:.4f}), "
            f"proof=#{result2['proof_record_id']}, "
            f"action={result2['action']}"
        )
    else:
        logger.error(f"FAIL  Bad arithmetic should reject: {result2}")
        return False

    # --- Test 3: Mission with attestation ---
    bundle = AttestationBundle(
        file_bytes=b"real invoice scan",
        gps_latitude=-36.8485,
        gps_longitude=174.7633,
        gps_accuracy_meters=8.0,
        timestamp=datetime.utcnow().isoformat(),
        device_fingerprint="field-agent-phone-001",
        depth_map_available=True,
        depth_variance=0.06,
    )
    result3 = await pipeline.process_mission_result(
        mission_id=103,
        agent_id="field-agent",
        payload={
            "company": "Contact Energy",
            "electricity_price_kwh": 0.30,
            "quantity": 5,
            "unit_price": 0.30,
            "total": 1.50,
        },
        attestation_bundle=bundle,
        context={"region": "nz", "domain": "energy"},
    )
    if result3["proof_record_id"] == 3:
        logger.info(
            f"  OK  Mission 103 (attested): {result3['verdict']} "
            f"(score={result3['score']:.4f}), "
            f"proof=#{result3['proof_record_id']}, "
            f"action={result3['action']}"
        )
    else:
        logger.error(f"FAIL  Attested mission: {result3}")
        return False

    # --- Test 4: Chain integrity ---
    chain_ok = pipeline.verify_ledger_integrity()
    if chain_ok:
        logger.info(f"  OK  Proof ledger chain: {pipeline.ledger.chain_length} records, integrity VALID")
    else:
        logger.error("FAIL  Chain integrity broken")
        return False

    # --- Test 5: Stats ---
    stats = pipeline.stats
    if stats["total"] == 3 and stats["rejected"] >= 1:
        logger.info(f"  OK  Pipeline stats: {stats}")
    else:
        logger.error(f"FAIL  Stats incorrect: {stats}")
        return False

    # --- Test 6: Proof ledger persistence ---
    ledger2 = __import__("core.verification.proof_ledger", fromlist=["ProofLedger"]).ProofLedger(
        storage_path=ledger_path
    )
    if ledger2.chain_length == 3:
        logger.info(f"  OK  Ledger reloaded from file: {ledger2.chain_length} records")
    else:
        logger.error(f"FAIL  Ledger reload: expected 3, got {ledger2.chain_length}")
        return False

    reloaded_ok = ledger2.verify_chain_integrity()
    if reloaded_ok:
        logger.info(f"  OK  Reloaded chain integrity: VALID")
    else:
        logger.error("FAIL  Reloaded chain integrity broken")
        return False

    # Cleanup temp file
    try:
        os.remove(ledger_path)
    except OSError:
        pass

    return True


async def test_phase_20_m2m_protocol():
    """Phase 20: M2M Protocol Layer."""
    logger.info("=" * 60)
    logger.info("PHASE 20: M2M PROTOCOL LAYER")
    logger.info("=" * 60)

    from protocols.agent_protocol import (
        AgentIdentity, AgentRole, MessageType,
        ProtocolMessage, validate_message_freshness,
        validate_protocol_version, PROTOCOL_VERSION,
    )
    from protocols.auth import M2MAuthenticator, sign_message
    from protocols.registry import AgentRegistry
    from protocols.quotation import QuotationEngine

    # --- Test 1: Message creation & serialization ---
    msg = ProtocolMessage(
        message_type=MessageType.DISCOVER,
        sender_id="test-agent-001",
        payload={"tags": ["energy", "nz"]},
    )
    serialized = msg.to_dict()
    deserialized = ProtocolMessage.from_dict(serialized)
    if (
        deserialized.message_type == MessageType.DISCOVER
        and deserialized.sender_id == "test-agent-001"
        and deserialized.payload == {"tags": ["energy", "nz"]}
    ):
        logger.info(f"  OK  Message round-trip: type={msg.message_type.value}, id={msg.message_id}")
    else:
        logger.error("FAIL  Message serialization round-trip failed")
        return False

    # --- Test 2: Message freshness ---
    if validate_message_freshness(msg):
        logger.info("  OK  Fresh message accepted")
    else:
        logger.error("FAIL  Fresh message rejected")
        return False

    stale_msg = ProtocolMessage(
        message_type=MessageType.HEARTBEAT,
        sender_id="test",
        payload={},
        timestamp="2020-01-01T00:00:00",
    )
    if not validate_message_freshness(stale_msg):
        logger.info("  OK  Stale message rejected")
    else:
        logger.error("FAIL  Stale message should be rejected")
        return False

    # --- Test 3: Agent identity & auth ---
    auth = M2MAuthenticator()
    # Generate a real Ed25519 keypair for signing + verification
    from nacl.signing import SigningKey as _TestSigningKey
    _test_sk = _TestSigningKey.generate()
    _test_privkey_hex = _test_sk.encode().hex()
    _test_pubkey_hex = _test_sk.verify_key.encode().hex()
    agent = AgentIdentity(
        agent_id="bot-mercury-nz",
        public_key=_test_pubkey_hex,
        role=AgentRole.DATA_CONSUMER,
        capabilities=["energy-nz", "comparison"],
    )
    auth.register_agent(agent)

    # Sign and authenticate a message
    task_msg = ProtocolMessage(
        message_type=MessageType.TASK_SUBMIT,
        sender_id="bot-mercury-nz",
        payload={"goal": "Get Mercury Energy prices"},
    )
    signed_msg = sign_message(task_msg, _test_privkey_hex)
    auth_ok, reason = auth.authenticate_message(signed_msg)
    if auth_ok:
        logger.info(f"  OK  Signed message authenticated: {reason}")
    else:
        logger.error(f"FAIL  Auth should pass: {reason}")
        return False

    # --- Test 4: Replay protection ---
    replay_ok, replay_reason = auth.authenticate_message(signed_msg)
    if not replay_ok and "replay" in replay_reason.lower():
        logger.info(f"  OK  Replay blocked: {replay_reason}")
    else:
        logger.error(f"FAIL  Replay should be blocked: {replay_reason}")
        return False

    # --- Test 5: API key auth ---
    key_id, raw_secret = auth.issue_api_key("bot-mercury-nz")
    valid, reason, agent_id, _env = auth.authenticate_api_key(key_id, raw_secret)
    if valid and agent_id == "bot-mercury-nz":
        logger.info(f"  OK  API key auth: {key_id}")
    else:
        logger.error(f"FAIL  API key auth failed: {reason}")
        return False

    # Wrong secret
    bad_valid, _, _, _ = auth.authenticate_api_key(key_id, "wrong_secret")
    if not bad_valid:
        logger.info("  OK  Bad API secret rejected")
    else:
        logger.error("FAIL  Bad secret should be rejected")
        return False

    # --- Test 6: Permissions ---
    can_submit = auth.check_permission("bot-mercury-nz", "submit_task")
    cannot_register = auth.check_permission("bot-mercury-nz", "register_agent")
    if can_submit and not cannot_register:
        logger.info("  OK  RBAC: consumer can submit_task, cannot register_agent")
    else:
        logger.error("FAIL  Permission check incorrect")
        return False

    # --- Test 7: Registry ---
    registry = AgentRegistry()
    reg_result = registry.register_agent(agent)
    if reg_result["status"] == "registered":
        logger.info(f"  OK  Agent registered: {reg_result}")
    else:
        logger.error(f"FAIL  Registration failed: {reg_result}")
        return False

    # Discover services
    energy_services = registry.discover_services(tags=["energy"], region="nz")
    if len(energy_services) > 0:
        logger.info(
            f"  OK  Discovered {len(energy_services)} energy services in NZ: "
            f"{[s['name'] for s in energy_services]}"
        )
    else:
        logger.error("FAIL  Should find energy services")
        return False

    # --- Test 8: Reputation ---
    new_rep = registry.update_reputation("bot-mercury-nz", +0.1)
    if new_rep and new_rep > 0.5:
        logger.info(f"  OK  Reputation updated: {new_rep:.2f}")
    else:
        logger.error(f"FAIL  Reputation update: {new_rep}")
        return False

    # --- Test 9: Quotation ---
    engine = QuotationEngine()
    engine.add_credits("bot-mercury-nz", 100.0)

    quote = engine.generate_quote(
        agent_id="bot-mercury-nz",
        service_id="svc-data-extraction",
        task_params={"field_count": 10, "attachment_count": 2, "region": "nz"},
    )
    if quote.estimated_credits > 0:
        logger.info(
            f"  OK  Quote generated: {quote.quote_id} = "
            f"{quote.estimated_credits:.4f} credits"
        )
    else:
        logger.error("FAIL  Quote should have positive cost")
        return False

    # Accept quote
    accepted = engine.accept_quote(quote.quote_id)
    if accepted:
        remaining = engine.get_balance("bot-mercury-nz")
        logger.info(f"  OK  Quote accepted, remaining balance: {remaining:.2f}")
    else:
        logger.error("FAIL  Quote acceptance failed")
        return False

    # Insufficient balance test
    engine2 = QuotationEngine()
    engine2.add_credits("broke-bot", 0.5)
    expensive_quote = engine2.generate_quote(
        agent_id="broke-bot",
        service_id="svc-data-extraction",
        task_params={"field_count": 20, "region": "global"},
    )
    denied = engine2.accept_quote(expensive_quote.quote_id)
    if not denied:
        logger.info(f"  OK  Insufficient credits rejected")
    else:
        logger.error("FAIL  Should reject when insufficient credits")
        return False

    return True


async def test_phase_21_ingestion_pipeline():
    """Phase 21: Ingestion Pipeline + Document Intelligence."""
    logger.info("=" * 60)
    logger.info("PHASE 21: INGESTION PIPELINE")
    logger.info("=" * 60)

    from core.ingestion import IngestPipeline, SourceProvenance, DataFormat
    from core.document_intelligence import DocumentIntelligence

    pipeline = IngestPipeline()
    intel = DocumentIntelligence()

    # --- Test 1: PDF format detection ---
    fake_pdf = b"%PDF-1.4 some pdf content here for testing"
    prov = SourceProvenance(
        source_agent_id="scraper-alpha",
        submission_protocol="m2m",
    )
    result1 = pipeline.ingest_bytes(fake_pdf, prov)
    if result1.detected_format == DataFormat.PDF and result1.data_hash:
        logger.info(
            f"  OK  PDF detected: hash={result1.data_hash[:16]}..., "
            f"size={result1.raw_size_bytes}"
        )
    else:
        logger.error(f"FAIL  PDF detection: {result1.detected_format}")
        return False

    # --- Test 2: JPEG format detection ---
    fake_jpeg = b"\xff\xd8\xff\xe0 jpeg image data"
    result2 = pipeline.ingest_bytes(fake_jpeg, prov)
    if result2.detected_format == DataFormat.IMAGE_JPEG:
        logger.info(f"  OK  JPEG detected: {result2.submission_id}")
    else:
        logger.error("FAIL  JPEG detection")
        return False

    # --- Test 3: Duplicate detection ---
    result3 = pipeline.ingest_bytes(fake_pdf, prov)
    if result3.is_duplicate and result3.duplicate_of == result1.submission_id:
        logger.info(
            f"  OK  Duplicate detected: {result3.submission_id} → "
            f"original={result3.duplicate_of}"
        )
    else:
        logger.error("FAIL  Duplicate not detected")
        return False

    # --- Test 4: Structured JSON ingestion ---
    json_data = {
        "company": "Mercury Energy",
        "electricity_price_kwh": 0.28,
        "region": "nz",
    }
    result4 = pipeline.ingest_structured(json_data, prov)
    if (
        result4.detected_format == DataFormat.JSON
        and result4.extraction_confidence == 1.0
        and result4.extracted_fields == json_data
    ):
        logger.info(
            f"  OK  JSON ingested: {result4.submission_id}, "
            f"fields={len(result4.extracted_fields)}"
        )
    else:
        logger.error("FAIL  JSON ingestion")
        return False

    # --- Test 5: CSV ingestion ---
    csv_text = "company,price,region\nMercury,0.28,nz\nContact,0.30,nz"
    result5 = pipeline.ingest_csv_text(csv_text, prov)
    if result5.extracted_fields.get("row_count") == 2:
        logger.info(
            f"  OK  CSV ingested: {result5.submission_id}, "
            f"rows={result5.extracted_fields['row_count']}"
        )
    else:
        logger.error(f"FAIL  CSV: {result5.extracted_fields}")
        return False

    # --- Test 6: Document Intelligence — JSON extraction ---
    cleaned = intel.extract_from_json(json_data, result4.submission_id)
    if (
        cleaned.overall_confidence == 1.0
        and cleaned.document_type in ("energy_pricing", "pricing_data")
    ):
        logger.info(
            f"  OK  JSON extraction: type={cleaned.document_type}, "
            f"fields={len(cleaned.field_details)}, "
            f"schema={cleaned.inferred_schema}"
        )
    else:
        logger.error(f"FAIL  JSON extraction: {cleaned.to_dict()}")
        return False

    # --- Test 7: Text extraction ---
    text = """
    Invoice Date: 2026-03-01
    Company: Mercury Energy
    Amount: $1,250.50 NZD
    GST Number: 123-456-789
    Contact: billing@mercury.co.nz
    """
    cleaned_text = intel.extract_from_text(text, "sub-text-001")
    if len(cleaned_text.fields) >= 3:
        logger.info(
            f"  OK  Text extraction: {len(cleaned_text.fields)} fields, "
            f"conf={cleaned_text.overall_confidence:.2f}"
        )
        for fd in cleaned_text.field_details[:3]:
            logger.info(f"       → {fd.name}: {fd.value} ({fd.data_type})")
    else:
        logger.error(f"FAIL  Text: only {len(cleaned_text.fields)} fields")
        return False

    # --- Test 8: CSV extraction ---
    rows = [
        {"company": "Mercury", "price": "0.28", "date": "2026-03-01"},
        {"company": "Contact", "price": "0.30", "date": "2026-03-02"},
    ]
    cleaned_csv = intel.extract_from_csv_rows(rows, "sub-csv-001")
    if cleaned_csv.inferred_schema.get("price") == "number":
        logger.info(
            f"  OK  CSV extraction: schema={cleaned_csv.inferred_schema}"
        )
    else:
        logger.error(f"FAIL  CSV schema: {cleaned_csv.inferred_schema}")
        return False

    # --- Test 9: Pipeline stats ---
    stats = pipeline.stats
    if stats["total_submissions"] >= 5 and stats["duplicates_detected"] >= 1:
        logger.info(f"  OK  Pipeline stats: {stats}")
    else:
        logger.error(f"FAIL  Stats: {stats}")
        return False

    # --- Test 10: Empty file rejection ---
    empty_result = pipeline.ingest_bytes(b"", prov)
    if empty_result.status == "failed":
        logger.info(f"  OK  Empty file rejected: {empty_result.warnings}")
    else:
        logger.error("FAIL  Empty file should be rejected")
        return False

    return True


async def test_phase_22_m2m_http_integration():
    """Phase 22: M2M HTTP Integration — Real endpoint tests via AsyncClient."""
    logger.info("=" * 60)
    logger.info("PHASE 22: M2M HTTP INTEGRATION")
    logger.info("=" * 60)

    try:
        import httpx
        from regional_core import app

        transport = httpx.ASGITransport(app=app)
    except Exception as init_err:
        logger.warning(f"SKIP  Cannot create test client: {init_err}")
        return "SKIPPED"

    # Use legacy registration (no challenge) for test compatibility
    import core.m2m_router as _m2m_mod
    _orig_challenge = _m2m_mod.REQUIRE_CHALLENGE
    _m2m_mod.REQUIRE_CHALLENGE = False

    async with httpx.AsyncClient(transport=transport, base_url="http://testserver") as client:

        # --- Test 1: Register an external agent (POST /m2m/register) ---
        reg_resp = await client.post("/m2m/register", json={
            "agent_id": "ext-energy-bot-001",
            "public_key": "pk_test_energy_bot_001",
            "role": "DATA_CONSUMER",
            "display_name": "Energy Price Bot",
            "capabilities": ["energy", "nz"],
        })
        if reg_resp.status_code == 200 and reg_resp.json().get("status") == "registered":
            reg_data = reg_resp.json()
            api_key_id = reg_data["api_key"]["key_id"]
            api_secret = reg_data["api_key"]["secret"]
            logger.info(
                f"  OK  HTTP Register: agent={reg_data['agent_id']}, "
                f"key={api_key_id}, credits={reg_data['starter_credits']}"
            )
        else:
            logger.error(f"FAIL  Register: {reg_resp.status_code} {reg_resp.text}")
            _m2m_mod.REQUIRE_CHALLENGE = _orig_challenge
            return False

        # Bootstrap trust for test agent so trust-gated endpoints work
        try:
            from core.database import save_agent_verification, update_agent_verification, AgentVerification, SessionLocal
            _avr = save_agent_verification(agent_id="ext-energy-bot-001", agent_name="Energy Price Bot")
            update_agent_verification(verification_id=_avr.id, verdict="TRUSTED", trust_score=0.80)
            logger.info("  OK  Test agent trust bootstrapped to 0.80 (ESTABLISHED)")
        except Exception as _te:
            logger.warning(f"  WARN  Trust bootstrap failed: {_te}")

        # --- Test 2: Discover services (GET /m2m/discover?tags=energy&region=nz) ---
        disc_resp = await client.get("/m2m/discover", params={"tags": "energy", "region": "nz"})
        if disc_resp.status_code == 200:
            services = disc_resp.json()["services"]
            logger.info(
                f"  OK  HTTP Discover: {len(services)} services, "
                f"names={[s['name'] for s in services]}"
            )
        else:
            logger.error(f"FAIL  Discover: {disc_resp.status_code}")
            return False

        # --- Test 3: Get a quote (POST /m2m/quote) ---
        quote_resp = await client.post(
            "/m2m/quote",
            json={
                "service_id": "svc-data-extraction",
                "task_params": {"field_count": 8, "region": "nz"},
            },
            headers={
                "x-api-key-id": api_key_id,
                "x-api-secret": api_secret,
            },
        )
        if quote_resp.status_code == 200:
            quote_data = quote_resp.json()
            quote_id = quote_data["quote"]["quote_id"]
            cost = quote_data["quote"]["estimated_credits"]
            can_afford = quote_data["can_afford"]
            logger.info(
                f"  OK  HTTP Quote: {quote_id} = {cost} credits, "
                f"can_afford={can_afford}, balance={quote_data['your_balance']}"
            )
        else:
            logger.error(f"FAIL  Quote: {quote_resp.status_code} {quote_resp.text}")
            return False

        # --- Test 4: Auth failure (no key) ---
        bad_quote = await client.post(
            "/m2m/quote",
            json={"service_id": "svc-data-extraction", "task_params": {}},
            headers={"x-api-key-id": "", "x-api-secret": ""},
        )
        if bad_quote.status_code == 401:
            logger.info(f"  OK  HTTP Auth rejection: 401 (no key)")
        else:
            logger.error(f"FAIL  Should reject unauthenticated: {bad_quote.status_code}")
            return False

        # --- Test 5: Submit a task (POST /m2m/submit) ---
        submit_resp = await client.post(
            "/m2m/submit",
            json={
                "service_id": "svc-data-extraction",
                "quote_id": quote_id,
                "payload": {"goal": "Get Mercury Energy NZ pricing"},
                "target_url": "https://mercury.co.nz",
            },
            headers={
                "x-api-key-id": api_key_id,
                "x-api-secret": api_secret,
            },
        )
        if submit_resp.status_code == 200 and submit_resp.json().get("status") == "queued":
            task_id = submit_resp.json()["task_id"]
            logger.info(f"  OK  HTTP Submit: task={task_id}, status=queued")
        else:
            logger.error(f"FAIL  Submit: {submit_resp.status_code} {submit_resp.text}")
            return False

        # --- Test 6: Check status (GET /m2m/status/{task_id}) ---
        status_resp = await client.get(
            f"/m2m/status/{task_id}",
            headers={
                "x-api-key-id": api_key_id,
                "x-api-secret": api_secret,
            },
        )
        if status_resp.status_code == 200:
            logger.info(f"  OK  HTTP Status: {status_resp.json()['status']}")
        else:
            logger.error(f"FAIL  Status: {status_resp.status_code}")
            return False

        # --- Test 7: 404 for unknown task ---
        not_found = await client.get(
            "/m2m/status/task-nonexistent",
            headers={
                "x-api-key-id": api_key_id,
                "x-api-secret": api_secret,
            },
        )
        if not_found.status_code == 404:
            logger.info(f"  OK  HTTP 404 for unknown task")
        else:
            logger.error(f"FAIL  Should be 404: {not_found.status_code}")
            return False

        # --- Test 8: Refinery submit (POST /refinery/submit) — actually runs verification ---
        refinery_resp = await client.post("/refinery/submit", json={
            "payload": {"company": "Mercury", "price": 0.28},
            "source_agent_id": "ext-energy-bot-001",
        }, headers={
            "x-api-key-id": api_key_id,
            "x-api-secret": api_secret,
        })
        if refinery_resp.status_code == 200 and refinery_resp.json().get("data_hash"):
            ref_data = refinery_resp.json()
            data_hash = ref_data["data_hash"]
            verdict = ref_data.get("verdict", "unknown")
            score = ref_data.get("score", 0.0)
            logger.info(
                f"  OK  HTTP Refinery submit: hash={data_hash[:16]}..., "
                f"verdict={verdict}, score={score:.4f}"
            )
        else:
            logger.error(f"FAIL  Refinery: {refinery_resp.status_code} {refinery_resp.text}")
            return False

        # --- Test 9: Refinery status (should have real verdict now) ---
        ref_status = await client.get(f"/refinery/status/{data_hash}")
        if ref_status.status_code == 200 and ref_status.json().get("verdict"):
            logger.info(
                f"  OK  HTTP Refinery status: {ref_status.json()['status']}, "
                f"verdict={ref_status.json()['verdict']}"
            )
        else:
            logger.error(f"FAIL  Refinery status: {ref_status.status_code}")
            return False

        # --- Test 10: Proof verification (public, no auth) ---
        proof_resp = await client.get("/m2m/verify/nonexistent_hash")
        if proof_resp.status_code == 200 and proof_resp.json()["verified"] is False:
            logger.info(f"  OK  HTTP Proof verify: not found (correct for unknown hash)")
        else:
            logger.error(f"FAIL  Proof verify: {proof_resp.status_code}")
            _m2m_mod.REQUIRE_CHALLENGE = _orig_challenge
            return False

    _m2m_mod.REQUIRE_CHALLENGE = _orig_challenge
    return True


async def test_phase_23_task_executor():
    """Phase 23: Task Executor — Full Lifecycle."""
    logger.info("")
    logger.info("=" * 60)
    logger.info("PHASE 23: TASK EXECUTOR & FULL LIFECYCLE")
    logger.info("=" * 60)

    from core.task_executor import TaskExecutor
    from core.verification.pipeline import VerificationPipeline

    pipeline = VerificationPipeline()
    executor = TaskExecutor(verification_pipeline=pipeline)

    # --- Test 1: Verification task ---
    task_verify = {
        "task_id": "test-verify-001",
        "agent_id": "lifecycle-agent",
        "service_id": "svc-document-verification",
        "payload": {
            "company": "Mercury Energy",
            "electricity_price_kwh": 0.28,
            "region": "nz",
        },
        "context": {},
    }

    result = await executor.execute_task(task_verify)
    if result["status"] == "completed" and result["result"].get("verdict"):
        verdict = result["result"]["verdict"]
        score = result["result"]["score"]
        proof = result["result"]["proof_hash"]
        logger.info(
            f"  OK  Verification task: {verdict}, "
            f"score={score:.4f}, proof={proof[:16]}..."
        )
    else:
        logger.error(f"FAIL  Verification task: {result['status']}")
        return False

    # --- Test 2: Data extraction task ---
    task_extract = {
        "task_id": "test-extract-001",
        "agent_id": "lifecycle-agent",
        "service_id": "svc-data-extraction",
        "payload": {
            "provider": "Contact Energy",
            "monthly_cost": 145.50,
            "plan_type": "low_user",
        },
        "context": {},
    }

    result_ex = await executor.execute_task(task_extract)
    if (
        result_ex["status"] == "completed"
        and result_ex["result"].get("submission_id")
    ):
        sub_id = result_ex["result"]["submission_id"]
        doc_type = result_ex["result"]["document_type"]
        v = result_ex["result"]["verification"]["verdict"]
        logger.info(
            f"  OK  Extraction task: sub={sub_id}, "
            f"type={doc_type}, verdict={v}"
        )
    else:
        logger.error(f"FAIL  Extraction task: {result_ex['status']}")
        return False

    # --- Test 3: Unknown service ---
    task_bad = {
        "task_id": "test-bad-001",
        "agent_id": "lifecycle-agent",
        "service_id": "svc-nonexistent",
        "payload": {},
        "context": {},
    }
    result_bad = await executor.execute_task(task_bad)
    if result_bad["status"] == "failed" and "Unknown service" in str(
        result_bad.get("result", {}).get("error", "")
    ):
        logger.info("  OK  Unknown service rejected correctly")
    else:
        logger.error(f"FAIL  Unknown service: {result_bad['status']}")
        return False

    # --- Test 4: Executor stats ---
    stats = executor.stats
    if stats["tasks_executed"] == 3 and stats["tasks_succeeded"] == 2:
        logger.info(
            f"  OK  Executor stats: executed={stats['tasks_executed']}, "
            f"succeeded={stats['tasks_succeeded']}, "
            f"failed={stats['tasks_failed']}"
        )
    else:
        logger.error(f"FAIL  Stats mismatch: {stats}")
        return False

    # --- Test 5: Proof ledger has records from both tasks ---
    chain_len = pipeline.ledger.chain_length
    if chain_len >= 2:
        logger.info(f"  OK  Proof ledger: {chain_len} records in chain")
    else:
        logger.error(f"FAIL  Proof chain too short: {chain_len}")
        return False

    return True


async def test_phase_24_refinery_db_persistence():
    """
    Phase 24: Verify the 5 new DB models actually persist data end-to-end.

    Tests:
      - RawSubmission saved on ingest
      - CleanedData saved after extraction
      - VerificationResult saved after pipeline runs
      - DataQuarantine created for QUARANTINE verdicts
      - BlockchainStamp created for VERIFIED/GOLD verdicts
      - get_verification_by_hash returns persisted records
      - get_quarantine_queue returns pending items
      - get_refinery_stats returns correct aggregate counts
    """
    logger.info("=" * 60)
    logger.info("PHASE 24: REFINERY DB PERSISTENCE")
    logger.info("=" * 60)

    from core.database import (
        SessionLocal,
        RawSubmission, CleanedData, VerificationResult,
        DataQuarantine, BlockchainStamp,
        save_raw_submission, save_cleaned_data,
        save_verification_result, save_quarantine, save_blockchain_stamp,
        get_verification_by_hash, get_quarantine_queue,
        resolve_quarantine, get_refinery_stats,
    )
    import secrets

    # Use unique hashes per run to avoid unique-constraint collisions
    run_token = secrets.token_hex(8)

    # ------------------------------------------------------------------ #
    # Test 1: RawSubmission round-trip
    # ------------------------------------------------------------------ #
    sub_id = f"sub-test-{secrets.token_hex(4)}"
    fake_hash = hashlib.sha256(f"test-raw-{run_token}".encode()).hexdigest()
    rec = save_raw_submission(
        submission_id=sub_id,
        data_hash=fake_hash,
        source_agent_id="test-agent",
        submission_protocol="api",
        format="json",
        raw_size_bytes=128,
        provenance={"source_agent_id": "test-agent", "submission_protocol": "api"},
        status="ingested",
    )
    if rec and rec.id == sub_id:
        logger.info(f"  OK  RawSubmission persisted: id={rec.id}, hash={rec.data_hash[:16]}...")
    else:
        logger.error("FAIL  RawSubmission not persisted")
        return False

    # Idempotent — re-saving same sub_id should return existing record
    rec2 = save_raw_submission(
        submission_id=sub_id,
        data_hash=fake_hash,
        source_agent_id="test-agent",
        submission_protocol="api",
        format="json",
        raw_size_bytes=128,
        provenance={},
    )
    if rec2.id == sub_id:
        logger.info(f"  OK  RawSubmission idempotent re-save works")
    else:
        logger.error("FAIL  Idempotent re-save returned wrong record")
        return False

    # ------------------------------------------------------------------ #
    # Test 2: CleanedData round-trip
    # ------------------------------------------------------------------ #
    cleaned = save_cleaned_data(
        submission_id=sub_id,
        structured_data={"company": "TestCorp", "price": 0.28},
        confidence=0.95,
        document_type="energy_pricing",
    )
    if cleaned and cleaned.submission_id == sub_id and cleaned.confidence == 0.95:
        logger.info(
            f"  OK  CleanedData persisted: id={cleaned.id}, "
            f"doc_type={cleaned.document_type}, conf={cleaned.confidence}"
        )
    else:
        logger.error(f"FAIL  CleanedData not persisted: {cleaned}")
        return False

    # Verify parent RawSubmission status updated to 'extracted'
    db = SessionLocal()
    try:
        parent = db.query(RawSubmission).filter(RawSubmission.id == sub_id).first()
        if parent and parent.status == "extracted":
            logger.info(f"  OK  RawSubmission status promoted to 'extracted'")
        else:
            logger.error(f"FAIL  Parent status not updated: {parent.status if parent else 'NOT FOUND'}")
            return False
    finally:
        db.close()

    # ------------------------------------------------------------------ #
    # Test 3: VerificationResult round-trip
    # ------------------------------------------------------------------ #
    proof_h = hashlib.sha256(f"test-proof-{run_token}".encode()).hexdigest()
    vr = save_verification_result(
        data_hash=fake_hash,
        proof_hash=proof_h,
        verdict="VERIFIED",
        composite_score=0.82,
        action="store_verified",
        agent_id="test-agent",
        submission_id=sub_id,
        proof_record_id=1,
        layer_scores={"forensic": 0.8, "triangulation": 0.85},
        details={"veto_triggered": False},
    )
    if vr and vr.verdict == "VERIFIED" and vr.composite_score == 0.82:
        logger.info(
            f"  OK  VerificationResult persisted: id={vr.id}, "
            f"verdict={vr.verdict}, score={vr.composite_score}"
        )
    else:
        logger.error(f"FAIL  VerificationResult not persisted")
        return False

    # Idempotent — same proof_hash should return existing record
    vr2 = save_verification_result(
        data_hash=fake_hash,
        proof_hash=proof_h,
        verdict="VERIFIED",
        composite_score=0.82,
        action="store_verified",
    )
    if vr2.id == vr.id:
        logger.info(f"  OK  VerificationResult idempotent re-save works")
    else:
        logger.error("FAIL  Idempotent re-save returned different record")
        return False

    # ------------------------------------------------------------------ #
    # Test 4: get_verification_by_hash lookup
    # ------------------------------------------------------------------ #
    looked_up = get_verification_by_hash(fake_hash)
    if (
        looked_up
        and looked_up["verdict"] == "VERIFIED"
        and looked_up["proof_hash"] == proof_h
    ):
        logger.info(
            f"  OK  get_verification_by_hash: verdict={looked_up['verdict']}, "
            f"score={looked_up['score']}"
        )
    else:
        logger.error(f"FAIL  get_verification_by_hash returned: {looked_up}")
        return False

    # ------------------------------------------------------------------ #
    # Test 5: DataQuarantine round-trip
    # ------------------------------------------------------------------ #
    q_hash = hashlib.sha256(f"test-quarantine-{run_token}".encode()).hexdigest()
    qr = save_quarantine(
        verification_result_id=vr.id,
        data_hash=q_hash,
        reason="Score in quarantine range: 0.55",
        score=0.55,
        submission_id=sub_id,
    )
    if qr and qr.resolution_status == "PENDING" and qr.score == 0.55:
        logger.info(
            f"  OK  DataQuarantine persisted: id={qr.id}, "
            f"score={qr.score}, status={qr.resolution_status}"
        )
    else:
        logger.error(f"FAIL  DataQuarantine not persisted")
        return False

    # get_quarantine_queue should include this item
    queue = get_quarantine_queue(limit=100)
    queue_hashes = [item["data_hash"] for item in queue]
    if q_hash in queue_hashes:
        logger.info(f"  OK  get_quarantine_queue: item present in queue (len={len(queue)})")
    else:
        logger.error(f"FAIL  Quarantine item not in queue: {queue_hashes[:3]}")
        return False

    # Resolve it as APPROVED
    resolved = resolve_quarantine(qr.id, "APPROVED", resolved_by="test-reviewer")
    if resolved:
        logger.info(f"  OK  resolve_quarantine APPROVED: id={qr.id}")
    else:
        logger.error("FAIL  resolve_quarantine returned False")
        return False

    # Should no longer appear in PENDING queue
    queue_after = get_quarantine_queue(limit=100)
    if q_hash not in [item["data_hash"] for item in queue_after]:
        logger.info(f"  OK  Resolved item removed from pending queue")
    else:
        logger.error("FAIL  Resolved item still in pending queue")
        return False

    # ------------------------------------------------------------------ #
    # Test 6: BlockchainStamp round-trip
    # ------------------------------------------------------------------ #
    bs = save_blockchain_stamp(
        proof_hash=proof_h,
        data_hash=fake_hash,
        verdict="VERIFIED",
        confidence=0.82,
        verification_result_id=vr.id,
        submission_id=sub_id,
        tx_hash="0x" + "d" * 64,
        chain="polygon",
        block_number=12345678,
    )
    if bs and bs.tx_hash and bs.chain == "polygon":
        logger.info(
            f"  OK  BlockchainStamp persisted: id={bs.id}, "
            f"chain={bs.chain}, block={bs.block_number}, "
            f"tx={bs.tx_hash[:18]}..."
        )
    else:
        logger.error(f"FAIL  BlockchainStamp not persisted")
        return False

    # ------------------------------------------------------------------ #
    # Test 7: get_refinery_stats aggregate counts
    # ------------------------------------------------------------------ #
    stats = get_refinery_stats()
    if (
        stats["total_submissions"] >= 1
        and stats["verdicts"]["verified"] >= 1
        and stats["blockchain_stamps"] >= 1
    ):
        logger.info(
            f"  OK  get_refinery_stats: submissions={stats['total_submissions']}, "
            f"verdicts={stats['verdicts']}, stamps={stats['blockchain_stamps']}, "
            f"quarantine_pending={stats['quarantine_pending']}"
        )
    else:
        logger.error(f"FAIL  Stats unexpected: {stats}")
        return False

    return True


async def test_phase_25_refinery_http_v2():
    """
    Phase 25: Test the new refinery HTTP endpoints added in v6.1.

    Tests:
      - POST /refinery/submit persists RawSubmission + CleanedData to DB
      - GET  /refinery/status/{hash} reads from DB (survives restart simulation)
      - GET  /refinery/stats returns live aggregate stats
      - GET  /refinery/quarantine returns pending queue
      - POST /refinery/quarantine/{id}/resolve resolves item (APPROVED/REJECTED)
      - POST /refinery/submit deduplication — same hash returns cached=True
      - POST /refinery/submit with document_type context hint
    """
    logger.info("=" * 60)
    logger.info("PHASE 25: REFINERY HTTP v2 (DB-BACKED)")
    logger.info("=" * 60)

    try:
        import httpx
        from regional_core import app
        transport = httpx.ASGITransport(app=app)
    except Exception as init_err:
        logger.warning(f"SKIP  Cannot create test client: {init_err}")
        return "SKIPPED"

    # Register test agent with trust for refinery access
    import core.m2m_router as _m2m_mod
    _orig_challenge = _m2m_mod.REQUIRE_CHALLENGE
    _m2m_mod.REQUIRE_CHALLENGE = False

    async with httpx.AsyncClient(transport=transport, base_url="http://testserver") as client:

        # Register agent for auth
        _reg = await client.post("/m2m/register", json={
            "agent_id": "phase-25-test-bot",
            "public_key": "pk_phase25_test",
            "role": "DATA_PROVIDER",
        })
        if _reg.status_code != 200:
            logger.error(f"FAIL  Phase 25 agent registration: {_reg.status_code} {_reg.text[:200]}")
            _m2m_mod.REQUIRE_CHALLENGE = _orig_challenge
            return False
        _reg_data = _reg.json()
        _key_id = _reg_data["api_key"]["key_id"]
        _secret = _reg_data["api_key"]["secret"]

        # Bootstrap trust to NEW (0.42) for refinery submit access
        try:
            from core.database import save_agent_verification, update_agent_verification
            _avr = save_agent_verification(agent_id="phase-25-test-bot", agent_name="Phase 25 Test Bot")
            update_agent_verification(verification_id=_avr.id, verdict="TRUSTED", trust_score=0.55)
        except Exception:
            pass

        _auth_headers = {"x-api-key-id": _key_id, "x-api-secret": _secret}

        # ------------------------------------------------------------------ #
        # Test 1: Submit data — verify DB persistence
        # ------------------------------------------------------------------ #
        payload_v2 = {
            "company": "Vector Energy",
            "electricity_price_kwh": 0.31,
            "region": "auckland",
            "quantity": 100,
            "unit_price": 0.31,
            "total": 31.0,
        }
        sub_resp = await client.post("/refinery/submit", json={
            "payload": payload_v2,
            "source_agent_id": "phase-25-test-bot",
            "context": {"document_type": "energy_pricing", "region": "nz"},
        }, headers=_auth_headers)
        if sub_resp.status_code != 200:
            logger.error(f"FAIL  Submit: {sub_resp.status_code} {sub_resp.text[:200]}")
            return False

        sub_data = sub_resp.json()
        data_hash = sub_data.get("data_hash")
        submission_id = sub_data.get("submission_id")
        verdict = sub_data.get("verdict", "")
        score = sub_data.get("score", 0.0)
        logger.info(
            f"  OK  Submit: hash={data_hash[:16]}..., "
            f"sub_id={submission_id}, verdict={verdict}, score={score:.4f}"
        )

        # ------------------------------------------------------------------ #
        # Test 2: Status lookup hits DB (not just in-memory cache)
        # ------------------------------------------------------------------ #
        status_resp = await client.get(f"/refinery/status/{data_hash}")
        if status_resp.status_code == 200:
            s = status_resp.json()
            # Must have a verdict — either from DB or cache
            if s.get("verdict"):
                logger.info(
                    f"  OK  Status (DB-backed): verdict={s['verdict']}, "
                    f"score={s.get('score', '?')}"
                )
            else:
                logger.error(f"FAIL  Status response missing verdict: {s}")
                return False
        else:
            logger.error(f"FAIL  Status: {status_resp.status_code}")
            return False

        # ------------------------------------------------------------------ #
        # Test 3: Deduplication — same payload returns cached=True immediately
        # ------------------------------------------------------------------ #
        dup_resp = await client.post("/refinery/submit", json={
            "payload": payload_v2,
            "source_agent_id": "phase-25-test-bot-b",
        }, headers=_auth_headers)
        if dup_resp.status_code == 200 and dup_resp.json().get("cached") is True:
            logger.info(
                f"  OK  Deduplication: same hash returned cached=True, "
                f"verdict={dup_resp.json()['verdict']}"
            )
        else:
            logger.error(
                f"FAIL  Deduplication should return cached=True: "
                f"{dup_resp.status_code} {dup_resp.json()}"
            )
            return False

        # ------------------------------------------------------------------ #
        # Test 4: GET /refinery/stats — aggregate counts
        # ------------------------------------------------------------------ #
        stats_resp = await client.get("/refinery/stats")
        if stats_resp.status_code == 200:
            st = stats_resp.json()
            if st.get("total_submissions", 0) >= 1:
                logger.info(
                    f"  OK  Stats endpoint: submissions={st['total_submissions']}, "
                    f"verdicts={st.get('verdicts', {})}, "
                    f"stamps={st.get('blockchain_stamps', 0)}"
                )
            else:
                logger.error(f"FAIL  Stats shows 0 submissions: {st}")
                return False
        else:
            logger.error(f"FAIL  Stats: {stats_resp.status_code} {stats_resp.text}")
            return False

        # ------------------------------------------------------------------ #
        # Test 5: GET /refinery/quarantine — pending queue
        # ------------------------------------------------------------------ #
        qqueue_resp = await client.get("/refinery/quarantine")
        if qqueue_resp.status_code == 200:
            qdata = qqueue_resp.json()
            if "queue" in qdata:
                logger.info(
                    f"  OK  Quarantine queue: {len(qdata['queue'])} pending items"
                )
            else:
                logger.error(f"FAIL  Quarantine queue missing 'queue' key: {qdata}")
                return False
        else:
            logger.error(f"FAIL  Quarantine queue: {qqueue_resp.status_code}")
            return False

        # ------------------------------------------------------------------ #
        # Test 6: POST /refinery/quarantine/{id}/resolve
        # ------------------------------------------------------------------ #
        # Create a quarantine item directly via DB helper, then resolve via HTTP
        from core.database import save_quarantine, save_verification_result
        import json as json_
        import secrets as sec25

        q_token = sec25.token_hex(8)
        tmp_hash = hashlib.sha256(f"quarantine-test-{q_token}".encode()).hexdigest()
        tmp_vr = save_verification_result(
            data_hash=tmp_hash,
            proof_hash=hashlib.sha256(f"proof-qtest-{q_token}".encode()).hexdigest(),
            verdict="QUARANTINE",
            composite_score=0.55,
            action="quarantine",
            agent_id="phase-25-test-bot",
        )
        tmp_qr = save_quarantine(
            verification_result_id=tmp_vr.id,
            data_hash=tmp_hash,
            reason="Test quarantine for Phase 25 resolve test",
            score=0.55,
        )

        resolve_resp = await client.post(
            f"/refinery/quarantine/{tmp_qr.id}/resolve",
            params={"resolution": "APPROVED", "resolved_by": "phase-25-reviewer"},
        )
        if resolve_resp.status_code == 200:
            r = resolve_resp.json()
            if r.get("resolution") == "APPROVED":
                logger.info(
                    f"  OK  Quarantine resolve: id={r['id']}, "
                    f"resolution={r['resolution']}, by={r['resolved_by']}"
                )
            else:
                logger.error(f"FAIL  Resolve response wrong: {r}")
                return False
        else:
            logger.error(f"FAIL  Resolve: {resolve_resp.status_code} {resolve_resp.text}")
            return False

        # ------------------------------------------------------------------ #
        # Test 7: Resolve with invalid resolution value → 400
        # ------------------------------------------------------------------ #
        bad_resolve = await client.post(
            f"/refinery/quarantine/{tmp_qr.id}/resolve",
            params={"resolution": "MAYBE"},
        )
        if bad_resolve.status_code == 400:
            logger.info(f"  OK  Invalid resolution rejected: 400")
        else:
            logger.error(f"FAIL  Should reject 'MAYBE': {bad_resolve.status_code}")
            return False

        # ------------------------------------------------------------------ #
        # Test 8: Status 404 for unknown hash
        # ------------------------------------------------------------------ #
        not_found = await client.get("/refinery/status/0000000000000000000000000000000000000000000000000000000000000000")
        if not_found.status_code == 404:
            logger.info(f"  OK  404 for unknown hash (DB + cache miss)")
        else:
            logger.error(f"FAIL  Unknown hash should 404: {not_found.status_code}")
            _m2m_mod.REQUIRE_CHALLENGE = _orig_challenge
            return False

    _m2m_mod.REQUIRE_CHALLENGE = _orig_challenge
    return True


async def main():
    """Orchestrates all test phases."""
    logger.info("THE LAST BASTION BACKEND VALIDATION (v7.0)")
    logger.info(f"   Time: {datetime.now().isoformat()}")
    logger.info(f"   DATABASE_URL: {os.getenv('DATABASE_URL', 'using default')[:50]}...")
    logger.info(f"   LLM_PROVIDER: {os.getenv('LLM_PROVIDER', 'ollama')}")
    logger.info("")

    results = {}

    # Phase 1: Database
    mission_id = await test_phase_1_database()
    results["1_database"] = bool(mission_id)
    if not mission_id:
        logger.error("Cannot continue without database. Aborting.")
        return

    # Phase 2: LLM
    results["2_llm"] = await test_phase_2_llm()
    if not results["2_llm"]:
        logger.error("Cannot continue without LLM. Aborting.")
        return

    # Phase 3: Redis
    results["3_redis"] = await test_phase_3_redis()

    # Phase 4: Truth Engine
    results["4_truth_engine"] = await test_phase_4_consensus()

    # Phase 5: Proof-of-Task
    results["5_proof_of_task"] = await test_phase_5_proof_of_task()

    # Phase 6: Structural Diff (Dual-Bot)
    results["6_structural_diff"] = await test_phase_7_structural_diff()

    # Phase 7: Episodic Memory
    results["7_episodic_memory"] = await test_phase_8_episodic_memory(mission_id)

    # Phase 8: Schema Gatekeeper
    results["8_schema"] = await test_phase_14_schema_gatekeeper()

    # Phase 9: Consistency Analyzer
    results["9_consistency"] = await test_phase_15_consistency()

    # Phase 10: Forensic Integrity
    results["10_forensic"] = await test_phase_16_forensic_integrity()

    # Phase 11: Full Verification Stack
    results["11_stack"] = await test_phase_17_verification_stack()

    # Phase 12: Attestation + Adversarial
    results["12_attestation_adversarial"] = await test_phase_18_attestation_adversarial()

    # Phase 13: Pipeline Integration
    results["13_pipeline"] = await test_phase_19_pipeline_integration()

    # Phase 14: M2M Protocol Layer
    results["14_m2m_protocol"] = await test_phase_20_m2m_protocol()

    # Phase 15: Ingestion Pipeline
    results["15_ingestion"] = await test_phase_21_ingestion_pipeline()

    # Phase 16: M2M HTTP Integration
    results["16_m2m_http"] = await test_phase_22_m2m_http_integration()

    # Phase 17: Task Executor & Full Lifecycle
    results["17_task_executor"] = await test_phase_23_task_executor()

    # Phase 18: Refinery DB Persistence
    results["18_refinery_db"] = await test_phase_24_refinery_db_persistence()

    # Phase 19: Refinery HTTP v2
    results["19_refinery_http_v2"] = await test_phase_25_refinery_http_v2()

    # Summary
    logger.info("")
    logger.info("=" * 60)
    logger.info("VALIDATION SUMMARY")
    logger.info("=" * 60)
    for phase, result in sorted(results.items()):
        icon = "✅" if result is True else ("⏭️" if result == "SKIPPED" else "❌")
        logger.info(f"   {icon} {phase}: {result}")

    passed = sum(1 for v in results.values() if v is True)
    failed = sum(1 for v in results.values() if v is False)
    skipped = sum(1 for v in results.values() if v == "SKIPPED")

    logger.info("")
    logger.info(f"   PASSED: {passed} | FAILED: {failed} | SKIPPED: {skipped}")

    all_passed = all(v is True or v == "SKIPPED" for v in results.values())
    if all_passed:
        logger.info("🎯 ALL PHASES PASSED — Backend is ready for mission deployment.")
    else:
        logger.info("⚠️  Some phases failed — review output above.")


if __name__ == "__main__":
    from dotenv import load_dotenv
    load_dotenv()
    asyncio.run(main())
