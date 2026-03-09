"""
The Last Bastion MCP Server — Model Context Protocol interface.

Exposes The Last Bastion's verification, proof lookup, agent trust,
and protocol monitoring as MCP tools that other AI agents
(Claude, GPT, etc.) can call directly.

Run standalone:
    python -m core.mcp_server

Or import and mount alongside the FastAPI app.
"""
import asyncio
import hashlib
import json
import logging
import secrets
from datetime import datetime
from typing import Any

from mcp.server.fastmcp import FastMCP

logger = logging.getLogger("MCP_SERVER")

# Create the MCP server
mcp = FastMCP(
    "The Last Bastion",
    instructions="The Last Bastion — neutral verification platform for AI agents. Use these tools to generate agent passports, verify them through a 10-check pipeline, and manage agent trust.",
)


# ---------------------------------------------------------------------------
# HELPER: lazy-load heavy dependencies to avoid circular imports
# ---------------------------------------------------------------------------

def _get_verification_pipeline():
    from core.verification.pipeline import VerificationPipeline
    from core.blockchain_anchor import BlockchainAnchor
    anchor = BlockchainAnchor()
    return VerificationPipeline(blockchain_anchor=anchor)

def _get_db_helpers():
    from core.database import (
        get_verification_by_hash,
        get_verification_by_proof_hash,
        get_refinery_stats,
        get_quarantine_queue,
        save_raw_submission,
        save_cleaned_data,
        get_agent_trust,
    )
    return {
        "get_verification_by_hash": get_verification_by_hash,
        "get_verification_by_proof_hash": get_verification_by_proof_hash,
        "get_refinery_stats": get_refinery_stats,
        "get_quarantine_queue": get_quarantine_queue,
        "save_raw_submission": save_raw_submission,
        "save_cleaned_data": save_cleaned_data,
        "get_agent_trust": get_agent_trust,
    }


# ---------------------------------------------------------------------------
# TOOLS
# ---------------------------------------------------------------------------

@mcp.tool()
async def verify_data(
    payload: dict,
    source_agent_id: str = "mcp-client",
    document_type: str = "json_submission",
) -> dict:
    """
    Submit data for verification through The Last Bastion's 5-layer pipeline.

    The pipeline runs:
    1. Schema Gatekeeper — structural + injection detection
    2. Consistency Analyzer — arithmetic, cross-field logic
    3. Forensic Integrity — ELA, noise, metadata analysis
    4. Logic Triangulation — cross-reference, temporal, domain
    5. Adversarial Challenge — devil's advocate scoring

    Returns a verdict (REJECTED / QUARANTINE / VERIFIED / GOLD),
    confidence score (0.0–1.0), and a tamper-evident proof hash.

    Args:
        payload: The data to verify (JSON object)
        source_agent_id: Identifier of the submitting agent
        document_type: Type of document (e.g., "invoice", "receipt", "json_submission")
    """
    db = _get_db_helpers()
    pipeline = _get_verification_pipeline()

    canonical = json.dumps(payload, sort_keys=True, separators=(",", ":")).encode()
    data_hash = hashlib.sha256(canonical).hexdigest()

    # Check for existing verification
    existing = db["get_verification_by_hash"](data_hash)
    if existing:
        return {
            "data_hash": data_hash,
            "verdict": existing["verdict"],
            "score": existing["score"],
            "proof_hash": existing["proof_hash"],
            "cached": True,
        }

    # Persist ingestion record
    submission_id = f"sub-{secrets.token_hex(8)}"
    try:
        db["save_raw_submission"](
            submission_id=submission_id,
            data_hash=data_hash,
            source_agent_id=source_agent_id,
            submission_protocol="mcp",
            format="json",
            raw_size_bytes=len(canonical),
            provenance={"source_agent_id": source_agent_id, "protocol": "mcp"},
        )
        db["save_cleaned_data"](
            submission_id=submission_id,
            structured_data=payload,
            confidence=1.0,
            document_type=document_type,
        )
    except Exception:
        pass

    # Run verification
    context = {"submission_id": submission_id, "data_hash": data_hash}
    result = await pipeline.process_mission_result(
        mission_id=hash(data_hash) % 100000,
        agent_id=source_agent_id,
        payload=payload,
        context=context,
    )

    return {
        "data_hash": data_hash,
        "submission_id": submission_id,
        "verdict": result["verdict"],
        "score": result["score"],
        "proof_hash": result["proof_hash"],
        "cached": False,
    }


@mcp.tool()
async def lookup_proof(data_hash: str) -> dict:
    """
    Look up a verification proof by data hash.

    Returns the full verification result including verdict, score,
    proof hash, and submission details. Returns null if not found.

    Args:
        data_hash: SHA-256 hash of the original data
    """
    db = _get_db_helpers()
    result = db["get_verification_by_hash"](data_hash)
    if not result:
        return {"found": False, "data_hash": data_hash}
    return {"found": True, **result}


@mcp.tool()
async def lookup_proof_by_hash(proof_hash: str) -> dict:
    """
    Look up a verification record by its proof hash (Merkle chain hash).

    This is the tamper-evident hash from the proof ledger.
    Can be used to verify a proof's authenticity.

    Args:
        proof_hash: The proof hash from the Merkle chain ledger
    """
    db = _get_db_helpers()
    result = db["get_verification_by_proof_hash"](proof_hash)
    if not result:
        return {"found": False, "proof_hash": proof_hash}
    return {"found": True, **result}


@mcp.tool()
async def get_agent_trust_passport(agent_id: str) -> dict:
    """
    Get the trust passport for a registered agent.

    Returns trust score (0.0–1.0), verification checks breakdown
    (identity, crypto, capability, reputation, behavior, network),
    risk flags, blockchain proof hash, and expiry.

    Args:
        agent_id: The agent's unique identifier
    """
    db = _get_db_helpers()
    trust = db["get_agent_trust"](agent_id)
    if not trust:
        return {"agent_id": agent_id, "status": "UNVERIFIED", "message": "No trust record found"}
    return {"agent_id": agent_id, **trust}


@mcp.tool()
async def get_pipeline_stats() -> dict:
    """
    Get aggregate statistics from the verification pipeline.

    Returns total submissions, verdict counts (verified, gold,
    quarantine, rejected), blockchain stamps, quarantine pending,
    reversal rate, and average scores per verdict.
    """
    db = _get_db_helpers()
    return db["get_refinery_stats"]()


@mcp.tool()
async def get_quarantine_items(limit: int = 20) -> dict:
    """
    Get items currently in the quarantine queue (scored 40-70).

    These items need human review. Returns data hash, score,
    reason for quarantine, and creation time.

    Args:
        limit: Maximum number of items to return (default 20)
    """
    db = _get_db_helpers()
    queue = db["get_quarantine_queue"](limit=limit)
    return {"count": len(queue), "items": queue}


@mcp.tool()
async def get_protocol_messages(
    limit: int = 50,
    message_type: str = "",
    sender_id: str = "",
    auth_result: str = "",
) -> dict:
    """
    Query the M2M protocol message bus.

    Returns recent protocol messages between agents including
    REGISTER, DISCOVER, TASK_SUBMIT, VERIFY_REQUEST, HANDOFF_REQUEST,
    etc. Messages include auth results, timing, and payload summaries.

    Args:
        limit: Maximum number of messages (default 50)
        message_type: Filter by message type (e.g., "REGISTER", "HANDOFF_REQUEST")
        sender_id: Filter by sender agent ID
        auth_result: Filter by auth result ("AUTHENTICATED", "REJECTED", "SKIPPED")
    """
    from core.protocol_bus import protocol_bus
    messages = protocol_bus.query(
        limit=limit,
        message_type=message_type or None,
        sender_id=sender_id or None,
        auth_result=auth_result or None,
    )
    stats = protocol_bus.get_stats()
    return {"messages": messages, "stats": stats}


@mcp.tool()
async def verify_chain_integrity() -> dict:
    """
    Verify the integrity of the proof ledger's Merkle chain.

    Walks every record in the proof ledger and recomputes all hashes.
    Any tampering breaks the chain. Returns whether the chain is intact
    and the total number of records verified.
    """
    pipeline = _get_verification_pipeline()
    ledger = pipeline.ledger
    try:
        is_valid = ledger.verify_chain_integrity()
        return {
            "chain_intact": is_valid,
            "total_records": len(ledger._records),
            "message": "Merkle chain integrity verified" if is_valid else "CHAIN BROKEN — tampering detected",
        }
    except Exception as e:
        return {"chain_intact": False, "error": str(e)}


# ---------------------------------------------------------------------------
# RESOURCES
# ---------------------------------------------------------------------------

@mcp.resource("registry-base://stats")
async def stats_resource() -> str:
    """Current The Last Bastion pipeline statistics."""
    db = _get_db_helpers()
    stats = db["get_refinery_stats"]()
    return json.dumps(stats, indent=2)


@mcp.resource("registry-base://services")
async def services_resource() -> str:
    """Available The Last Bastion services and their credit costs."""
    return json.dumps({
        "services": [
            {"id": "svc-data-extraction", "name": "Data Extraction", "credits": 5, "description": "Extract structured data from URLs via browser automation"},
            {"id": "svc-document-verification", "name": "Document Verification", "credits": 3, "description": "5-layer verification pipeline with blockchain proof"},
            {"id": "svc-market-intelligence", "name": "Market Intelligence", "credits": 2, "description": "Regional market data aggregation"},
            {"id": "svc-attestation-proof", "name": "Attestation Proof", "credits": 4, "description": "GPS, device, depth attestation verification"},
        ],
        "blockchain": {
            "network": "Polygon Amoy",
            "proof_registry": "0x110affBAC98FCC6b86Da499550B1fC0aCA22e946",
            "agent_registry": "0xc9177baBF86FF16794AABd1a2169f898986a0D7D",
        },
    }, indent=2)


@mcp.resource("registry-base://thresholds")
async def thresholds_resource() -> str:
    """Current verification score thresholds and their meanings."""
    return json.dumps({
        "thresholds": {
            "REJECTED": {"range": "0.00 — 0.40", "action": "Data discarded, agent flagged"},
            "QUARANTINE": {"range": "0.40 — 0.70", "action": "Held for human review"},
            "VERIFIED": {"range": "0.70 — 0.90", "action": "Stored + blockchain stamp"},
            "GOLD": {"range": "0.90 — 1.00", "action": "Highest trust, requires forensic >= 0.80"},
        },
        "veto_rights": ["SchemaGatekeeper (gate 1)", "LogicTriangulation (pillar 2)"],
        "note": "A veto forces score <= 0.10 regardless of other pillars",
    }, indent=2)


# ---------------------------------------------------------------------------
# PROMPTS
# ---------------------------------------------------------------------------

@mcp.prompt()
async def verify_document(document_type: str = "invoice") -> str:
    """Generate a prompt for verifying a specific document type through The Last Bastion."""
    return f"""You are using The Last Bastion's verification pipeline to verify a {document_type}.

Steps:
1. Use the verify_data tool to submit the {document_type} data as a JSON payload
2. Check the verdict: REJECTED, QUARANTINE, VERIFIED, or GOLD
3. If QUARANTINE, the data needs human review — use get_quarantine_items to check the queue
4. Use lookup_proof to verify the proof hash is recorded
5. Use verify_chain_integrity to confirm the Merkle chain is intact

The verification runs through 5 layers:
- Schema Gatekeeper (injection detection, structural validation)
- Consistency Analyzer (arithmetic checks, anomaly detection)
- Forensic Integrity (image/file forensics)
- Logic Triangulation (cross-reference, temporal, domain logic)
- Adversarial Challenge (devil's advocate scoring)

Score thresholds: <0.40 REJECTED, 0.40-0.70 QUARANTINE, 0.70-0.90 VERIFIED, >=0.90 GOLD"""


@mcp.prompt()
async def check_agent_trust(agent_id: str = "") -> str:
    """Generate a prompt for checking an agent's trust status."""
    target = f" for agent '{agent_id}'" if agent_id else ""
    return f"""You are checking the trust passport{target} on The Last Bastion.

Steps:
1. Use get_agent_trust_passport with the agent_id to get their trust record
2. Review the 6 verification checks: identity, crypto, capability, reputation, behavior, network
3. Check for risk flags
4. Note the overall verdict: TRUSTED, SUSPICIOUS, MALICIOUS, or UNVERIFIED
5. Check blockchain proof hash for on-chain verification

If the agent is UNVERIFIED, they haven't been through the trust verification pipeline yet."""


# ---------------------------------------------------------------------------
# PASSPORT TOOLS — for Claude.ai / MCP integration
# ---------------------------------------------------------------------------

@mcp.tool()
async def generate_passport(
    agent_name: str = "My Agent",
    agent_id: str = "",
) -> dict:
    """
    Generate a fresh Agent Passport with Ed25519 keypair.

    This creates a cryptographically signed passport that can be uploaded
    to The Last Bastion for verification. The passport contains the agent's
    identity, public key, and is signed by an issuer keypair.

    Returns the passport details and base64-encoded signed envelope
    ready for upload.

    Args:
        agent_name: Human-readable name for the agent
        agent_id: Unique agent identifier (auto-generated if empty)
    """
    import base64
    import os
    import tempfile

    try:
        from lastbastion.passport_generator import generate_passport_file

        with tempfile.TemporaryDirectory() as tmpdir:
            result = generate_passport_file(
                output_path=os.path.join(tmpdir, "agent.passport"),
                agent_name=agent_name,
                agent_id=agent_id,
            )
            with open(result["passport"], "rb") as f:
                envelope_bytes = f.read()

            return {
                "status": "success",
                "agent_id": result["agent_id"],
                "passport_id": result["passport_id"],
                "public_key": result["public_key"],
                "envelope_b64": base64.b64encode(envelope_bytes).decode(),
                "message": (
                    f"Passport generated for '{agent_name}' ({result['agent_id']}). "
                    f"Use upload_passport to submit it for verification."
                ),
            }
    except Exception as e:
        return {"status": "error", "message": str(e)}


@mcp.tool()
async def upload_passport(
    envelope_b64: str,
    agent_name: str = "",
) -> dict:
    """
    Upload a passport to The Last Bastion for 10-check verification.

    The passport goes through identity verification, cryptographic checks,
    behavioral analysis, anti-Sybil detection, and more. Returns detailed
    per-check results with scores.

    After upload, the passport is in PENDING_REVIEW status.
    Use approve_passport to approve it.

    Args:
        envelope_b64: Base64-encoded signed passport envelope (from generate_passport)
        agent_name: Optional human-readable name
    """
    import httpx

    try:
        async with httpx.AsyncClient(timeout=30) as client:
            resp = await client.post(
                "http://localhost:8000/sandbox/passport/upload",
                json={"passport_b64": envelope_b64, "agent_name": agent_name},
            )
            if resp.status_code != 200:
                return {"status": "error", "message": f"Upload failed ({resp.status_code}): {resp.text}"}
            data = resp.json()
            return {
                "status": "success",
                "verification_id": data.get("id"),
                "agent_id": data.get("agent_id"),
                "passport_id": data.get("passport_id"),
                "trust_score": data.get("trust_score"),
                "checks": data.get("checks", {}),
                "risk_flags": data.get("risk_flags", []),
                "message": (
                    f"Passport verified with score {data.get('trust_score', 0):.2f}. "
                    f"Status: {data.get('status')}. "
                    f"Use approve_passport with verification_id={data.get('id')} to approve."
                ),
            }
    except Exception as e:
        return {"status": "error", "message": str(e)}


@mcp.tool()
async def approve_passport(verification_id: int) -> dict:
    """
    Approve a passport that has been uploaded and verified.

    After approval, the agent can connect to the Border Police
    on port 9200 via the Bastion Binary Protocol (Ed25519 + X25519).

    Args:
        verification_id: The verification ID returned from upload_passport
    """
    import httpx

    try:
        async with httpx.AsyncClient(timeout=15) as client:
            resp = await client.post(
                f"http://localhost:8000/sandbox/passport/{verification_id}/approve",
            )
            if resp.status_code != 200:
                return {"status": "error", "message": f"Approve failed ({resp.status_code}): {resp.text}"}
            data = resp.json()
            return {
                "status": "success",
                "verdict": "APPROVED",
                "message": (
                    "Passport approved! The agent can now connect to the Border Police "
                    "on port 9200 via the Bastion Binary Protocol."
                ),
            }
    except Exception as e:
        return {"status": "error", "message": str(e)}


@mcp.tool()
async def full_passport_demo(
    agent_name: str = "Claude MCP Agent",
) -> dict:
    """
    Run the complete passport verification demo in one step.

    This generates a passport, uploads it for 10-check verification,
    auto-approves it, and returns the full results. Perfect for
    demonstrating The Last Bastion's agent verification pipeline.

    Steps performed:
    1. Generate Ed25519 keypair + Agent Passport
    2. Upload to The Last Bastion (runs 10-check pipeline)
    3. Auto-approve the passport
    4. Return complete verification results

    Args:
        agent_name: Name for the demo agent
    """
    import httpx
    import base64
    import os
    import tempfile

    steps = []

    try:
        # Step 1: Generate passport
        from lastbastion.passport_generator import generate_passport_file

        with tempfile.TemporaryDirectory() as tmpdir:
            result = generate_passport_file(
                output_path=os.path.join(tmpdir, "agent.passport"),
                agent_name=agent_name,
            )
            with open(result["passport"], "rb") as f:
                envelope_bytes = f.read()

        envelope_b64 = base64.b64encode(envelope_bytes).decode()
        steps.append({
            "step": "passport_generated",
            "agent_id": result["agent_id"],
            "passport_id": result["passport_id"],
            "public_key": result["public_key"][:32] + "...",
        })

        # Step 2: Upload for verification
        async with httpx.AsyncClient(timeout=30) as client:
            resp = await client.post(
                "http://localhost:8000/sandbox/passport/upload",
                json={"passport_b64": envelope_b64, "agent_name": agent_name},
            )
            if resp.status_code != 200:
                return {"status": "error", "step": "upload", "message": resp.text}
            upload_data = resp.json()

        verification_id = upload_data.get("id")
        steps.append({
            "step": "uploaded_and_verified",
            "verification_id": verification_id,
            "trust_score": upload_data.get("trust_score"),
            "checks": upload_data.get("checks", {}),
            "risk_flags": upload_data.get("risk_flags", []),
        })

        # Step 3: Auto-approve
        async with httpx.AsyncClient(timeout=15) as client:
            resp = await client.post(
                f"http://localhost:8000/sandbox/passport/{verification_id}/approve",
            )
            if resp.status_code != 200:
                return {"status": "error", "step": "approve", "message": resp.text}

        steps.append({
            "step": "passport_approved",
            "verdict": "APPROVED",
        })

        return {
            "status": "success",
            "agent_id": result["agent_id"],
            "passport_id": result["passport_id"],
            "trust_score": upload_data.get("trust_score"),
            "verdict": "APPROVED",
            "steps": steps,
            "message": (
                f"Complete! Agent '{agent_name}' ({result['agent_id']}) has been verified "
                f"through the 10-check pipeline (score: {upload_data.get('trust_score', 0):.2f}) "
                f"and approved. The agent can now connect to the Border Police via the "
                f"Bastion Binary Protocol (Ed25519 + X25519 encrypted channel)."
            ),
        }
    except Exception as e:
        return {"status": "error", "message": str(e), "steps": steps}


@mcp.tool()
async def list_approved_passports() -> dict:
    """
    List all approved agent passports.

    Shows which agents have been verified and approved to connect
    to the Border Police via the binary protocol.
    """
    import httpx

    try:
        async with httpx.AsyncClient(timeout=15) as client:
            resp = await client.get("http://localhost:8000/sandbox/passport/approved")
            if resp.status_code != 200:
                return {"status": "error", "message": resp.text}
            data = resp.json()
            return {
                "status": "success",
                "count": len(data.get("passports", data if isinstance(data, list) else [])),
                "passports": data.get("passports", data if isinstance(data, list) else []),
            }
    except Exception as e:
        return {"status": "error", "message": str(e)}


@mcp.tool()
async def list_pending_passports() -> dict:
    """
    List passports waiting for review.

    These have been uploaded and verified but not yet approved or rejected.
    """
    import httpx

    try:
        async with httpx.AsyncClient(timeout=15) as client:
            resp = await client.get("http://localhost:8000/sandbox/passport/pending")
            if resp.status_code != 200:
                return {"status": "error", "message": resp.text}
            data = resp.json()
            return {
                "status": "success",
                "count": len(data.get("passports", data if isinstance(data, list) else [])),
                "passports": data.get("passports", data if isinstance(data, list) else []),
            }
    except Exception as e:
        return {"status": "error", "message": str(e)}


@mcp.prompt()
async def passport_demo() -> str:
    """Walk through the full agent passport verification demo."""
    return """You are demonstrating The Last Bastion's agent verification system.

Walk the user through this process step by step:

1. Use full_passport_demo to generate, verify, and approve a passport in one step
2. Explain each check result to the user in plain English
3. Show the trust score and what it means
4. Explain that the approved agent could now connect via the Bastion Binary Protocol

Key concepts to explain:
- Ed25519 cryptographic signatures (the agent's identity)
- 10-check verification pipeline (identity, crypto, behavioral, anti-Sybil, etc.)
- Trust scores: 0.0-1.0, with thresholds for different trust levels
- The Bastion Binary Protocol: encrypted agent-to-agent communication
- Blockchain anchoring: proofs stamped on Polygon for tamper evidence

Keep explanations simple and non-technical for non-programmers.
If the user is a developer, they can ask for technical details."""


# ---------------------------------------------------------------------------
# AUDIT TOOLS — let LLMs independently verify the system works
# ---------------------------------------------------------------------------

@mcp.tool()
async def test_bad_passport(
    defect_type: str = "tampered",
) -> dict:
    """
    Generate a deliberately BROKEN passport and submit it for verification.
    Use this to independently test whether the system catches specific attacks.

    This is the key tool for auditing — if the system blindly accepts broken
    passports, it's not doing real verification. If it catches them, it is.

    Defect types:
    - tampered: crypto_hash corrupted after signing (integrity check should catch it)
    - expired: expires_at set to yesterday (temporal check should catch it)
    - injected: SQL/XSS payload in agent_name (schema gatekeeper should catch it)
    - wrong_key: signed with a different key than claimed public_key (crypto check should catch it)
    - sybil: uses a known duplicate public_key (anti-Sybil check should catch it)

    Args:
        defect_type: One of: tampered, expired, injected, wrong_key, sybil
    """
    import base64
    import os
    import tempfile
    import httpx

    try:
        from lastbastion.passport_generator import generate_bad_passport_file

        with tempfile.TemporaryDirectory() as tmpdir:
            result = generate_bad_passport_file(
                output_path=os.path.join(tmpdir, "bad.passport"),
                defect_type=defect_type,
            )
            with open(result["passport"], "rb") as f:
                envelope_bytes = f.read()

        envelope_b64 = base64.b64encode(envelope_bytes).decode()

        async with httpx.AsyncClient(timeout=30) as client:
            resp = await client.post(
                "http://localhost:8000/sandbox/passport/upload",
                json={"passport_b64": envelope_b64, "agent_name": f"Bad Agent ({defect_type})"},
            )

            if resp.status_code != 200:
                return {
                    "defect_type": defect_type,
                    "defect_description": result.get("defect", ""),
                    "rejected_at_upload": True,
                    "http_status": resp.status_code,
                    "rejection_reason": resp.text[:300],
                }

            data = resp.json()

        return {
            "defect_type": defect_type,
            "defect_description": result.get("defect", ""),
            "accepted_for_review": True,
            "trust_score": data.get("trust_score"),
            "checks": data.get("checks", {}),
            "risk_flags": data.get("risk_flags", []),
            "verdict": data.get("verdict"),
        }
    except Exception as e:
        return {"status": "error", "message": str(e)}


@mcp.tool()
async def test_all_defects() -> dict:
    """
    Run ALL 5 defect types against the verification system at once.
    Generates 5 broken passports (tampered, expired, injected, wrong_key, sybil)
    and 1 clean passport, submits each, and returns comparative results.

    This is the comprehensive audit — you can see whether each specific
    attack type was caught by the appropriate check. If all 5 bad passports
    are caught and the clean one passes, the system is working correctly.
    """
    results = {}

    # Test clean passport first
    clean_result = await full_passport_demo(agent_name="Audit Clean Agent")
    results["clean"] = {
        "type": "clean (no defects)",
        "trust_score": clean_result.get("trust_score"),
        "verdict": clean_result.get("verdict"),
        "status": clean_result.get("status"),
    }

    # Test each defect type
    for defect in ["tampered", "expired", "injected", "wrong_key", "sybil"]:
        result = await test_bad_passport(defect_type=defect)
        results[defect] = {
            "type": defect,
            "defect": result.get("defect_description", ""),
            "trust_score": result.get("trust_score"),
            "verdict": result.get("verdict"),
            "rejected_at_upload": result.get("rejected_at_upload", False),
            "risk_flags": result.get("risk_flags", []),
            "checks": result.get("checks", {}),
        }

    # Summary
    clean_passed = results["clean"].get("verdict") == "APPROVED" or results["clean"].get("status") == "success"
    bad_caught = sum(
        1 for k, v in results.items()
        if k != "clean" and (
            v.get("rejected_at_upload") or
            v.get("trust_score", 1.0) < 0.5 or
            len(v.get("risk_flags", [])) > 0
        )
    )

    return {
        "results": results,
        "summary": {
            "clean_passport_passed": clean_passed,
            "bad_passports_caught": f"{bad_caught}/5",
            "defect_types_tested": ["tampered", "expired", "injected", "wrong_key", "sybil"],
        },
    }


@mcp.tool()
async def inspect_verification_checks() -> dict:
    """
    Describe what each of the 10 agent verification checks does.
    Returns the check names, what they look for, and what attacks they prevent.
    This is factual information about the system's design — not a claim about
    whether it works. Use test_bad_passport or test_all_defects to verify.
    """
    return {
        "checks": {
            "identity_verification": {
                "what_it_does": "Verifies agent_id format, agent_name for injection patterns, company_domain validity",
                "attacks_prevented": "Identity spoofing, injection attacks via agent metadata",
            },
            "cryptographic_verification": {
                "what_it_does": "Verifies Ed25519 public key format (64 hex chars = 32 bytes), checks signature validity on the passport envelope",
                "attacks_prevented": "Forged passports, key substitution attacks",
            },
            "integrity_check": {
                "what_it_does": "Recomputes SHA-256 crypto_hash from passport fields, compares to the stored hash",
                "attacks_prevented": "Post-signing tampering — any field change breaks the hash",
            },
            "temporal_check": {
                "what_it_does": "Checks issued_at is not in the future, expires_at is not in the past, passport age is reasonable",
                "attacks_prevented": "Expired credential reuse, backdated passports",
            },
            "behavioral_analysis": {
                "what_it_does": "Analyzes agent_name for suspicious patterns, checks trust_score claims against metadata",
                "attacks_prevented": "Social engineering via misleading names, inflated trust claims",
            },
            "anti_sybil": {
                "what_it_does": "Checks if the public_key has been seen in previous verifications (duplicate key = Sybil)",
                "attacks_prevented": "Sybil attacks — one entity creating many fake identities with the same key",
            },
            "payload_integrity": {
                "what_it_does": "Verifies the envelope structure: correct size, valid MessagePack, 64-byte signature present",
                "attacks_prevented": "Malformed envelopes, truncated or padded data",
            },
            "network_analysis": {
                "what_it_does": "Checks geo_ip, geo_country, runtime_fingerprint for consistency",
                "attacks_prevented": "Clone attacks — same agent appearing from impossible locations",
            },
            "budget_check": {
                "what_it_does": "Verifies interaction_budget > 0, budget_max is reasonable, not exhausted",
                "attacks_prevented": "Resource exhaustion, budget manipulation",
            },
            "schema_gatekeeper": {
                "what_it_does": "Scans all string fields for SQL injection, XSS, Python injection, path traversal patterns",
                "attacks_prevented": "Injection attacks embedded in passport metadata",
            },
        },
        "note": "These are the checks the system is designed to run. To verify they actually work, use test_bad_passport with each defect type and inspect the results.",
    }


@mcp.tool()
async def inspect_proof_ledger(last_n: int = 5) -> dict:
    """
    Inspect the last N entries in the proof ledger (Merkle chain).

    The proof ledger is an append-only chain where each record's hash
    includes the previous record's hash. Any tampering breaks the chain.
    Use verify_chain_integrity to check the full chain.

    Args:
        last_n: Number of recent entries to show (default 5)
    """
    try:
        from core.verification.proof_ledger import ProofLedger
        ledger = ProofLedger()

        records = ledger._records[-last_n:] if ledger._records else []
        chain_valid = ledger.verify_chain_integrity() if ledger._records else True

        return {
            "total_records": len(ledger._records),
            "chain_intact": chain_valid,
            "recent_entries": [
                {
                    "index": i,
                    "proof_hash": r.get("proof_hash", "")[:32] + "...",
                    "previous_hash": r.get("previous_hash", "")[:32] + "..." if r.get("previous_hash") else "GENESIS",
                    "verdict": r.get("verdict"),
                    "score": r.get("score"),
                    "timestamp": r.get("timestamp"),
                }
                for i, r in enumerate(records)
            ],
            "chain_structure": "Each record's hash = SHA-256(payload + previous_hash). Tampering any record breaks all subsequent hashes.",
        }
    except Exception as e:
        return {"status": "error", "message": str(e)}


@mcp.tool()
async def get_border_police_status() -> dict:
    """
    Check if the Border Police agent is running and get its status.

    The Border Police is a separate TCP server (port 9200) that authenticates
    agents via the Bastion Binary Protocol before allowing LLM conversation.

    This tool checks if it's reachable — useful for verifying the system
    is actually running two separate agents, not faking it.
    """
    import httpx

    try:
        # Try to get status from the main API
        async with httpx.AsyncClient(timeout=5) as client:
            resp = await client.get("http://localhost:8000/m2m/dashboard/stats")
            api_running = resp.status_code == 200
    except Exception:
        api_running = False

    # Try TCP connect to Border Police
    import asyncio
    bp_running = False
    try:
        reader, writer = await asyncio.wait_for(
            asyncio.open_connection("localhost", 9200), timeout=3
        )
        bp_running = True
        writer.close()
        await writer.wait_closed()
    except Exception:
        bp_running = False

    return {
        "api_server": {"running": api_running, "url": "http://localhost:8000"},
        "border_police": {"running": bp_running, "host": "localhost", "port": 9200, "protocol": "Bastion Binary Protocol v2 (TCP)"},
        "separate_processes": "The API server and Border Police are independent — Border Police is a TCP server, not an HTTP endpoint",
    }


# ---------------------------------------------------------------------------
# STARLETTE APP — for mounting in FastAPI (Claude.ai integration)
# ---------------------------------------------------------------------------

def get_mcp_app():
    """
    Return the MCP server as a Starlette ASGI app for mounting.

    Mount in FastAPI:
        from core.mcp_server import get_mcp_app
        app.mount("/mcp", get_mcp_app())

    Then add to Claude.ai:
        Settings → Integrations → Add → URL: https://your-domain.com/mcp
    """
    return mcp.streamable_http_app()


# ---------------------------------------------------------------------------
# ENTRY POINT
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    import sys

    transport = "stdio"
    if "--http" in sys.argv or "--streamable-http" in sys.argv:
        transport = "streamable-http"
    elif "--sse" in sys.argv:
        transport = "sse"

    print(f"Starting MCP server with {transport} transport...")
    mcp.run(transport=transport)
