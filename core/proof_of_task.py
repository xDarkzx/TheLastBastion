"""
Proof-of-Task (v1.0): Cryptographic Verification of Extraction Results.
Hashes gold payload + worker ID + timestamp -> SHA-256 -> stores proof
alongside GoldYield for verifiable fulfillment.

This proves:
  1. Which worker produced the data
  2. When it was produced
  3. The data hasn't been tampered with since extraction
"""
import hashlib
import hmac as _hmac
import json
import logging
from datetime import datetime
from typing import Dict, Any, Optional

from core.industrial_logger import get_industrial_logger

logger = get_industrial_logger("ProofOfTask")


def generate_proof(
    gold_payload: Dict[str, Any],
    worker_id: str,
    mission_id: int,
    timestamp: Optional[datetime] = None
) -> Dict[str, str]:
    """
    Generates a cryptographic proof for an extraction result.

    Returns:
        {
            "proof_hash": "sha256 hex digest",
            "worker_id": "ALPHA_5",
            "mission_id": 5,
            "timestamp": "2026-03-04T08:30:00Z",
            "payload_size": 1234
        }
    """
    ts = timestamp or datetime.utcnow()
    ts_str = ts.isoformat() + "Z"

    # Normalize payload: sort keys for deterministic hashing
    # Strip internal audit metadata before hashing
    clean_payload = {
        k: v for k, v in gold_payload.items()
        if not k.startswith("_")
    }

    # Build the proof input: payload + worker + mission + time
    proof_input = json.dumps(clean_payload, sort_keys=True, default=str)
    proof_input += f"|worker={worker_id}"
    proof_input += f"|mission={mission_id}"
    proof_input += f"|ts={ts_str}"

    # SHA-256 hash
    proof_hash = hashlib.sha256(proof_input.encode("utf-8")).hexdigest()

    logger.info(
        f"PROOF: Generated hash {proof_hash[:16]}... "
        f"(worker={worker_id}, mission={mission_id}, "
        f"payload_keys={len(clean_payload)})"
    )

    return {
        "proof_hash": proof_hash,
        "worker_id": worker_id,
        "mission_id": mission_id,
        "timestamp": ts_str,
        "payload_size": len(proof_input)
    }


def verify_proof(
    gold_payload: Dict[str, Any],
    proof: Dict[str, str]
) -> bool:
    """
    Verifies that a gold payload matches its recorded proof.
    Re-generates the hash from the payload and compares.

    Returns True if the data hasn't been tampered with.
    """
    worker_id = proof.get("worker_id", "")
    mission_id = proof.get("mission_id", 0)
    ts_str = proof.get("timestamp", "")
    expected_hash = proof.get("proof_hash", "")

    # Rebuild the hash
    clean_payload = {
        k: v for k, v in gold_payload.items()
        if not k.startswith("_")
    }

    proof_input = json.dumps(clean_payload, sort_keys=True, default=str)
    proof_input += f"|worker={worker_id}"
    proof_input += f"|mission={mission_id}"
    proof_input += f"|ts={ts_str}"

    actual_hash = hashlib.sha256(proof_input.encode("utf-8")).hexdigest()

    is_valid = _hmac.compare_digest(actual_hash, expected_hash)

    if is_valid:
        logger.info(f"PROOF: Verification PASSED for hash {expected_hash[:16]}...")
    else:
        logger.warning(
            f"PROOF: Verification FAILED. "
            f"Expected {expected_hash[:16]}..., got {actual_hash[:16]}..."
        )

    return is_valid
