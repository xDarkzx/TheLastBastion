"""
Proof Ledger — Blockchain-Ready Verification Audit Trail.

Each verification verdict produces a ProofRecord that:
1. Hashes the verdict + evidence into a Merkle leaf
2. Chains it to the previous record (like a blockchain)
3. Stores the full evidence chain for audit replay
4. Is structured for future smart contract submission

The chain is tamper-evident: changing ANY record breaks
the chain hash of every subsequent record.

Architecture:
    ┌──────────────┐    ┌──────────────┐    ┌──────────────┐
    │  Record #1   │───▶│  Record #2   │───▶│  Record #3   │
    │  prev: 0x00  │    │  prev: hash1 │    │  prev: hash2 │
    │  data: {...}  │    │  data: {...}  │    │  data: {...}  │
    │  hash: hash1 │    │  hash: hash2 │    │  hash: hash3 │
    └──────────────┘    └──────────────┘    └──────────────┘

Future: These records can be batch-submitted to a smart contract
        on Ethereum/Polygon/Solana for immutable public proof.
"""
import asyncio
import hashlib
import json
import logging
import os
import threading
import time
from dataclasses import asdict, dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional

from core.verification.models import VerificationVerdict

logger = logging.getLogger("ProofLedger")


@dataclass
class ProofRecord:
    """
    A single entry in the proof ledger.

    Contains everything needed to verify and replay a decision:
    - The verdict and its score
    - The payload hash (what was verified)
    - The evidence hash (what evidence was used)
    - The previous record hash (chain integrity)
    - The combined block hash (this record's identity)
    """
    record_id: int
    timestamp: str
    payload_hash: str           # SHA-256 of the original payload
    verdict: str                # REJECTED, QUARANTINE, VERIFIED, GOLD
    score: float
    evidence_hash: str          # SHA-256 of serialised evidence chain
    pillar_scores: Dict[str, float]
    adversarial_penalty: float
    provenance_hash: str        # From attestation (if available)
    previous_hash: str          # Hash of previous record (chain link)
    block_hash: str = ""        # SHA-256 of this entire record
    metadata: Dict[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:
        if not self.block_hash:
            self.block_hash = self._compute_block_hash()

    def _compute_block_hash(self) -> str:
        """
        Computes the block hash for this record.

        hash = SHA-256(
            record_id + timestamp + payload_hash +
            verdict + score + evidence_hash +
            provenance_hash + previous_hash
        )
        """
        components = [
            str(self.record_id),
            self.timestamp,
            self.payload_hash,
            self.verdict,
            f"{self.score:.6f}",
            self.evidence_hash,
            self.provenance_hash,
            self.previous_hash,
        ]
        combined = "|".join(components)
        return hashlib.sha256(combined.encode()).hexdigest()

    def to_dict(self) -> Dict[str, Any]:
        """Serialises for storage or smart contract submission."""
        return {
            "record_id": self.record_id,
            "timestamp": self.timestamp,
            "payload_hash": self.payload_hash,
            "verdict": self.verdict,
            "score": round(self.score, 6),
            "evidence_hash": self.evidence_hash,
            "pillar_scores": {
                k: round(v, 4) for k, v in self.pillar_scores.items()
            },
            "adversarial_penalty": round(self.adversarial_penalty, 4),
            "provenance_hash": self.provenance_hash,
            "previous_hash": self.previous_hash,
            "block_hash": self.block_hash,
            "metadata": self.metadata,
        }

    def to_smart_contract_args(self) -> Dict[str, Any]:
        """
        Returns arguments formatted for smart contract submission.

        A Solidity contract would accept:
            function recordVerification(
                bytes32 payloadHash,
                bytes32 evidenceHash,
                bytes32 provenanceHash,
                bytes32 previousHash,
                bytes32 blockHash,
                uint8 verdict,     // 0=REJECTED, 1=QUARANTINE, 2=VERIFIED, 3=GOLD
                uint256 score,     // score × 1e6 (6 decimal fixed-point)
                uint256 timestamp
            )
        """
        verdict_codes = {
            "REJECTED": 0,
            "QUARANTINE": 1,
            "VERIFIED": 2,
            "GOLD": 3,
        }
        return {
            "payloadHash": f"0x{self.payload_hash}",
            "evidenceHash": f"0x{self.evidence_hash}",
            "provenanceHash": f"0x{self.provenance_hash}" if self.provenance_hash else "0x" + "0" * 64,
            "previousHash": f"0x{self.previous_hash}",
            "blockHash": f"0x{self.block_hash}",
            "verdict": verdict_codes.get(self.verdict, 0),
            "score": int(self.score * 1_000_000),
            "timestamp": int(datetime.fromisoformat(self.timestamp).timestamp()),
        }


class ProofLedger:
    """
    Append-only hash chain for verification verdicts.

    Each new record is chained to the previous one,
    creating a tamper-evident audit trail that can be
    verified independently and batch-submitted to a blockchain.

    Storage: JSON lines file (one record per line) for
    simplicity. Production would use a database +
    periodic blockchain anchoring.
    """

    GENESIS_HASH = "0" * 64  # Genesis block previous hash
    MAX_IN_MEMORY_RECORDS = 50_000  # Older records still in JSONL file

    def __init__(
        self,
        storage_path: Optional[str] = None,
        blockchain_anchor: Optional[Any] = None,
    ) -> None:
        self._records: List[ProofRecord] = []
        self._hash_index: Dict[str, ProofRecord] = {}  # O(1) proof lookup by block_hash
        self._storage_path = storage_path
        self._next_id = 1
        self._blockchain_anchor = blockchain_anchor
        self._lock = threading.Lock()  # Protects chain state during record_verdict

        # Load existing records if storage exists
        if storage_path and os.path.exists(storage_path):
            self._load_from_file(storage_path)

    @property
    def chain_length(self) -> int:
        return len(self._records)

    @property
    def latest_hash(self) -> str:
        if self._records:
            return self._records[-1].block_hash
        return self.GENESIS_HASH

    def record_verdict(
        self,
        verdict: VerificationVerdict,
        provenance_hash: str = "",
        metadata: Optional[Dict[str, Any]] = None,
    ) -> ProofRecord:
        """
        Creates a new chained proof record from a verification verdict.

        Args:
            verdict: The VerificationVerdict to record
            provenance_hash: Attestation provenance hash (if available)
            metadata: Additional context (mission_id, agent_id, etc.)

        Returns: The new ProofRecord (already appended to chain)
        """
        # Compute evidence hash from the verdict's evidence chain
        evidence_data = json.dumps(
            [
                {
                    "source": e.source,
                    "field": e.claim_field,
                    "confirms": e.confirms,
                    "reasoning": e.reasoning,
                }
                for e in verdict.evidence_chain
            ],
            sort_keys=True,
        )
        evidence_hash = hashlib.sha256(evidence_data.encode()).hexdigest()

        # Extract pillar scores
        pillar_scores = {}
        for name, pr in verdict.pillar_results.items():
            if hasattr(pr, "score"):
                pillar_scores[name] = pr.score

        # Get adversarial penalty if present
        adversarial_penalty = 0.0
        for name, pr in verdict.pillar_results.items():
            if hasattr(pr, "layer_results"):
                for lr in pr.layer_results:
                    if hasattr(lr, "metadata") and "total_penalty" in lr.metadata:
                        adversarial_penalty = lr.metadata["total_penalty"]

        with self._lock:
            record = ProofRecord(
                record_id=self._next_id,
                timestamp=verdict.timestamp or datetime.utcnow().isoformat(),
                payload_hash=verdict.payload_hash or "",
                verdict=verdict.verdict,
                score=verdict.score,
                evidence_hash=evidence_hash,
                pillar_scores=pillar_scores,
                adversarial_penalty=adversarial_penalty,
                provenance_hash=provenance_hash,
                previous_hash=self.latest_hash,
                metadata=metadata or {},
            )

            self._records.append(record)
            self._hash_index[record.block_hash] = record
            self._next_id += 1

            # Persist to file (always — file is the authoritative store)
            if self._storage_path:
                self._append_to_file(record)

            # Evict oldest in-memory records (file retains everything)
            if len(self._records) > self.MAX_IN_MEMORY_RECORDS:
                evict = len(self._records) - self.MAX_IN_MEMORY_RECORDS
                for old in self._records[:evict]:
                    self._hash_index.pop(old.block_hash, None)
                self._records = self._records[evict:]

        logger.info(
            "PROOF #%d: %s (score=%.4f), block=%s..., chain_length=%d",
            record.record_id, record.verdict, record.score,
            record.block_hash[:16], self.chain_length,
        )

        return record

    def anchor_approved_record(self, block_hash: str) -> Optional[Dict[str, Any]]:
        """
        Anchors a specific proof record on-chain AFTER human approval.

        This is the only path to blockchain anchoring. No auto-stamping.
        Called by the human review endpoint after an operator approves.

        Returns:
            Transaction receipt dict, or None if failed/not connected.
        """
        if not self._blockchain_anchor or not self._blockchain_anchor.is_connected:
            logger.warning("ANCHOR: Blockchain not connected — cannot anchor")
            return None

        record = self._hash_index.get(block_hash)
        if not record:
            logger.error(f"ANCHOR: Record not found for hash {block_hash[:16]}...")
            return None

        contract_args = record.to_smart_contract_args()
        tx_receipt = self._blockchain_anchor.anchor_proof(contract_args)
        if tx_receipt:
            logger.info(
                f"HUMAN-APPROVED ANCHOR: #{record.record_id} "
                f"-> tx={tx_receipt['transactionHash'][:18]}..."
            )
        return tx_receipt

    def lookup(self, block_hash: str) -> Optional[ProofRecord]:
        """O(1) proof record lookup by block hash."""
        return self._hash_index.get(block_hash)

    def verify_chain_integrity(self) -> bool:
        """
        Verifies the entire chain is unbroken.

        Each record's previous_hash must match the
        previous record's block_hash.

        Returns: True if chain is intact, False if tampered
        """
        if not self._records:
            return True

        # First record must reference genesis
        if self._records[0].previous_hash != self.GENESIS_HASH:
            logger.error(
                f"CHAIN BROKEN: Record #1 previous_hash is "
                f"{self._records[0].previous_hash[:16]}..., "
                f"expected genesis"
            )
            return False

        for i in range(1, len(self._records)):
            expected = self._records[i - 1].block_hash
            actual = self._records[i].previous_hash

            if actual != expected:
                logger.error(
                    f"CHAIN BROKEN at record #{self._records[i].record_id}: "
                    f"prev={actual[:16]}... != expected={expected[:16]}..."
                )
                return False

        # Verify each block hash is valid
        for record in self._records:
            recomputed = record._compute_block_hash()
            if recomputed != record.block_hash:
                logger.error(
                    f"HASH MISMATCH at record #{record.record_id}: "
                    f"stored={record.block_hash[:16]}... != "
                    f"computed={recomputed[:16]}..."
                )
                return False

        logger.info(f"CHAIN VERIFIED: {len(self._records)} records, integrity OK")
        return True

    def get_record(self, record_id: int) -> Optional[ProofRecord]:
        """Retrieves a record by ID."""
        for r in self._records:
            if r.record_id == record_id:
                return r
        return None

    def get_pending_for_blockchain(
        self, batch_size: int = 10
    ) -> List[Dict[str, Any]]:
        """
        Returns the next batch of records formatted for
        smart contract submission.

        In production, this would track which records have
        already been anchored on-chain.
        """
        pending = self._records[-batch_size:]
        return [r.to_smart_contract_args() for r in pending]

    def export_chain(self) -> List[Dict[str, Any]]:
        """Exports the full chain as a list of dicts."""
        return [r.to_dict() for r in self._records]

    def _append_to_file(self, record: ProofRecord) -> None:
        """Appends a single record to the storage file."""
        try:
            path = Path(self._storage_path)
            path.parent.mkdir(parents=True, exist_ok=True)
            with open(path, "a", encoding="utf-8") as f:
                f.write(json.dumps(record.to_dict()) + "\n")
        except OSError as e:
            logger.error(f"Failed to write proof record: {e}")

    def _load_from_file(self, path: str) -> None:
        """Loads existing records from a JSON lines file."""
        try:
            with open(path, "r", encoding="utf-8") as f:
                for line in f:
                    line = line.strip()
                    if not line:
                        continue
                    data = json.loads(line)
                    record = ProofRecord(
                        record_id=data["record_id"],
                        timestamp=data["timestamp"],
                        payload_hash=data["payload_hash"],
                        verdict=data["verdict"],
                        score=data["score"],
                        evidence_hash=data["evidence_hash"],
                        pillar_scores=data.get("pillar_scores", {}),
                        adversarial_penalty=data.get("adversarial_penalty", 0),
                        provenance_hash=data.get("provenance_hash", ""),
                        previous_hash=data["previous_hash"],
                        block_hash=data["block_hash"],
                        metadata=data.get("metadata", {}),
                    )
                    self._records.append(record)
                    self._hash_index[record.block_hash] = record

            if self._records:
                self._next_id = self._records[-1].record_id + 1
                logger.info(
                    f"Loaded {len(self._records)} proof records from {path}"
                )
        except (OSError, json.JSONDecodeError) as e:
            logger.error(f"Failed to load proof ledger: {e}")
