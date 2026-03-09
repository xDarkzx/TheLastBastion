"""
Verification Pipeline — Connects Agent Output to Verification Stack.

This is the integration point where agent mission results get
piped through the full verification stack before being stored
as verified truth.

Flow:
    Agent completes mission
    -> Extracts structured data + attachments
    -> Pipes through VerificationOrchestrator
    -> Records verdict in ProofLedger
    -> Stores verified data (or quarantines/rejects)

This module is the SINGLE ENTRY POINT for all verification.
No data enters the verified store without passing through here.
"""
import hashlib
import json
import logging
from datetime import datetime
from typing import Any, Dict, List, Optional

from core.verification.attestation import AttestationBundle
from core.verification.models import DataSchema, VerificationVerdict
from core.verification.proof_ledger import ProofLedger
from core.verification.verification_stack import VerificationOrchestrator
from core.database import (
    save_verification_result,
    save_quarantine,
    save_blockchain_stamp,
)

logger = logging.getLogger("VerificationPipeline")


class VerificationPipeline:
    """
    Single entry point for data verification.

    Accepts raw mission output, runs the full stack,
    records the proof, and returns a decision.
    """

    def __init__(
        self,
        ledger_path: Optional[str] = None,
        blockchain_anchor: Optional[Any] = None,
    ) -> None:
        self.orchestrator = VerificationOrchestrator()
        self.ledger = ProofLedger(
            storage_path=ledger_path,
            blockchain_anchor=blockchain_anchor,
        )
        self.blockchain_anchor = blockchain_anchor
        self._stats = {
            "total": 0,
            "verified": 0,
            "quarantined": 0,
            "rejected": 0,
            "gold": 0,
        }

    @property
    def stats(self) -> Dict[str, int]:
        """Returns cumulative verification statistics."""
        return dict(self._stats)

    async def process_mission_result(
        self,
        mission_id: int,
        agent_id: str,
        payload: Dict[str, Any],
        attachments: Optional[List[Dict[str, Any]]] = None,
        attestation_bundle: Optional[AttestationBundle] = None,
        schema: Optional[DataSchema] = None,
        context: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        """
        Processes a single mission result through the full verification stack.

        Args:
            mission_id: The mission that produced this data
            agent_id: Which agent submitted it
            payload: Structured data extracted by the agent
            attachments: Document/image bytes for forensic analysis
            attestation_bundle: Provenance proof (GPS, depth, device)
            schema: Expected data schema (optional)
            context: Domain context (region, industry, etc.)

        Returns:
            Dict with:
                - verdict: REJECTED/QUARANTINE/VERIFIED/GOLD
                - score: 0.0 to 1.0
                - proof_record_id: ID in the proof ledger
                - proof_hash: Block hash for audit
                - action: what to do with the data
                - details: pillar breakdown
        """
        logger.info(f"PIPELINE: Mission {mission_id} from agent '{agent_id}'")

        # Run full verification stack
        verdict = await self.orchestrator.verify(
            payload=payload,
            schema=schema,
            attachments=attachments,
            attestation_bundle=attestation_bundle,
            context=context,
        )

        # Extract provenance hash if attestation was provided
        provenance_hash = ""
        if attestation_bundle:
            provenance_hash = self.orchestrator.attestation_verifier.generate_provenance_hash(
                attestation_bundle
            )

        # Record in proof ledger
        proof_record = self.ledger.record_verdict(
            verdict=verdict,
            provenance_hash=provenance_hash,
            metadata={
                "mission_id": mission_id,
                "agent_id": agent_id,
                "field_count": len(payload),
                "attachment_count": len(attachments or []),
            },
        )

        # Update stats
        self._stats["total"] += 1
        verdict_lower = verdict.verdict.lower()
        if verdict_lower in self._stats:
            self._stats[verdict_lower] += 1

        # Determine action
        action = self._determine_action(verdict)

        # Build result
        pillar_breakdown = {}
        for name, pr in verdict.pillar_results.items():
            if hasattr(pr, "score"):
                pillar_breakdown[name] = {
                    "score": round(pr.score, 4),
                    "layers": len(pr.layer_results) if hasattr(pr, "layer_results") else 0,
                    "is_veto": pr.is_veto if hasattr(pr, "is_veto") else False,
                }

        details = {
            "pillar_breakdown": pillar_breakdown,
            "veto_triggered": bool(verdict.veto_reason),
            "veto_reason": verdict.veto_reason,
        }

        result = {
            "verdict": verdict.verdict,
            "score": round(verdict.score, 4),
            "proof_record_id": proof_record.record_id,
            "proof_hash": proof_record.block_hash,
            "action": action,
            "mission_id": mission_id,
            "agent_id": agent_id,
            "chain_length": self.ledger.chain_length,
            "details": details,
        }

        # Persist to DB
        submission_id = (context or {}).get("submission_id")
        data_hash = (context or {}).get("data_hash", "")
        try:
            db_record = save_verification_result(
                data_hash=data_hash,
                proof_hash=proof_record.block_hash,
                verdict=verdict.verdict,
                composite_score=round(verdict.score, 4),
                action=action,
                agent_id=agent_id,
                mission_id=mission_id,
                submission_id=submission_id,
                proof_record_id=proof_record.record_id,
                layer_scores=pillar_breakdown,
                details=details,
            )
            result["db_id"] = db_record.id

            # Quarantine items need a human review entry
            if action == "quarantine":
                veto_reason = verdict.veto_reason or "Score in quarantine range (40–70)"
                save_quarantine(
                    verification_result_id=db_record.id,
                    data_hash=data_hash,
                    reason=veto_reason,
                    score=round(verdict.score, 4),
                    submission_id=submission_id,
                )

            # Save blockchain stamp record for ALL verdicts — pending human approval.
            # tx_hash stays empty until a human operator reviews and approves anchoring.
            # This is intentional: no automated on-chain stamping without human oversight.
            save_blockchain_stamp(
                proof_hash=proof_record.block_hash,
                data_hash=data_hash,
                verdict=verdict.verdict,
                confidence=round(verdict.score, 4),
                verification_result_id=db_record.id,
                submission_id=submission_id,
                tx_hash="",
            )
        except Exception as db_err:
            # DB persistence failure must not break the pipeline
            logger.error(f"PIPELINE DB PERSIST FAILED: {db_err}")

        logger.info(
            f"PIPELINE: Mission {mission_id} -> {verdict.verdict} "
            f"(score={verdict.score:.4f}), "
            f"action='{action}', "
            f"proof=#{proof_record.record_id}"
        )

        # Broadcast verdict event via protocol bus (fires WebSocket if wired)
        try:
            from core.protocol_bus import protocol_bus
            protocol_bus.record(
                direction="OUTBOUND",
                message_type="VERDICT",
                sender_id="verification-pipeline",
                recipient_id=agent_id,
                endpoint="/verification/pipeline",
                auth_result="INTERNAL",
                payload_summary=f"verdict={verdict.verdict}, score={verdict.score:.4f}, action={action}",
                processing_ms=0.0,
            )
        except Exception:
            pass

        return result

    async def process_batch(
        self,
        missions: List[Dict[str, Any]],
        context: Optional[Dict[str, Any]] = None,
    ) -> List[Dict[str, Any]]:
        """
        Processes multiple mission results sequentially.

        Each mission dict should contain:
            - mission_id: int
            - agent_id: str
            - payload: Dict
            - attachments: Optional[List]
            - attestation_bundle: Optional[AttestationBundle]
            - schema: Optional[DataSchema]

        Returns: List of result dicts (same format as process_mission_result)
        """
        results = []
        for mission in missions:
            result = await self.process_mission_result(
                mission_id=mission["mission_id"],
                agent_id=mission["agent_id"],
                payload=mission["payload"],
                attachments=mission.get("attachments"),
                attestation_bundle=mission.get("attestation_bundle"),
                schema=mission.get("schema"),
                context=context,
            )
            results.append(result)

        # Summary
        verdicts = [r["verdict"] for r in results]
        logger.info(
            f"BATCH: {len(results)} missions processed — "
            f"VERIFIED={verdicts.count('VERIFIED')}, "
            f"QUARANTINE={verdicts.count('QUARANTINE')}, "
            f"REJECTED={verdicts.count('REJECTED')}, "
            f"GOLD={verdicts.count('GOLD')}"
        )

        return results

    def verify_ledger_integrity(self) -> bool:
        """Verifies the proof ledger chain is unbroken."""
        return self.ledger.verify_chain_integrity()

    def _determine_action(self, verdict: VerificationVerdict) -> str:
        """
        Determines what action to take based on the verdict.

        Returns one of:
            - 'store_verified': Safe to store as verified truth
            - 'store_gold': Highest confidence — store with gold status
            - 'quarantine': Hold for human review
            - 'reject': Do not store, flag the agent
        """
        if verdict.verdict == "GOLD":
            return "store_gold"
        elif verdict.verdict == "VERIFIED":
            return "store_verified"
        elif verdict.verdict == "QUARANTINE":
            return "quarantine"
        else:
            return "reject"
