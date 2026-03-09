"""
Verification Stack Orchestrator.

Top-level module that takes a complete payload, decomposes it,
routes each component to the correct verification pillar, and
produces a unified VerificationVerdict.

    PAYLOAD
    ├── Structured Data (JSON)    ->  Schema -> Consistency -> Triangulation
    ├── Attached Documents        ->  Forensic Integrity (per document)
    └── Submission Metadata       ->  Attestation (future)

The Verdict Engine fuses all pillar results into a single score.
"""
import hashlib
import logging
from datetime import datetime
from typing import Any, Dict, List, Optional

from core.verification.adversarial import AdversarialChallengeAgent
from core.verification.attestation import AttestationBundle, AttestationVerifier
from core.verification.consistency import ConsistencyAnalyzer
from core.verification.forensic_integrity import ForensicIntegrityAnalyzer
from core.verification.logic_triangulation import LogicTriangulationEngine
from core.verification.models import (
    DataClaim, FieldSpec, DataSchema, Evidence, EvidenceType,
    LayerResult, PillarResult, VerificationVerdict,
)
from core.verification.schema_gatekeeper import SchemaGatekeeper

logger = logging.getLogger("VerificationStack")


class VerificationOrchestrator:
    """
    Top-level orchestrator that runs the full verification stack.

    Pipeline:
    1. Schema Gatekeeper -> structural validation
    2. Consistency Analyzer -> internal logic validation
    3. Forensic Integrity -> document/image authenticity (per attachment)
    4. Logic Triangulation -> cross-domain truth verification
    5. Future: Attestation Verifier -> provenance proof

    Each step produces evidence that feeds into the Verdict Engine.
    """

    # Pillar weights (from implementation plan)
    PILLAR_WEIGHTS = {
        "forensic_integrity":   0.30,
        "logic_triangulation":  0.45,
        "attestation_proof":    0.25,
    }

    # Weights when attestation is absent
    PILLAR_WEIGHTS_NO_ATTESTATION = {
        "forensic_integrity":   0.40,
        "logic_triangulation":  0.60,
    }

    def __init__(self) -> None:
        self.schema_gatekeeper = SchemaGatekeeper()
        self.consistency_analyzer = ConsistencyAnalyzer()
        self.forensic_analyzer = ForensicIntegrityAnalyzer()
        self.triangulation_engine = LogicTriangulationEngine()
        self.attestation_verifier = AttestationVerifier()
        self.adversarial_agent = AdversarialChallengeAgent()

    async def verify(
        self,
        payload: Dict[str, Any],
        schema: Optional[DataSchema] = None,
        attachments: Optional[List[Dict[str, Any]]] = None,
        attestation_bundle: Optional[AttestationBundle] = None,
        context: Optional[Dict[str, Any]] = None,
    ) -> VerificationVerdict:
        """
        Runs the full verification stack on a payload.

        Args:
            payload: Structured data (JSON-like dict)
            schema: Optional schema for structural validation
            attachments: List of {bytes, type, name} for document forensics
            context: Domain context (region, domain, etc.)

        Returns: VerificationVerdict with composite score and evidence
        """
        ctx = context or {}
        pillar_results: Dict[str, PillarResult] = {}
        all_evidence: List[Evidence] = []
        warnings: List[str] = []

        logger.info("=" * 60)
        logger.info("VERIFICATION STACK: Processing payload")
        logger.info(f"  Fields: {len(payload)}")
        logger.info(f"  Attachments: {len(attachments or [])}")
        logger.info(f"  Context: {ctx}")
        logger.info("=" * 60)

        # --- Gate 1: Schema Validation ---
        if schema:
            schema_result = self.schema_gatekeeper.check(payload, schema)
            if schema_result.is_veto:
                logger.warning(
                    f"GATE 1 VETO: {schema_result.veto_reason}"
                )
                return self._build_verdict(
                    pillar_results={},
                    pre_check_results=[schema_result],
                    veto_reason=f"Schema: {schema_result.veto_reason}",
                )
            all_evidence.extend(schema_result.evidence)
            logger.info(f"  Gate 1 (Schema): score={schema_result.score:.2f}")
        else:
            schema_result = None
            logger.info("  Gate 1 (Schema): skipped — no schema provided")

        # --- Gate 2: Consistency Check ---
        # Build a minimal schema from payload if none provided
        consistency_schema = schema
        if consistency_schema is None:
            consistency_schema = self._build_minimal_schema(payload)
        consistency_result = self.consistency_analyzer.check(
            payload, consistency_schema
        )
        all_evidence.extend(consistency_result.evidence)
        logger.info(
            f"  Gate 2 (Consistency): score={consistency_result.score:.2f}"
        )

        # --- Pillar 1: Forensic Integrity (per attachment) ---
        if attachments:
            forensic_results = []
            for att in attachments:
                fr = await self.forensic_analyzer.analyze(
                    file_bytes=att["bytes"],
                    file_type=att.get("type", "unknown"),
                    metadata=att.get("metadata"),
                )
                forensic_results.append(fr)
                all_evidence.extend(fr.evidence_chain)

            # Average across all attachments
            if forensic_results:
                avg_forensic = sum(
                    fr.score for fr in forensic_results
                ) / len(forensic_results)
                forensic_is_veto = any(fr.is_veto for fr in forensic_results)
                forensic_veto_reason = next(
                    (fr.veto_reason for fr in forensic_results if fr.is_veto),
                    "",
                )

                # Merge all layer results
                merged_layers = []
                for fr in forensic_results:
                    merged_layers.extend(fr.layer_results)

                pillar_results["forensic_integrity"] = PillarResult(
                    pillar_name="forensic_integrity",
                    score=round(avg_forensic, 4),
                    layer_results=merged_layers,
                    evidence_chain=[
                        e for fr in forensic_results
                        for e in fr.evidence_chain
                    ],
                    is_veto=forensic_is_veto,
                    veto_reason=forensic_veto_reason,
                )
                logger.info(
                    f"  Pillar 1 (Forensic): score={avg_forensic:.2f} "
                    f"({len(forensic_results)} documents)"
                )

                if forensic_is_veto:
                    logger.warning(
                        f"PILLAR 1 VETO: {forensic_veto_reason}"
                    )
                    return self._build_verdict(
                        pillar_results=pillar_results,
                        pre_check_results=[
                            r for r in [schema_result, consistency_result]
                            if r is not None
                        ],
                        veto_reason=f"Forensic: {forensic_veto_reason}",
                    )
        else:
            logger.info("  Pillar 1 (Forensic): skipped — no attachments")

        # --- Pillar 2: Logic Triangulation ---
        claims = self._extract_claims(payload)
        if claims:
            triangulation_result = await self.triangulation_engine.triangulate(
                claims=claims,
                context=ctx,
            )
            pillar_results["logic_triangulation"] = triangulation_result
            all_evidence.extend(triangulation_result.evidence_chain)
            logger.info(
                f"  Pillar 2 (Triangulation): "
                f"score={triangulation_result.score:.2f}"
            )

            if triangulation_result.is_veto:
                logger.warning(
                    f"PILLAR 2 VETO: {triangulation_result.veto_reason}"
                )
                return self._build_verdict(
                    pillar_results=pillar_results,
                    pre_check_results=[
                        r for r in [schema_result, consistency_result]
                        if r is not None
                    ],
                    veto_reason=f"Triangulation: {triangulation_result.veto_reason}",
                )
        else:
            logger.info("  Pillar 2 (Triangulation): no claims extracted")

        # --- Pillar 3: Attestation (if bundle provided) ---
        if attestation_bundle:
            attestation_result = await self.attestation_verifier.verify(
                attestation_bundle
            )
            pillar_results["attestation_proof"] = attestation_result
            all_evidence.extend(attestation_result.evidence_chain)
            logger.info(
                f"  Pillar 3 (Attestation): "
                f"score={attestation_result.score:.2f}"
            )

            if attestation_result.is_veto:
                logger.warning(
                    f"PILLAR 3 VETO: {attestation_result.veto_reason}"
                )
                return self._build_verdict(
                    pillar_results=pillar_results,
                    pre_check_results=[
                        r for r in [schema_result, consistency_result]
                        if r is not None
                    ],
                    veto_reason=f"Attestation: {attestation_result.veto_reason}",
                )
        else:
            logger.info("  Pillar 3 (Attestation): no bundle provided")

        # --- Adversarial Challenge (runs last) ---
        adversarial_result = await self.adversarial_agent.challenge(
            pillar_results=pillar_results,
            pre_check_results=[
                r for r in [schema_result, consistency_result]
                if r is not None
            ],
            original_payload=payload,
        )
        all_evidence.extend(adversarial_result.evidence)
        logger.info(
            f"  Adversarial: score={adversarial_result.score:.2f}, "
            f"challenges={adversarial_result.metadata.get('challenges_raised', 0)}"
        )

        # --- Verdict ---
        verdict = self._build_verdict(
            pillar_results=pillar_results,
            pre_check_results=[
                r for r in [schema_result, consistency_result]
                if r is not None
            ],
            adversarial_result=adversarial_result,
        )

        logger.info(f"  VERDICT: {verdict.verdict} (score={verdict.score:.4f})")
        logger.info("=" * 60)

        return verdict

    def _extract_claims(self, payload: Dict[str, Any]) -> List[DataClaim]:
        """Converts payload fields into DataClaim objects for triangulation."""
        claims = []
        for field_name, value in payload.items():
            if value is not None:
                claims.append(DataClaim(
                    field_name=field_name,
                    value=value,
                    source="payload",
                ))
        return claims

    def _build_verdict(
        self,
        pillar_results: Dict[str, PillarResult],
        pre_check_results: Optional[List[LayerResult]] = None,
        adversarial_result: Optional[LayerResult] = None,
        veto_reason: str = "",
    ) -> VerificationVerdict:
        """
        Combines all results into a final VerificationVerdict.

        Rules from the implementation plan:
        1. If forensic integrity < 0.3 -> REJECT
        2. If triangulation finds active contradiction -> REJECT
        3. If no attestation -> redistribute weights
        4. Otherwise -> weighted average

        Verdicts:
        - REJECTED:    score < 0.40 OR veto
        - QUARANTINE:  0.40 ≤ score < 0.70
        - VERIFIED:    0.70 ≤ score < 0.90
        - GOLD:        score ≥ 0.90
        """
        # Early veto
        if veto_reason:
            return VerificationVerdict(
                score=0.0,
                verdict="REJECTED",
                pillar_results=pillar_results,
                pre_check_results=pre_check_results or [],
                veto_reason=veto_reason,
                timestamp=datetime.utcnow().isoformat(),
            )

        # Select weights based on attestation presence
        has_attestation = "attestation_proof" in pillar_results
        weights = (
            self.PILLAR_WEIGHTS if has_attestation
            else self.PILLAR_WEIGHTS_NO_ATTESTATION
        )

        # Weighted score
        weighted_sum = 0.0
        total_weight = 0.0

        for pillar_name, weight in weights.items():
            if pillar_name in pillar_results:
                weighted_sum += pillar_results[pillar_name].score * weight
                total_weight += weight

        # Include pre-check results as a baseline factor
        pre_check_avg = 1.0
        if pre_check_results:
            pre_scores = [r.score for r in pre_check_results]
            pre_check_avg = sum(pre_scores) / len(pre_scores)

        if total_weight > 0:
            pillar_score = weighted_sum / total_weight
            # Blend pre-checks and pillar scores
            # Pre-checks are structural validation (schema + consistency)
            # Pillars are deeper verification (forensic, triangulation, attestation)
            # Weight: 40% pre-checks, 60% pillars when both available
            score = pillar_score * 0.6 + pre_check_avg * 0.4
            # If pillars are strong and pre-checks are also strong,
            # let the pillar score dominate (70/30 blend)
            if pillar_score >= 0.80 and pre_check_avg >= 0.70:
                score = max(score, pillar_score * 0.85 + pre_check_avg * 0.15)
            # But if pre-checks found real problems, cap the score
            if pre_check_avg < 0.5:
                score = min(score, pre_check_avg)
        elif pre_check_results:
            # Only pre-checks ran (no pillar data)
            # Pre-checks alone can get up to 0.75 (VERIFIED requires pillars)
            score = min(pre_check_avg * 0.75, 0.75)
        else:
            score = 0.5

        # Apply adversarial penalty
        if adversarial_result:
            adv_penalty = adversarial_result.metadata.get("total_penalty", 0)
            if adv_penalty > 0:
                score = max(0.0, score - adv_penalty)

        # Apply verdict rules
        forensic = pillar_results.get("forensic_integrity")
        if forensic and forensic.score < 0.3:
            score = min(score, 0.15)
            veto_reason = "Document integrity too low"

        triangulation = pillar_results.get("logic_triangulation")
        if triangulation and triangulation.is_veto:
            score = min(score, 0.1)
            veto_reason = triangulation.veto_reason
        # Determine verdict label
        if veto_reason or score < 0.40:
            verdict_label = "REJECTED"
        elif score < 0.70:
            verdict_label = "QUARANTINE"
        elif score < 0.90:
            verdict_label = "VERIFIED"
        else:
            # GOLD requires additional checks — forensic analysis is mandatory
            gold_eligible = True
            if not forensic or forensic.score < 0.8:
                gold_eligible = False
            if not has_attestation and not (
                triangulation and triangulation.score >= 0.85
            ):
                gold_eligible = False

            verdict_label = "GOLD" if gold_eligible else "VERIFIED"

        # Generate payload hash
        import json
        payload_str = json.dumps(pillar_results, default=str, sort_keys=True)
        payload_hash = hashlib.sha256(payload_str.encode()).hexdigest()

        return VerificationVerdict(
            score=round(score, 4),
            verdict=verdict_label,
            pillar_results=pillar_results,
            pre_check_results=pre_check_results or [],
            veto_reason=veto_reason,
            payload_hash=payload_hash,
            timestamp=datetime.utcnow().isoformat(),
        )

    def _build_minimal_schema(
        self, payload: Dict[str, Any]
    ) -> DataSchema:
        """
        Builds a minimal DataSchema from payload values.

        Infers field types from Python types:
        - int -> INTEGER
        - float -> FLOAT
        - str -> STRING
        - bool -> BOOLEAN
        """
        from core.verification.models import FieldType

        type_map = {
            int: FieldType.INTEGER,
            float: FieldType.FLOAT,
            str: FieldType.STRING,
            bool: FieldType.BOOLEAN,
        }

        fields = []
        for name, value in payload.items():
            ft = type_map.get(type(value), FieldType.STRING)
            fields.append(FieldSpec(
                name=name,
                field_type=ft,
                required=False,
            ))

        return DataSchema(
            name="auto_inferred",
            version="1.0",
            fields=fields,
            description="Auto-inferred from payload types",
        )
