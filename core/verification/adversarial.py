"""
Adversarial Challenge Agent (Step 9).

The 'Devil's Advocate' — actively tries to DISPROVE the data.
If the data survives adversarial challenge, it's stronger.

Strategies:
1. Contradiction Hunting — looks for internal contradictions
2. Boundary Testing — pushes values to extremes to test plausibility
3. Source Skepticism — questions the reliability of evidence sources
4. Pattern Injection — checks if data follows suspiciously perfect patterns
5. Confidence Calibration — penalises over-confident results with weak evidence

This agent runs AFTER all other verification steps and can
DOWNGRADE the final score if it finds weaknesses that the
other layers missed.
"""
import logging
import math
import statistics
from typing import Any, Dict, List, Optional, Tuple

from core.verification.models import (
    Evidence, EvidenceType, LayerResult, PillarResult,
)

logger = logging.getLogger("AdversarialAgent")


class AdversarialChallengeAgent:
    """
    Actively tries to disprove verified data.

    Takes the evidence gathered by other pillars and runs
    adversarial challenges against it. The data must survive
    these challenges to maintain its score.
    """

    # Minimum evidence pieces per pillar for confidence
    MIN_EVIDENCE_PER_PILLAR = 2

    def __init__(self) -> None:
        self.logger = logging.getLogger(self.__class__.__name__)

    async def challenge(
        self,
        pillar_results: Dict[str, PillarResult],
        pre_check_results: Optional[List[LayerResult]] = None,
        original_payload: Optional[Dict[str, Any]] = None,
    ) -> LayerResult:
        """
        Runs adversarial challenges against the verification results.

        Args:
            pillar_results: Results from all pillars
            pre_check_results: Results from pre-checks (schema, consistency)
            original_payload: The raw payload being verified (for content-based checks)

        Returns: LayerResult with adversarial findings
        """
        evidence: List[Evidence] = []
        warnings: List[str] = []
        penalties: List[Tuple[str, float]] = []

        # --- Challenge 1: Evidence Sufficiency ---
        sufficiency_result = self._challenge_evidence_sufficiency(
            pillar_results
        )
        evidence.extend(sufficiency_result)
        for ev in sufficiency_result:
            if not ev.confirms:
                penalties.append(("evidence_gap", 0.05))
                warnings.append(ev.reasoning)

        # --- Challenge 2: Score Consistency ---
        consistency_result = self._challenge_score_consistency(
            pillar_results, pre_check_results or []
        )
        evidence.extend(consistency_result)
        for ev in consistency_result:
            if not ev.confirms:
                penalties.append(("score_inconsistency", 0.08))
                warnings.append(ev.reasoning)

        # --- Challenge 3: Perfect Pattern Detection ---
        pattern_result = self._challenge_perfect_patterns(pillar_results)
        evidence.extend(pattern_result)
        for ev in pattern_result:
            if not ev.confirms:
                penalties.append(("suspicious_pattern", 0.1))
                warnings.append(ev.reasoning)

        # --- Challenge 4: Confidence vs Evidence Mismatch ---
        confidence_result = self._challenge_confidence_calibration(
            pillar_results
        )
        evidence.extend(confidence_result)
        for ev in confidence_result:
            if not ev.confirms:
                penalties.append(("overconfident", 0.06))
                warnings.append(ev.reasoning)

        # --- Challenge 5: Missing Pillar Coverage ---
        coverage_result = self._challenge_pillar_coverage(pillar_results)
        evidence.extend(coverage_result)
        for ev in coverage_result:
            if not ev.confirms:
                penalties.append(("missing_pillar", 0.05))
                warnings.append(ev.reasoning)

        # --- Challenge 6: Content Plausibility (requires original payload) ---
        if original_payload:
            content_result = self._challenge_content_plausibility(original_payload)
            evidence.extend(content_result)
            for ev in content_result:
                if not ev.confirms:
                    penalties.append(("content_implausible", 0.07))
                    warnings.append(ev.reasoning)

        # Compute adversarial score
        total_penalty = sum(p[1] for p in penalties)
        score = max(0.0, 1.0 - total_penalty)

        self.logger.info(
            f"ADVERSARIAL: {len(penalties)} challenges, "
            f"total_penalty={total_penalty:.2f}, score={score:.2f}"
        )

        return LayerResult(
            layer_name="adversarial_challenge",
            score=round(score, 4),
            evidence=evidence,
            warnings=warnings,
            metadata={
                "challenges_raised": len(penalties),
                "total_penalty": round(total_penalty, 4),
                "penalty_breakdown": [
                    {"type": t, "amount": a} for t, a in penalties
                ],
            },
        )

    def _challenge_evidence_sufficiency(
        self, pillar_results: Dict[str, PillarResult]
    ) -> List[Evidence]:
        """
        Checks if each pillar has enough evidence to justify its score.
        High scores with little evidence are suspicious.
        """
        results: List[Evidence] = []

        for name, pillar in pillar_results.items():
            evidence_count = len(pillar.evidence_chain)

            if pillar.score >= 0.7 and evidence_count < self.MIN_EVIDENCE_PER_PILLAR:
                results.append(Evidence(
                    source="adversarial",
                    source_type=EvidenceType.ADVERSARIAL,
                    claim_field=name,
                    confirms=False,
                    reasoning=(
                        f"EVIDENCE GAP: {name} scored {pillar.score:.2f} "
                        f"but only has {evidence_count} evidence piece(s) "
                        f"— insufficient justification"
                    ),
                    confidence=0.7,
                ))
            elif evidence_count >= self.MIN_EVIDENCE_PER_PILLAR:
                results.append(Evidence(
                    source="adversarial",
                    source_type=EvidenceType.ADVERSARIAL,
                    claim_field=name,
                    confirms=True,
                    reasoning=(
                        f"{name}: {evidence_count} evidence pieces — "
                        f"sufficient for score {pillar.score:.2f}"
                    ),
                    confidence=0.5,
                ))

        return results

    def _challenge_score_consistency(
        self,
        pillar_results: Dict[str, PillarResult],
        pre_checks: List[LayerResult],
    ) -> List[Evidence]:
        """
        Checks if pillar scores are consistent with each other.

        If forensic integrity is low but triangulation is high,
        that's suspicious — someone might be gaming the logic checks
        while submitting forged documents.
        """
        results: List[Evidence] = []

        forensic = pillar_results.get("forensic_integrity")
        triangulation = pillar_results.get("logic_triangulation")

        if forensic and triangulation:
            gap = abs(forensic.score - triangulation.score)
            if gap > 0.4:
                lower = "forensic" if forensic.score < triangulation.score else "triangulation"
                results.append(Evidence(
                    source="adversarial",
                    source_type=EvidenceType.ADVERSARIAL,
                    claim_field="pillar_consistency",
                    confirms=False,
                    reasoning=(
                        f"PILLAR MISMATCH: forensic={forensic.score:.2f}, "
                        f"triangulation={triangulation.score:.2f} — "
                        f"{gap:.2f} gap, {lower} is weak"
                    ),
                    confidence=0.7,
                ))

        # Check pre-check vs pillar consistency
        if pre_checks and pillar_results:
            pre_avg = sum(r.score for r in pre_checks) / len(pre_checks)
            pillar_avg = sum(
                p.score for p in pillar_results.values()
            ) / len(pillar_results)

            if pre_avg < 0.5 and pillar_avg > 0.7:
                results.append(Evidence(
                    source="adversarial",
                    source_type=EvidenceType.ADVERSARIAL,
                    claim_field="gate_pillar_consistency",
                    confirms=False,
                    reasoning=(
                        f"GATE-PILLAR MISMATCH: pre-checks avg={pre_avg:.2f} "
                        f"but pillars avg={pillar_avg:.2f} — data has "
                        f"structural issues but passes verification?"
                    ),
                    confidence=0.65,
                ))

        return results

    def _challenge_perfect_patterns(
        self, pillar_results: Dict[str, PillarResult]
    ) -> List[Evidence]:
        """
        Detects suspiciously perfect score patterns.

        Real data verification almost never produces all-perfect scores.
        If every single layer gives 0.9+, that's worth questioning.
        """
        results: List[Evidence] = []

        all_layer_scores = []
        for pillar in pillar_results.values():
            for lr in pillar.layer_results:
                all_layer_scores.append(lr.score)

        if len(all_layer_scores) >= 4:
            perfect_count = sum(1 for s in all_layer_scores if s >= 0.9)
            perfect_ratio = perfect_count / len(all_layer_scores)

            if perfect_ratio >= 0.8:
                results.append(Evidence(
                    source="adversarial",
                    source_type=EvidenceType.ADVERSARIAL,
                    claim_field="pattern_perfection",
                    confirms=False,
                    reasoning=(
                        f"SUSPICIOUS PERFECTION: {perfect_count}/"
                        f"{len(all_layer_scores)} layers scored ≥0.9 "
                        f"({perfect_ratio:.0%}) — real data has imperfections"
                    ),
                    confidence=0.6,
                ))

            # Check for suspiciously uniform scores
            if len(all_layer_scores) >= 3:
                try:
                    score_std = statistics.stdev(all_layer_scores)
                    if score_std < 0.05 and len(all_layer_scores) >= 5:
                        results.append(Evidence(
                            source="adversarial",
                            source_type=EvidenceType.ADVERSARIAL,
                            claim_field="score_uniformity",
                            confirms=False,
                            reasoning=(
                                f"UNIFORM SCORES: std={score_std:.3f} across "
                                f"{len(all_layer_scores)} layers — suspiciously "
                                f"uniform, natural variation expected"
                            ),
                            confidence=0.5,
                        ))
                except statistics.StatisticsError:
                    pass

        return results

    def _challenge_confidence_calibration(
        self, pillar_results: Dict[str, PillarResult]
    ) -> List[Evidence]:
        """
        Checks if confidence levels match evidence quality.

        High confidence with low-quality evidence sources = overconfident.
        """
        results: List[Evidence] = []

        for pillar in pillar_results.values():
            high_conf_weak_source = 0
            total_evidence = 0

            for ev in pillar.evidence_chain:
                total_evidence += 1
                # 'computation' is internal-only, 'forensic' is better
                weak_sources = {"computation"}
                if (
                    ev.confidence >= 0.8
                    and ev.source_type.value.lower() in weak_sources
                ):
                    high_conf_weak_source += 1

            if high_conf_weak_source > 0 and total_evidence > 0:
                ratio = high_conf_weak_source / total_evidence
                if ratio > 0.5:
                    results.append(Evidence(
                        source="adversarial",
                        source_type=EvidenceType.ADVERSARIAL,
                        claim_field=f"{pillar.pillar_name}_confidence",
                        confirms=False,
                        reasoning=(
                            f"OVERCONFIDENT: {pillar.pillar_name} has "
                            f"{high_conf_weak_source}/{total_evidence} "
                            f"high-confidence evidence from weak sources"
                        ),
                        confidence=0.5,
                    ))

        return results

    def _challenge_pillar_coverage(
        self, pillar_results: Dict[str, PillarResult]
    ) -> List[Evidence]:
        """
        Checks if enough pillars ran to form a verdict.

        A verdict based on a single pillar is weak.
        """
        results: List[Evidence] = []

        expected_pillars = {
            "forensic_integrity",
            "logic_triangulation",
            "attestation_proof",
        }
        present = set(pillar_results.keys())
        missing = expected_pillars - present

        if len(missing) >= 2:
            results.append(Evidence(
                source="adversarial",
                source_type=EvidenceType.ADVERSARIAL,
                claim_field="pillar_coverage",
                confirms=False,
                reasoning=(
                    f"WEAK COVERAGE: {len(missing)} pillars missing "
                    f"({', '.join(missing)}) — verdict based on limited data"
                ),
                confidence=0.6,
            ))
        elif missing:
            # One missing is acceptable but noted
            results.append(Evidence(
                source="adversarial",
                source_type=EvidenceType.ADVERSARIAL,
                claim_field="pillar_coverage",
                confirms=True,
                reasoning=(
                    f"Coverage acceptable: {len(present)}/3 pillars present "
                    f"(missing: {', '.join(missing)})"
                ),
                confidence=0.4,
            ))
        else:
            results.append(Evidence(
                source="adversarial",
                source_type=EvidenceType.ADVERSARIAL,
                claim_field="pillar_coverage",
                confirms=True,
                reasoning="Full coverage: all 3 pillars present",
                confidence=0.7,
            ))

        return results

    def _challenge_content_plausibility(
        self, payload: Dict[str, Any]
    ) -> List[Evidence]:
        """
        Content-based adversarial checks on the original payload.

        Looks for signs of fabricated or placeholder data that other
        checks might miss by only looking at pillar results.
        """
        results: List[Evidence] = []

        # Check for suspiciously repetitive values
        str_values = []
        for key, val in payload.items():
            if isinstance(val, str) and len(val) > 2:
                str_values.append(val)

        if len(str_values) >= 3:
            unique_ratio = len(set(str_values)) / len(str_values)
            if unique_ratio < 0.3:
                results.append(Evidence(
                    source="adversarial",
                    source_type=EvidenceType.ADVERSARIAL,
                    claim_field="content_repetition",
                    confirms=False,
                    reasoning=(
                        f"REPETITIVE CONTENT: {unique_ratio:.0%} unique values "
                        f"across {len(str_values)} string fields — possible copy-paste"
                    ),
                    confidence=0.6,
                ))

        # Check for placeholder patterns
        placeholder_patterns = ("test", "example", "sample", "placeholder", "lorem", "foo", "bar")
        placeholder_hits = 0
        for val in str_values:
            if any(p in val.lower() for p in placeholder_patterns):
                placeholder_hits += 1

        if placeholder_hits >= 2:
            results.append(Evidence(
                source="adversarial",
                source_type=EvidenceType.ADVERSARIAL,
                claim_field="placeholder_content",
                confirms=False,
                reasoning=(
                    f"PLACEHOLDER DATA: {placeholder_hits} fields contain "
                    f"test/example/placeholder values"
                ),
                confidence=0.7,
            ))

        return results
