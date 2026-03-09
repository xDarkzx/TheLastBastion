"""
Attestation Verifier (Pillar 3 — Step 8).

Proves that a physical artifact EXISTED at a specific place and time.
Even if we can't prove the DATA inside it is 'fair', we can prove
the document was real, captured by a real device, at a real location.

Checks:
1. GPS Plausibility — is the location a real address?
2. Temporal Plausibility — timestamp within reasonable window
3. Depth Verification — depth map shows paper geometry (not flat screen)
4. Device Consistency — same device fingerprint across submissions
5. Anti-Replay — haven't we seen this exact bundle before?
6. Provenance Hash — blockchain-ready composite hash

The value: "I can prove with certainty that this specific piece of paper
existed in this warehouse on March 4, 2026."
"""
import hashlib
import logging
import math
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from typing import Any, Dict, List, Optional, Set, Tuple

from core.verification.models import Evidence, EvidenceType, LayerResult, PillarResult

logger = logging.getLogger("AttestationVerifier")


@dataclass
class AttestationBundle:
    """
    A submission bundle containing provenance evidence.

    Captures everything needed to prove a physical artifact
    existed at a specific place and time.
    """
    file_bytes: bytes
    file_hash: str = ""  # Computed automatically if empty
    gps_latitude: Optional[float] = None
    gps_longitude: Optional[float] = None
    gps_accuracy_meters: Optional[float] = None
    timestamp: Optional[str] = None        # ISO-8601
    device_fingerprint: Optional[str] = None
    depth_map_available: bool = False
    depth_variance: Optional[float] = None  # Std dev of depth values
    video_frame_count: int = 0
    submission_metadata: Dict[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:
        if not self.file_hash and self.file_bytes:
            self.file_hash = hashlib.sha256(self.file_bytes).hexdigest()


class AttestationVerifier:
    """
    Verifies human-attested document submissions where the physical
    provenance of the artifact can be cryptographically proven.

    Each check produces evidence that feeds into the attestation
    pillar score. Multiple checks can independently confirm or
    deny provenance.
    """

    # Maximum age for a submission timestamp (24 hours)
    MAX_SUBMISSION_AGE_HOURS = 24

    # Minimum GPS accuracy to be useful (meters)
    MIN_GPS_ACCURACY = 500.0

    # Minimum depth variance to indicate real paper (not flat screen)
    MIN_DEPTH_VARIANCE = 0.01

    _MAX_SEEN_HASHES = 100_000  # Prevent unbounded memory growth
    _MAX_DEVICE_HISTORY = 10_000

    def __init__(self) -> None:
        # Anti-replay: set of seen provenance hashes (bounded)
        self._seen_hashes: Set[str] = set()
        # Device history: fingerprint -> list of submission timestamps (bounded)
        self._device_history: Dict[str, List[str]] = {}

    async def verify(
        self, bundle: AttestationBundle
    ) -> PillarResult:
        """
        Runs all attestation checks on a submission bundle.

        Args:
            bundle: AttestationBundle with provenance data

        Returns: PillarResult with attestation score
        """
        evidence: List[Evidence] = []
        warnings: List[str] = []
        layer_results: List[LayerResult] = []

        # --- Check 1: GPS Plausibility ---
        gps_result = self._check_gps_plausibility(bundle)
        layer_results.append(gps_result)
        evidence.extend(gps_result.evidence)

        # --- Check 2: Temporal Plausibility ---
        temporal_result = self._check_temporal_plausibility(bundle)
        layer_results.append(temporal_result)
        evidence.extend(temporal_result.evidence)

        # --- Check 3: Depth Verification ---
        depth_result = self._check_depth_authenticity(bundle)
        layer_results.append(depth_result)
        evidence.extend(depth_result.evidence)

        # --- Check 4: Device Consistency ---
        device_result = self._check_device_consistency(bundle)
        layer_results.append(device_result)
        evidence.extend(device_result.evidence)

        # --- Check 5: Anti-Replay ---
        replay_result = self._check_anti_replay(bundle)
        layer_results.append(replay_result)
        evidence.extend(replay_result.evidence)

        # --- Generate Provenance Hash ---
        provenance_hash = self.generate_provenance_hash(bundle)

        # Record for future anti-replay (bounded to prevent memory growth)
        self._seen_hashes.add(provenance_hash)
        if len(self._seen_hashes) > self._MAX_SEEN_HASHES:
            # Evict oldest half (set has no order, but this prevents unbounded growth)
            evict_count = len(self._seen_hashes) // 2
            it = iter(self._seen_hashes)
            for _ in range(evict_count):
                self._seen_hashes.discard(next(it))
        if bundle.device_fingerprint:
            ts = bundle.timestamp or datetime.utcnow().isoformat()
            if bundle.device_fingerprint not in self._device_history:
                self._device_history[bundle.device_fingerprint] = []
            self._device_history[bundle.device_fingerprint].append(ts)
            # Bound device history
            if len(self._device_history) > self._MAX_DEVICE_HISTORY:
                oldest_keys = list(self._device_history.keys())[:len(self._device_history) // 2]
                for k in oldest_keys:
                    del self._device_history[k]

        # --- Composite Score ---
        scored_layers = [lr for lr in layer_results if lr.score >= 0]
        if scored_layers:
            avg_score = sum(lr.score for lr in scored_layers) / len(scored_layers)
        else:
            avg_score = 0.5

        # Completeness bonus: having MORE provenance data is better
        completeness = self._compute_completeness(bundle)
        # Blend: 70% check results, 30% completeness
        composite = avg_score * 0.7 + completeness * 0.3

        is_veto = any(lr.is_veto for lr in layer_results)
        veto_reason = next(
            (lr.veto_reason for lr in layer_results if lr.is_veto), ""
        )
        if is_veto:
            composite = min(composite, 0.1)

        # Cap composite when critical checks fail hard
        # GPS spoofing (null island, etc.) should drag the whole score down
        if gps_result.score <= 0.15:
            composite = min(composite, 0.3)
        # Stale timestamps are suspicious
        if temporal_result.score <= 0.4:
            composite = min(composite, 0.4)
        # Screen photo (flat depth) is a red flag
        if depth_result.score <= 0.2:
            composite = min(composite, 0.4)

        logger.info(
            f"ATTESTATION: score={composite:.2f}, "
            f"completeness={completeness:.2f}, "
            f"hash={provenance_hash[:16]}..."
        )

        return PillarResult(
            pillar_name="attestation_proof",
            score=round(composite, 4),
            layer_results=layer_results,
            evidence_chain=evidence,
            is_veto=is_veto,
            veto_reason=veto_reason,
        )

    def generate_provenance_hash(self, bundle: AttestationBundle) -> str:
        """
        Creates the blockchain-ready provenance hash.

        hash = SHA-256(
            file_hash +
            gps_lat + gps_lon +
            timestamp_unix +
            depth_variance +
            device_fingerprint
        )

        This hash proves:
        "This specific document was captured by this device,
         at this location, at this time."
        """
        components = [
            bundle.file_hash or "",
            str(bundle.gps_latitude or ""),
            str(bundle.gps_longitude or ""),
            bundle.timestamp or "",
            str(bundle.depth_variance or ""),
            bundle.device_fingerprint or "",
        ]
        combined = "|".join(components)
        return hashlib.sha256(combined.encode()).hexdigest()

    # --- Individual Checks ---

    def _check_gps_plausibility(self, bundle: AttestationBundle) -> LayerResult:
        """
        Validates GPS coordinates are real and accurate enough.

        Checks:
        - Lat/lon within valid ranges (-90/90, -180/180)
        - Accuracy is reasonable (< 500m)
        - Not at null island (0, 0) — common fake GPS
        """
        if bundle.gps_latitude is None or bundle.gps_longitude is None:
            return LayerResult(
                layer_name="gps_plausibility",
                score=0.3,
                evidence=[Evidence(
                    source="attestation",
                    source_type=EvidenceType.ATTESTATION,
                    claim_field="gps",
                    confirms=False,
                    reasoning="No GPS data provided — cannot verify location",
                    confidence=0.5,
                )],
                warnings=["No GPS coordinates in submission"],
            )

        lat, lon = bundle.gps_latitude, bundle.gps_longitude
        evidence: List[Evidence] = []
        score = 0.9

        # Valid range check
        if not (-90 <= lat <= 90 and -180 <= lon <= 180):
            return LayerResult(
                layer_name="gps_plausibility",
                score=0.0,
                evidence=[Evidence(
                    source="attestation",
                    source_type=EvidenceType.ATTESTATION,
                    claim_field="gps",
                    confirms=False,
                    found_value=f"({lat}, {lon})",
                    reasoning="GPS coordinates outside valid range",
                    confidence=0.95,
                )],
                is_veto=True,
                veto_reason="Invalid GPS coordinates",
            )

        # Null island check (0, 0)
        if abs(lat) < 0.01 and abs(lon) < 0.01:
            score = 0.1
            evidence.append(Evidence(
                source="attestation",
                source_type=EvidenceType.ATTESTATION,
                claim_field="gps",
                confirms=False,
                found_value=f"({lat}, {lon})",
                reasoning="GPS at Null Island (0,0) — common spoofed location",
                confidence=0.85,
            ))
        else:
            evidence.append(Evidence(
                source="attestation",
                source_type=EvidenceType.ATTESTATION,
                claim_field="gps",
                confirms=True,
                found_value=f"({lat:.6f}, {lon:.6f})",
                reasoning=f"GPS coordinates valid: ({lat:.6f}, {lon:.6f})",
                confidence=0.6,
            ))

        # Accuracy check
        if bundle.gps_accuracy_meters is not None:
            if bundle.gps_accuracy_meters > self.MIN_GPS_ACCURACY:
                score -= 0.2
                evidence.append(Evidence(
                    source="attestation",
                    source_type=EvidenceType.ATTESTATION,
                    claim_field="gps_accuracy",
                    confirms=False,
                    found_value=f"{bundle.gps_accuracy_meters:.1f}m",
                    reasoning=(
                        f"GPS accuracy {bundle.gps_accuracy_meters:.1f}m "
                        f"is poor (>{self.MIN_GPS_ACCURACY}m)"
                    ),
                    confidence=0.6,
                ))
            else:
                evidence.append(Evidence(
                    source="attestation",
                    source_type=EvidenceType.ATTESTATION,
                    claim_field="gps_accuracy",
                    confirms=True,
                    found_value=f"{bundle.gps_accuracy_meters:.1f}m",
                    reasoning=(
                        f"GPS accuracy {bundle.gps_accuracy_meters:.1f}m — "
                        f"acceptable"
                    ),
                    confidence=0.7,
                ))

        return LayerResult(
            layer_name="gps_plausibility",
            score=max(0.0, round(score, 4)),
            evidence=evidence,
            metadata={
                "latitude": lat,
                "longitude": lon,
                "accuracy_m": bundle.gps_accuracy_meters,
            },
        )

    def _check_temporal_plausibility(self, bundle: AttestationBundle) -> LayerResult:
        """
        Validates the submission timestamp.

        Checks:
        - Timestamp is parseable
        - Not too far in the past (>24h stale)
        - Not in the future
        """
        if not bundle.timestamp:
            return LayerResult(
                layer_name="temporal_plausibility",
                score=0.3,
                evidence=[Evidence(
                    source="attestation",
                    source_type=EvidenceType.ATTESTATION,
                    claim_field="timestamp",
                    confirms=False,
                    reasoning="No timestamp provided",
                    confidence=0.5,
                )],
                warnings=["No submission timestamp"],
            )

        try:
            ts = datetime.fromisoformat(
                bundle.timestamp.replace("Z", "+00:00").replace("+00:00", "")
            )
        except ValueError:
            return LayerResult(
                layer_name="temporal_plausibility",
                score=0.1,
                evidence=[Evidence(
                    source="attestation",
                    source_type=EvidenceType.ATTESTATION,
                    claim_field="timestamp",
                    confirms=False,
                    found_value=bundle.timestamp,
                    reasoning=f"Unparseable timestamp: {bundle.timestamp}",
                    confidence=0.8,
                )],
            )

        now = datetime.utcnow()
        evidence: List[Evidence] = []

        # Future check
        if ts > now + timedelta(minutes=5):
            return LayerResult(
                layer_name="temporal_plausibility",
                score=0.1,
                evidence=[Evidence(
                    source="attestation",
                    source_type=EvidenceType.ATTESTATION,
                    claim_field="timestamp",
                    confirms=False,
                    found_value=bundle.timestamp,
                    reasoning=f"Timestamp is in the future: {ts.isoformat()}",
                    confidence=0.85,
                )],
                warnings=["Future timestamp detected"],
            )

        # Staleness check
        age = now - ts
        age_hours = age.total_seconds() / 3600

        if age_hours > self.MAX_SUBMISSION_AGE_HOURS:
            score = 0.4
            evidence.append(Evidence(
                source="attestation",
                source_type=EvidenceType.ATTESTATION,
                claim_field="timestamp",
                confirms=False,
                found_value=f"{age_hours:.1f} hours ago",
                reasoning=(
                    f"Submission is {age_hours:.1f}h old "
                    f"(max {self.MAX_SUBMISSION_AGE_HOURS}h)"
                ),
                confidence=0.6,
            ))
        else:
            score = 0.9
            evidence.append(Evidence(
                source="attestation",
                source_type=EvidenceType.ATTESTATION,
                claim_field="timestamp",
                confirms=True,
                found_value=f"{age_hours:.1f} hours ago",
                reasoning=f"Timestamp fresh: {age_hours:.1f}h old — valid",
                confidence=0.7,
            ))

        return LayerResult(
            layer_name="temporal_plausibility",
            score=round(score, 4),
            evidence=evidence,
            metadata={"age_hours": round(age_hours, 2)},
        )

    def _check_depth_authenticity(self, bundle: AttestationBundle) -> LayerResult:
        """
        Verifies depth map proves a real 3D object (not a flat screen).

        Real paper has Z-depth variation (curves, folds, thickness).
        A photo of a screen is FLAT (uniform Z-depth).
        """
        if not bundle.depth_map_available:
            return LayerResult(
                layer_name="depth_authenticity",
                score=0.3,
                evidence=[Evidence(
                    source="attestation",
                    source_type=EvidenceType.ATTESTATION,
                    claim_field="depth_map",
                    confirms=False,
                    reasoning="No depth map provided — cannot verify 3D presence",
                    confidence=0.4,
                )],
                warnings=["No depth data — cannot distinguish paper from screen"],
            )

        if bundle.depth_variance is None:
            return LayerResult(
                layer_name="depth_authenticity",
                score=0.3,
                evidence=[Evidence(
                    source="attestation",
                    source_type=EvidenceType.ATTESTATION,
                    claim_field="depth_variance",
                    confirms=False,
                    reasoning="Depth map available but no variance computed",
                    confidence=0.3,
                )],
            )

        evidence: List[Evidence] = []

        if bundle.depth_variance < self.MIN_DEPTH_VARIANCE:
            # Too flat — looks like a screen
            score = 0.15
            evidence.append(Evidence(
                source="attestation",
                source_type=EvidenceType.ATTESTATION,
                claim_field="depth_variance",
                confirms=False,
                found_value=f"{bundle.depth_variance:.4f}",
                reasoning=(
                    f"Depth variance {bundle.depth_variance:.4f} is too flat "
                    f"— likely a screen capture, not real paper"
                ),
                confidence=0.8,
            ))
        else:
            # Real paper has bends, curves, thickness
            score = 0.9
            evidence.append(Evidence(
                source="attestation",
                source_type=EvidenceType.ATTESTATION,
                claim_field="depth_variance",
                confirms=True,
                found_value=f"{bundle.depth_variance:.4f}",
                reasoning=(
                    f"Depth variance {bundle.depth_variance:.4f} — "
                    f"3D geometry consistent with real paper"
                ),
                confidence=0.8,
            ))

        return LayerResult(
            layer_name="depth_authenticity",
            score=round(score, 4),
            evidence=evidence,
            metadata={"depth_variance": bundle.depth_variance},
        )

    def _check_device_consistency(self, bundle: AttestationBundle) -> LayerResult:
        """
        Checks device fingerprint for consistency across submissions.

        A consistent device fingerprint across multiple submissions
        increases confidence. A new device is neutral.
        """
        if not bundle.device_fingerprint:
            return LayerResult(
                layer_name="device_consistency",
                score=0.4,
                evidence=[Evidence(
                    source="attestation",
                    source_type=EvidenceType.ATTESTATION,
                    claim_field="device_fingerprint",
                    confirms=False,
                    reasoning="No device fingerprint — cannot verify device",
                    confidence=0.4,
                )],
            )

        fp = bundle.device_fingerprint
        history = self._device_history.get(fp, [])

        if len(history) >= 3:
            score = 0.9
            reasoning = (
                f"Device {fp[:12]}... has {len(history)} prior submissions "
                f"— established trust"
            )
            confirms = True
        elif len(history) >= 1:
            score = 0.7
            reasoning = (
                f"Device {fp[:12]}... has {len(history)} prior submission(s) "
                f"— building trust"
            )
            confirms = True
        else:
            score = 0.5
            reasoning = f"New device {fp[:12]}... — first submission"
            confirms = True  # Neutral, not negative

        return LayerResult(
            layer_name="device_consistency",
            score=round(score, 4),
            evidence=[Evidence(
                source="attestation",
                source_type=EvidenceType.ATTESTATION,
                claim_field="device_fingerprint",
                confirms=confirms,
                found_value=fp[:16],
                reasoning=reasoning,
                confidence=0.6,
            )],
            metadata={
                "fingerprint": fp[:16],
                "prior_submissions": len(history),
            },
        )

    def _check_anti_replay(self, bundle: AttestationBundle) -> LayerResult:
        """
        Detects replayed submissions (same bundle submitted twice).

        A previously-seen provenance hash means someone is re-submitting
        the exact same data — possible replay attack.
        """
        provenance_hash = self.generate_provenance_hash(bundle)

        if provenance_hash in self._seen_hashes:
            return LayerResult(
                layer_name="anti_replay",
                score=0.0,
                evidence=[Evidence(
                    source="attestation",
                    source_type=EvidenceType.ATTESTATION,
                    claim_field="replay_check",
                    confirms=False,
                    found_value=provenance_hash[:16],
                    reasoning=(
                        f"REPLAY DETECTED: Hash {provenance_hash[:16]}... "
                        f"has been submitted before"
                    ),
                    confidence=0.95,
                )],
                is_veto=True,
                veto_reason="Replay attack — duplicate submission",
            )

        return LayerResult(
            layer_name="anti_replay",
            score=0.9,
            evidence=[Evidence(
                source="attestation",
                source_type=EvidenceType.ATTESTATION,
                claim_field="replay_check",
                confirms=True,
                found_value=provenance_hash[:16],
                reasoning=f"First-seen submission — hash {provenance_hash[:16]}...",
                confidence=0.8,
            )],
            metadata={"provenance_hash": provenance_hash},
        )

    def _compute_completeness(self, bundle: AttestationBundle) -> float:
        """
        Scores how much provenance data was provided.

        More data = higher confidence in the attestation.
        """
        max_fields = 6
        present = 0

        if bundle.gps_latitude is not None:
            present += 1
        if bundle.timestamp:
            present += 1
        if bundle.device_fingerprint:
            present += 1
        if bundle.depth_map_available:
            present += 1
        if bundle.video_frame_count > 0:
            present += 1
        if bundle.file_hash:
            present += 1

        return present / max_fields
