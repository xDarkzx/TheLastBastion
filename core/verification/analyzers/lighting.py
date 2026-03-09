"""
Lighting Consistency Analyzer.

For photographed documents: analyzes brightness gradients across
a grid to detect inconsistent lighting that indicates compositing.

Real photos have smooth, directional light. Composites have
abrupt brightness transitions between pasted regions.

Detects: Composited photos, digitally overlaid text on real paper.
"""
from typing import Any, Dict, List, Optional

from core.verification.analyzers.base import BaseAnalyzer
from core.verification.models import Evidence, EvidenceType, LayerResult

try:
    import numpy as np
    HAS_NUMPY = True
except ImportError:
    HAS_NUMPY = False


class LightingAnalyzer(BaseAnalyzer):
    """Detects composites via brightness gradient analysis."""

    GRID_SIZE = 4  # 4×4 brightness grid

    @property
    def name(self) -> str:
        return "lighting"

    @property
    def supported_types(self) -> List[str]:
        return ["jpg", "jpeg", "png", "bmp", "tiff", "webp"]

    @property
    def dependencies(self) -> List[str]:
        return ["numpy", "Pillow"]

    async def analyze(
        self,
        file_bytes: bytes,
        file_type: str,
        image: Optional[Any] = None,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> LayerResult:
        if not HAS_NUMPY:
            return self._unavailable_result("Requires numpy")

        if image is None:
            return self._unavailable_result("No image provided")

        evidence: List[Evidence] = []

        try:
            gray = np.array(image.convert("L"), dtype=np.float32)
            h, w = gray.shape
            gs = self.GRID_SIZE
            cell_h, cell_w = h // gs, w // gs

            # Build brightness map
            brightness_map = []
            for gy in range(gs):
                row = []
                for gx in range(gs):
                    cell = gray[
                        gy * cell_h:(gy + 1) * cell_h,
                        gx * cell_w:(gx + 1) * cell_w,
                    ]
                    row.append(float(np.mean(cell)))
                brightness_map.append(row)

            flat = [v for row in brightness_map for v in row]
            brightness_std = float(np.std(flat))

            # Count gradient violations (abrupt transitions)
            # Use a FIXED threshold (not relative to image std) to catch
            # composites where large brightness jumps between adjacent cells
            # indicate pasted regions from different lighting conditions
            TRANSITION_THRESHOLD = 50.0  # 50 brightness levels = significant jump
            violations = 0
            total = 0
            max_transition = 0.0

            for gy in range(gs):
                for gx in range(gs - 1):
                    total += 1
                    diff = abs(brightness_map[gy][gx + 1] - brightness_map[gy][gx])
                    max_transition = max(max_transition, diff)
                    if diff > TRANSITION_THRESHOLD:
                        violations += 1

            for gy in range(gs - 1):
                for gx in range(gs):
                    total += 1
                    diff = abs(brightness_map[gy + 1][gx] - brightness_map[gy][gx])
                    max_transition = max(max_transition, diff)
                    if diff > TRANSITION_THRESHOLD:
                        violations += 1

            ratio = violations / max(total, 1)

            # Also flag extreme overall brightness variance (composites from
            # different lighting environments have very high cell-to-cell spread)
            if brightness_std > 70:
                # Extreme brightness spread — very likely composite
                score = 0.20
                reasoning = (
                    f"Extreme brightness spread (std={brightness_std:.1f}): "
                    f"strong composite evidence"
                )
            elif ratio < 0.08:
                score = 0.9
                reasoning = f"Lighting consistent (violations={ratio:.2f})"
            elif ratio < 0.25:
                # Natural photos can have horizon transitions, object edges
                # that produce some violations — this is normal
                score = 0.7
                reasoning = f"Lighting mostly consistent ({ratio:.2f})"
            elif ratio < 0.40:
                score = 0.4
                reasoning = f"Lighting inconsistencies ({ratio:.2f}) — possible composite"
            else:
                score = 0.2
                reasoning = f"Lighting highly inconsistent ({ratio:.2f}) — composite evidence"

            evidence.append(Evidence(
                source="lighting_analysis",
                source_type=EvidenceType.FORENSIC,
                claim_field="document_integrity",
                confirms=score >= 0.5,
                reasoning=reasoning,
                confidence=score,
            ))

            self.logger.info(
                f"LIGHTING: {violations}/{total} violations, "
                f"ratio={ratio:.2f}, score={score:.2f}"
            )

            return LayerResult(
                layer_name=self.name,
                score=round(score, 4),
                evidence=evidence,
                metadata={
                    "brightness_std": round(brightness_std, 2),
                    "violations": violations,
                    "violation_ratio": round(ratio, 3),
                },
            )

        except Exception as e:
            self.logger.warning(f"Lighting analysis failed: {e}")
            return LayerResult(
                layer_name=self.name,
                score=0.5,
                warnings=[f"Lighting error: {str(e)}"],
            )
