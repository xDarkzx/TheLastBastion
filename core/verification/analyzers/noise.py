"""
Noise Pattern Analyzer.

Every camera/scanner produces a unique sensor noise fingerprint.
Consistent noise across the image = single capture device (authentic).
Inconsistent noise across regions = composite from multiple sources.

Detects: Documents assembled from multiple scans, composited images.
"""
from typing import Any, Dict, List, Optional

from core.verification.analyzers.base import BaseAnalyzer
from core.verification.models import Evidence, EvidenceType, LayerResult

try:
    import numpy as np
    HAS_NUMPY = True
except ImportError:
    HAS_NUMPY = False

try:
    from PIL import ImageFilter
    HAS_PIL = True
except ImportError:
    HAS_PIL = False


class NoiseAnalyzer(BaseAnalyzer):
    """Detects multi-source composites via sensor noise fingerprinting."""

    @property
    def name(self) -> str:
        return "noise_pattern"

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
        if not HAS_NUMPY or not HAS_PIL:
            return self._unavailable_result("Requires numpy + Pillow")

        if image is None:
            return self._unavailable_result("No image provided")

        evidence: List[Evidence] = []

        try:
            # Extract noise: original minus blurred version
            gray = image.convert("L")
            blurred = gray.filter(ImageFilter.GaussianBlur(radius=3))

            gray_arr = np.array(gray, dtype=np.float32)
            blur_arr = np.array(blurred, dtype=np.float32)
            noise = gray_arr - blur_arr

            # Divide into quadrants and compare noise characteristics
            h, w = noise.shape
            mid_h, mid_w = h // 2, w // 2

            quadrants = {
                "top_left": noise[:mid_h, :mid_w],
                "top_right": noise[:mid_h, mid_w:],
                "bottom_left": noise[mid_h:, :mid_w],
                "bottom_right": noise[mid_h:, mid_w:],
            }

            quad_stats = {}
            for qname, q_data in quadrants.items():
                if q_data.size > 0:
                    quad_stats[qname] = {
                        "mean": round(float(np.mean(q_data)), 4),
                        "std": round(float(np.std(q_data)), 4),
                    }

            if len(quad_stats) < 4:
                return LayerResult(
                    layer_name=self.name,
                    score=0.5,
                    warnings=["Image too small for quadrant noise analysis"],
                )

            # Coefficient of variation across quadrant noise stds
            stds = [s["std"] for s in quad_stats.values()]
            mean_std = float(np.mean(stds))
            cv = float(np.std(stds) / mean_std) if mean_std > 0 else 0

            if cv < 0.15:
                score = 0.9
                reasoning = (
                    f"Noise consistent (CV={cv:.3f}): "
                    f"single capture device likely"
                )
            elif cv < 0.3:
                score = 0.7
                reasoning = (
                    f"Noise minor variation (CV={cv:.3f}): "
                    f"acceptable for scanned documents"
                )
            elif cv < 0.5:
                score = 0.4
                reasoning = (
                    f"Noise significant variation (CV={cv:.3f}): "
                    f"possible multi-source composite"
                )
            else:
                score = 0.15
                reasoning = (
                    f"Noise inconsistent (CV={cv:.3f}): "
                    f"strong composite evidence"
                )

            evidence.append(Evidence(
                source="noise_analysis",
                source_type=EvidenceType.FORENSIC,
                claim_field="document_integrity",
                confirms=score >= 0.5,
                reasoning=reasoning,
                confidence=score,
            ))

            self.logger.info(
                f"NOISE: CV={cv:.3f}, score={score:.2f}"
            )

            return LayerResult(
                layer_name=self.name,
                score=round(score, 4),
                evidence=evidence,
                metadata={"quadrant_stats": quad_stats, "cv": round(cv, 4)},
            )

        except Exception as e:
            self.logger.warning(f"Noise analysis failed: {e}")
            return LayerResult(
                layer_name=self.name,
                score=0.5,
                warnings=[f"Noise analysis error: {str(e)}"],
            )
