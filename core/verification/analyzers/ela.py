"""
Error Level Analysis (ELA) Analyzer.

Re-compresses an image at a known quality level, then compares
the pixel-level differences between original and recompressed.
Edited regions appear as "hot spots" because they were saved
at a different compression level than the rest of the image.

Detects: Photoshop edits, pasted text, replaced numbers.
"""
import io
from typing import Any, Dict, List, Optional

from core.verification.analyzers.base import BaseAnalyzer
from core.verification.models import Evidence, EvidenceType, LayerResult

# Conditional imports — graceful degradation
try:
    import numpy as np
    HAS_NUMPY = True
except ImportError:
    HAS_NUMPY = False

try:
    from PIL import Image
    HAS_PIL = True
except ImportError:
    HAS_PIL = False


class ELAAnalyzer(BaseAnalyzer):
    """Detects image tampering via Error Level Analysis."""

    # JPEG re-compression quality for comparison
    RECOMPRESS_QUALITY = 90
    # Mean block-level ELA above this -> "hot spot"
    HOTSPOT_THRESHOLD = 25

    @property
    def name(self) -> str:
        return "ela"

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
            # Convert to RGB (JPEG doesn't support RGBA/palette modes)
            rgb_image = image.convert("RGB")

            # Re-compress at known quality
            buffer = io.BytesIO()
            rgb_image.save(buffer, format="JPEG", quality=self.RECOMPRESS_QUALITY)
            buffer.seek(0)
            recompressed = Image.open(buffer)

            # Compute pixel-level differences
            original_arr = np.array(image.convert("RGB"), dtype=np.float32)
            recomp_arr = np.array(
                recompressed.convert("RGB").resize(image.size),
                dtype=np.float32,
            )
            diff = np.abs(original_arr - recomp_arr)

            mean_diff = float(np.mean(diff))
            std_diff = float(np.std(diff))
            max_diff = float(np.max(diff))

            # Regional variance: split into blocks and measure per-block ELA
            block_means = self._compute_block_means(diff)
            block_std = float(np.std(block_means)) if len(block_means) > 1 else 0.0
            block_cv = block_std / (float(np.mean(block_means)) + 1e-6)

            # Outlier detection: check if any blocks are significantly above
            # the median (a small edited region in a mostly-uniform image)
            # Bimodal detection: check for two distinct ELA populations
            # (edited region vs original — different compression artifacts)
            if len(block_means) > 4:
                sorted_means = sorted(block_means)
                n = len(sorted_means)
                median_val = sorted_means[n // 2]
                p90_val = sorted_means[int(n * 0.9)]
                p25_val = sorted_means[int(n * 0.25)]
                p75_val = sorted_means[int(n * 0.75)]
                # How much do the top 10% of blocks differ from median?
                outlier_ratio = (p90_val / (median_val + 1e-6))
                # Interquartile ratio: detects two distinct populations
                iq_ratio = (p75_val / (p25_val + 1e-6))
            else:
                outlier_ratio = 1.0
                iq_ratio = 1.0

            # Score: combine global std, regional variance, and outlier detection
            # Global std catches large-scale edits
            # block_cv catches half-and-half composites
            # outlier_ratio catches small edited regions
            # iq_ratio catches bimodal ELA (two compression populations)
            has_outlier = outlier_ratio > 2.0
            has_regional_variance = block_cv >= 0.3
            has_bimodal = iq_ratio > 2.0

            if std_diff < 5.0 and not has_regional_variance and not has_outlier and not has_bimodal:
                score = 0.95
                reasoning = (
                    f"ELA uniform (std={std_diff:.1f}, block_cv={block_cv:.2f}, "
                    f"outlier={outlier_ratio:.1f}, iq={iq_ratio:.1f}): compression "
                    f"artifacts consistent — likely unedited"
                )
            elif std_diff < 5.0 and (has_regional_variance or has_outlier or has_bimodal):
                # Low global variance but localized inconsistency
                if block_cv >= 0.6 or outlier_ratio > 3.0 or iq_ratio > 3.0:
                    score = 0.25
                    reasoning = (
                        f"ELA localized edit detected (std={std_diff:.1f}, "
                        f"block_cv={block_cv:.2f}, outlier={outlier_ratio:.1f}): "
                        f"regional compression inconsistency"
                    )
                else:
                    score = 0.45
                    reasoning = (
                        f"ELA suspicious regional variation (std={std_diff:.1f}, "
                        f"block_cv={block_cv:.2f}, outlier={outlier_ratio:.1f}): "
                        f"possible localized editing"
                    )
            elif std_diff < 10.0:
                score = 0.75
                reasoning = (
                    f"ELA minor variation (std={std_diff:.1f}): "
                    f"acceptable JPEG artifact range"
                )
            elif std_diff < 20.0:
                score = 0.4
                reasoning = (
                    f"ELA suspicious (std={std_diff:.1f}): regions "
                    f"show different compression levels"
                )
            else:
                score = 0.15
                reasoning = (
                    f"ELA high variation (std={std_diff:.1f}): strong "
                    f"evidence of post-compression editing"
                )

            evidence.append(Evidence(
                source="ela_analysis",
                source_type=EvidenceType.FORENSIC,
                claim_field="document_integrity",
                confirms=score >= 0.5,
                reasoning=reasoning,
                confidence=score,
            ))

            # Detect localized hot spots (lowered threshold for sensitivity)
            hot_spots = self._find_hotspots(diff)
            if hot_spots:
                score = min(score, 0.3)
                evidence.append(Evidence(
                    source="ela_hotspot",
                    source_type=EvidenceType.FORENSIC,
                    claim_field="document_integrity",
                    confirms=False,
                    reasoning=(
                        f"Found {len(hot_spots)} ELA hot spot(s) — "
                        f"localized editing detected"
                    ),
                    confidence=0.8,
                ))

            self.logger.info(
                f"ELA: std={std_diff:.1f}, mean={mean_diff:.1f}, "
                f"hotspots={len(hot_spots)}, score={score:.2f}"
            )

            return LayerResult(
                layer_name=self.name,
                score=round(score, 4),
                evidence=evidence,
                metadata={
                    "mean_diff": round(mean_diff, 2),
                    "max_diff": round(max_diff, 2),
                    "std_diff": round(std_diff, 2),
                    "block_cv": round(block_cv, 4),
                    "outlier_ratio": round(outlier_ratio, 2),
                    "iq_ratio": round(iq_ratio, 2),
                    "hotspot_count": len(hot_spots),
                },
            )

        except Exception as e:
            self.logger.warning(f"ELA analysis failed: {e}")
            return LayerResult(
                layer_name=self.name,
                score=0.5,
                warnings=[f"ELA error: {str(e)}"],
            )

    def _compute_block_means(self, diff: "np.ndarray") -> List[float]:
        """Computes mean ELA per block for regional variance analysis."""
        block_size = max(16, min(diff.shape[0], diff.shape[1]) // 10)
        h, w = diff.shape[:2]
        means = []
        for y in range(0, h - block_size, block_size):
            for x in range(0, w - block_size, block_size):
                block = diff[y:y + block_size, x:x + block_size]
                means.append(float(np.mean(block)))
        return means

    def _find_hotspots(self, diff: "np.ndarray") -> List[Dict[str, Any]]:
        """Finds image blocks with abnormally high ELA values."""
        block_size = max(16, min(diff.shape[0], diff.shape[1]) // 10)
        h, w = diff.shape[:2]
        hot_spots = []

        for y in range(0, h - block_size, block_size):
            for x in range(0, w - block_size, block_size):
                block = diff[y:y + block_size, x:x + block_size]
                block_mean = float(np.mean(block))
                if block_mean > self.HOTSPOT_THRESHOLD:
                    hot_spots.append({
                        "x": x, "y": y,
                        "size": block_size,
                        "intensity": round(block_mean, 2),
                    })

        return hot_spots
