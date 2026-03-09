"""
Copy-Move Detection Analyzer.

Finds duplicate pixel regions within a document using block-hash
comparison. Real documents don't have cloned pixel patterns.

Detects: Copy-paste forgery where a section is duplicated over another.
"""
import hashlib
from typing import Any, Dict, List, Optional

from core.verification.analyzers.base import BaseAnalyzer
from core.verification.models import Evidence, EvidenceType, LayerResult

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


class CopyMoveAnalyzer(BaseAnalyzer):
    """Detects copy-paste forgery via block-hash duplicate detection."""

    BLOCK_SIZE = 16
    # Minimum distance between blocks to be considered "non-adjacent"
    MIN_DISTANCE_FACTOR = 3

    @property
    def name(self) -> str:
        return "copy_move"

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
            # Downscale for performance
            max_dim = 512
            ratio = min(max_dim / image.width, max_dim / image.height, 1.0)
            if ratio < 1.0:
                resized = image.resize(
                    (int(image.width * ratio), int(image.height * ratio)),
                    Image.LANCZOS,
                )
            else:
                resized = image

            gray = np.array(resized.convert("L"), dtype=np.float32)
            h, w = gray.shape
            bs = self.BLOCK_SIZE

            # Hash every overlapping block.
            # Skip low-variance blocks (uniform/gradient regions) which create
            # false positive matches. Only textured blocks are informative.
            MIN_BLOCK_VARIANCE = 50.0
            block_hashes: Dict[str, List[tuple]] = {}
            step = bs // 2
            for y in range(0, h - bs, step):
                for x in range(0, w - bs, step):
                    block = gray[y:y + bs, x:x + bs]
                    if float(np.var(block)) < MIN_BLOCK_VARIANCE:
                        continue  # Skip flat/gradient block
                    quantized = (block // 4).astype(np.uint8)
                    bh = hashlib.md5(quantized.tobytes()).hexdigest()[:8]
                    block_hashes.setdefault(bh, []).append((x, y))

            # Find non-adjacent duplicates with consistent shift vectors
            # Real copy-move: a contiguous region is cloned, producing many blocks
            # all shifted by the SAME dx,dy offset
            # Natural images: gradients/uniform areas create duplicates with
            # RANDOM shift vectors (no consistent pattern)
            min_dist = bs * self.MIN_DISTANCE_FACTOR
            shift_vectors: Dict[tuple, int] = {}

            for positions in block_hashes.values():
                if len(positions) < 2:
                    continue
                for i in range(len(positions)):
                    for j in range(i + 1, len(positions)):
                        dx = positions[j][0] - positions[i][0]
                        dy = positions[j][1] - positions[i][1]
                        dist = (dx ** 2 + dy ** 2) ** 0.5
                        if dist > min_dist:
                            # Quantize shift vector to nearest 16px
                            sv = ((dx // 16) * 16, (dy // 16) * 16)
                            shift_vectors[sv] = shift_vectors.get(sv, 0) + 1

            # Hash diversity check: gradients/uniform images have very few
            # unique hashes (many blocks look identical). Real images with
            # copy-move have high diversity except in the cloned region.
            total_hash_slots = sum(len(v) for v in block_hashes.values())
            unique_hashes = len(block_hashes)
            hash_diversity = unique_hashes / max(total_hash_slots, 1)

            # Only count coherent clusters that indicate REAL copy-move
            # Filter out gradient/uniform background patterns:
            # - Pure vertical shifts = horizontal gradient (sky, water)
            # - Pure horizontal shifts = vertical gradient (walls, columns)
            # Real copy-move almost always has DIAGONAL shift (both dx and dy != 0)
            max_coherent = 0
            for sv, count in shift_vectors.items():
                is_pure_vertical = (sv[0] == 0 and sv[1] != 0)
                is_pure_horizontal = (sv[0] != 0 and sv[1] == 0)

                # Skip ALL axis-aligned shifts — these are gradient artifacts
                if is_pure_vertical or is_pure_horizontal:
                    continue

                if count > max_coherent:
                    max_coherent = count

            total_blocks = max((h // bs) * (w // bs), 1)

            # If hash diversity is low (< 0.5), the image is mostly
            # gradient/uniform — heavily discount coherent clusters
            if hash_diversity < 0.5:
                max_coherent = int(max_coherent * hash_diversity * 0.5)

            dup_ratio = max_coherent / total_blocks

            if dup_ratio < 0.01:
                score = 0.9
                reasoning = f"Minimal duplication (ratio={dup_ratio:.3f}) — no copy-move"
            elif dup_ratio < 0.03:
                score = 0.7
                reasoning = f"Minor duplication ({dup_ratio:.3f}) — likely natural"
            elif dup_ratio < 0.08:
                score = 0.4
                reasoning = f"Significant duplication ({dup_ratio:.3f}) — suspicious"
            else:
                score = 0.15
                reasoning = f"Extensive duplication ({dup_ratio:.3f}) — strong copy-move"

            evidence.append(Evidence(
                source="copy_move_detection",
                source_type=EvidenceType.FORENSIC,
                claim_field="document_integrity",
                confirms=score >= 0.5,
                reasoning=reasoning,
                confidence=score,
            ))

            self.logger.info(
                f"COPY-MOVE: max_coherent={max_coherent}, "
                f"ratio={dup_ratio:.3f}, score={score:.2f}"
            )

            return LayerResult(
                layer_name=self.name,
                score=round(score, 4),
                evidence=evidence,
                metadata={
                    "max_coherent_cluster": max_coherent,
                    "dup_ratio": round(dup_ratio, 4),
                    "total_blocks": total_blocks,
                    "shift_vectors": len(shift_vectors),
                    "hash_diversity": round(hash_diversity, 4),
                },
            )

        except Exception as e:
            self.logger.warning(f"Copy-move detection failed: {e}")
            return LayerResult(
                layer_name=self.name,
                score=0.5,
                warnings=[f"Copy-move error: {str(e)}"],
            )
