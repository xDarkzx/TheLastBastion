"""
Forensic Integrity Compositor (Pillar 1).

Orchestrates all registered forensic sub-analyzers via dependency injection.
Each sub-analyzer implements BaseAnalyzer and is independently testable.

Architecture:
    ForensicIntegrityAnalyzer
      ├── FileStructureAnalyzer  (file_structure.py)
      ├── MetadataForensics      (metadata_forensics.py)
      ├── ELAAnalyzer            (ela.py)
      ├── NoiseAnalyzer          (noise.py)
      ├── CopyMoveAnalyzer       (copy_move.py)
      ├── LightingAnalyzer       (lighting.py)
      ├── FabricationDetector    (fabrication_detector.py)  ← NEW
      └── PDFForensicsAnalyzer   (pdf_forensics.py)
"""
import io
import logging
from typing import Any, Dict, List, Optional

from core.verification.analyzers.base import BaseAnalyzer
from core.verification.analyzers.copy_move import CopyMoveAnalyzer
from core.verification.analyzers.ela import ELAAnalyzer
from core.verification.analyzers.fabrication_detector import FabricationDetector
from core.verification.analyzers.file_structure import FileStructureAnalyzer
from core.verification.analyzers.lighting import LightingAnalyzer
from core.verification.analyzers.metadata_forensics import MetadataForensicsAnalyzer
from core.verification.analyzers.noise import NoiseAnalyzer
from core.verification.analyzers.pdf_forensics import PDFForensicsAnalyzer
from core.verification.models import Evidence, LayerResult, PillarResult

logger = logging.getLogger("ForensicIntegrity")

# Conditional import for image loading
try:
    from PIL import Image
    # Protect against decompression bombs (e.g., 50000x50000 pixel images)
    Image.MAX_IMAGE_PIXELS = 50_000_000  # ~50MP — reasonable limit
    HAS_PIL = True
except ImportError:
    HAS_PIL = False


class ForensicIntegrityAnalyzer:
    """
    Compositor that orchestrates all forensic sub-analyzers.

    Responsibilities:
    1. Maintains a registry of available sub-analyzers
    2. Filters analyzers by file type and dependency availability
    3. Loads the image once and passes it to all image-based analyzers
    4. Collects results and produces a composite PillarResult

    New analyzers can be registered at runtime via `register()`.
    """

    def __init__(self) -> None:
        self._analyzers: List[BaseAnalyzer] = []
        # Register all built-in analyzers
        self._register_defaults()

    def _register_defaults(self) -> None:
        """Registers all built-in forensic sub-analyzers."""
        defaults = [
            FileStructureAnalyzer(),   # Always runs (no deps)
            MetadataForensicsAnalyzer(),  # Always runs (no deps)
            ELAAnalyzer(),
            NoiseAnalyzer(),
            CopyMoveAnalyzer(),
            LightingAnalyzer(),
            FabricationDetector(),     # NEW: camera vs fabrication
            PDFForensicsAnalyzer(),
        ]
        for analyzer in defaults:
            self.register(analyzer)

    def register(self, analyzer: BaseAnalyzer) -> None:
        """
        Registers a new sub-analyzer.

        Args:
            analyzer: Must implement BaseAnalyzer interface
        """
        if not isinstance(analyzer, BaseAnalyzer):
            raise TypeError(
                f"Analyzer must implement BaseAnalyzer, "
                f"got {type(analyzer).__name__}"
            )
        self._analyzers.append(analyzer)
        logger.debug(
            f"Registered analyzer: {analyzer.name} "
            f"(types={analyzer.supported_types}, "
            f"available={analyzer.available})"
        )

    @property
    def registered_analyzers(self) -> List[str]:
        """Returns names of all registered analyzers."""
        return [a.name for a in self._analyzers]

    def get_applicable(self, file_type: str) -> List[BaseAnalyzer]:
        """Returns analyzers that support this file type and have deps."""
        ft = file_type.lower().strip(".")
        return [
            a for a in self._analyzers
            if a.supports(ft) and a.available
        ]

    async def analyze(
        self,
        file_bytes: bytes,
        file_type: str,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> PillarResult:
        """
        Runs all applicable sub-analyzers on the document.

        Args:
            file_bytes: Raw document bytes
            file_type: File extension (e.g., "jpg", "pdf")
            metadata: Optional externally provided metadata

        Returns: PillarResult combining all sub-analyzer results
        """
        ft = file_type.lower().strip(".")
        applicable = self.get_applicable(ft)

        if not applicable:
            logger.warning(
                f"No applicable analyzers for .{ft} — "
                f"returning neutral score"
            )
            return PillarResult(
                pillar_name="forensic_integrity",
                score=0.5,
                layer_results=[LayerResult(
                    layer_name="no_analyzers",
                    score=0.5,
                    warnings=[f"No forensic analyzers available for .{ft}"],
                )],
            )

        # Pre-load image once (shared across all image analyzers)
        image = None
        if ft in ("jpg", "jpeg", "png", "bmp", "tiff", "webp") and HAS_PIL:
            image = self._load_image(file_bytes)

        # Run all applicable analyzers
        layer_results: List[LayerResult] = []
        evidence_chain: List[Evidence] = []
        skipped: List[str] = []

        for analyzer in applicable:
            try:
                result = await analyzer.analyze(
                    file_bytes=file_bytes,
                    file_type=ft,
                    image=image,
                    metadata=metadata,
                )
                layer_results.append(result)
                evidence_chain.extend(result.evidence)
            except Exception as e:
                logger.warning(
                    f"Analyzer '{analyzer.name}' raised: {e}"
                )
                # Score 0.3 (suspicious), not 0.5 (neutral) — crash ≠ clean
                layer_results.append(LayerResult(
                    layer_name=analyzer.name,
                    score=0.3,
                    warnings=[f"Analyzer error: {str(e)}"],
                ))

        # Report analyzers that were skipped (available but not applicable)
        all_names = {a.name for a in self._analyzers}
        ran_names = {a.name for a in applicable}
        skipped = list(all_names - ran_names)

        # Composite score: average of all layer scores
        if layer_results:
            total = sum(lr.score for lr in layer_results)
            avg_score = total / len(layer_results)
        else:
            avg_score = 0.5

        # Suspicion correlation: if too many analyzers give near-perfect
        # scores, something is wrong. Real documents have imperfections.
        avg_score = self._apply_suspicion_correlation(
            avg_score, layer_results
        )

        # Check for vetoes
        is_veto = any(lr.is_veto for lr in layer_results)
        veto_reason = next(
            (lr.veto_reason for lr in layer_results if lr.is_veto), ""
        )
        if is_veto:
            avg_score = min(avg_score, 0.1)

        logger.info(
            f"FORENSIC: .{ft} ({len(file_bytes)} bytes) — "
            f"ran {len(applicable)} analyzers, "
            f"skipped {len(skipped)}, score={avg_score:.2f}"
        )

        return PillarResult(
            pillar_name="forensic_integrity",
            score=round(avg_score, 4),
            layer_results=layer_results,
            evidence_chain=evidence_chain,
            is_veto=is_veto,
            veto_reason=veto_reason,
        )

    def _load_image(self, file_bytes: bytes) -> Optional["Image.Image"]:
        """Safely loads a PIL Image from bytes."""
        try:
            image = Image.open(io.BytesIO(file_bytes))
            image.load()
            return image
        except Exception as e:
            logger.warning(f"Image load failed: {e}")
            return None

    def _apply_suspicion_correlation(
        self, base_score: float, layer_results: List[LayerResult]
    ) -> float:
        """
        Suspicion correlation: real-world documents ALWAYS have
        imperfections. If everything looks too perfect, that's a
        signal of digital fabrication.

        Count how many tampering-detection layers gave near-perfect
        scores (≥ 0.88). If too many are perfect simultaneously,
        apply a penalty.
        """
        tamper_layers = {
            "ela", "noise_pattern", "copy_move", "lighting"
        }
        perfect_count = 0
        tamper_count = 0

        for lr in layer_results:
            if lr.layer_name in tamper_layers:
                tamper_count += 1
                if lr.score >= 0.88:
                    perfect_count += 1

        if tamper_count == 0:
            return base_score

        # If ALL tamper-detection layers are near-perfect,
        # something is suspiciously clean
        if perfect_count >= tamper_count and tamper_count >= 3:
            penalty = 0.15
            logger.info(
                f"SUSPICION: {perfect_count}/{tamper_count} tamper-detection "
                f"layers are too-perfect — applying {penalty} penalty"
            )
            # Also add a warning to the fabrication layer if it exists
            for lr in layer_results:
                if lr.layer_name == "fabrication_detector":
                    lr.warnings.append(
                        f"{perfect_count} tamper layers scored ≥0.88 — "
                        f"suspiciously perfect for a real document"
                    )
            return base_score - penalty
        elif perfect_count >= 3:
            penalty = 0.08
            logger.info(
                f"SUSPICION: {perfect_count}/{tamper_count} layers perfect "
                f"— minor penalty {penalty}"
            )
            return base_score - penalty

        return base_score
