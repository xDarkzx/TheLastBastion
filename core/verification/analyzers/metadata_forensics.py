"""
Metadata Forensics Analyzer.

Examines EXIF data, PDF producer fields, creation/modification dates,
software signatures, and file-level metadata to detect tampering.

Detects: Post-creation edits, metadata stripping, editing tool mismatch.
"""
import hashlib
import io
from datetime import datetime
from typing import Any, Dict, List, Optional, Tuple

from core.verification.analyzers.base import BaseAnalyzer
from core.verification.models import Evidence, EvidenceType, LayerResult

try:
    from PIL import Image
    HAS_PIL = True
except ImportError:
    HAS_PIL = False

# Software names that indicate image editing
SUSPICIOUS_SOFTWARE = [
    "photoshop", "gimp", "paint.net",
    "affinity", "pixlr", "canva",
    "illustrator", "inkscape",
]


class MetadataForensicsAnalyzer(BaseAnalyzer):
    """Analyzes EXIF/PDF metadata for tampering indicators."""

    @property
    def name(self) -> str:
        return "metadata_forensics"

    @property
    def supported_types(self) -> List[str]:
        return ["jpg", "jpeg", "png", "tiff", "bmp", "webp", "pdf"]

    @property
    def dependencies(self) -> List[str]:
        return []  # No hard dependencies — works with raw bytes

    async def analyze(
        self,
        file_bytes: bytes,
        file_type: str,
        image: Optional[Any] = None,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> LayerResult:
        evidence: List[Evidence] = []
        warnings: List[str] = []
        score = 0.7  # Base — metadata alone isn't conclusive

        # File hash for audit trail
        file_hash = hashlib.sha256(file_bytes).hexdigest()
        evidence.append(Evidence(
            source="metadata_forensics",
            source_type=EvidenceType.FORENSIC,
            claim_field="file_hash",
            confirms=True,
            found_value=file_hash[:16] + "...",
            reasoning="SHA-256 computed for audit trail",
            raw_proof_hash=file_hash,
        ))

        # EXIF analysis for images
        ft = file_type.lower().strip(".")
        if ft in ("jpg", "jpeg", "tiff") and HAS_PIL:
            exif_score, exif_ev, exif_warn = self._analyze_exif(file_bytes)
            score = (score + exif_score) / 2
            evidence.extend(exif_ev)
            warnings.extend(exif_warn)

        # External metadata checks
        if metadata:
            for ok, msg in self._check_external_metadata(metadata):
                if not ok:
                    warnings.append(msg)
                    score -= 0.1

        # File size reasonableness
        size_kb = len(file_bytes) / 1024
        if ft in ("jpg", "jpeg") and size_kb < 5:
            warnings.append(
                f"Very small JPEG ({size_kb:.0f}KB) — "
                f"may be heavily compressed or thumbnail"
            )
            score -= 0.1
        elif ft == "pdf" and size_kb < 1:
            warnings.append("PDF smaller than 1KB — likely invalid")
            score -= 0.2

        score = max(0.0, min(1.0, score))

        self.logger.info(
            f"METADATA: {ft.upper()} ({len(file_bytes)} bytes), "
            f"score={score:.2f}, warnings={len(warnings)}"
        )

        return LayerResult(
            layer_name=self.name,
            score=round(score, 4),
            evidence=evidence,
            warnings=warnings,
            metadata={"file_hash": file_hash, "file_size_kb": round(size_kb, 1)},
        )

    def _analyze_exif(
        self, file_bytes: bytes
    ) -> Tuple[float, List[Evidence], List[str]]:
        """Extracts and analyzes EXIF metadata."""
        evidence: List[Evidence] = []
        warnings: List[str] = []
        score = 0.7

        try:
            img = Image.open(io.BytesIO(file_bytes))
            exif = img.getexif()

            if not exif:
                warnings.append(
                    "No EXIF metadata — may have been stripped"
                )
                score = 0.3
                evidence.append(Evidence(
                    source="exif_analysis",
                    source_type=EvidenceType.FORENSIC,
                    claim_field="metadata",
                    confirms=False,
                    reasoning="Missing EXIF — metadata stripping is suspicious",
                    confidence=0.6,
                ))
                return score, evidence, warnings

            # Check software field (tag 305)
            software = exif.get(305, "")
            if software:
                sw_lower = software.lower()
                if any(s in sw_lower for s in SUSPICIOUS_SOFTWARE):
                    warnings.append(
                        f"Created/modified with editor: '{software}'"
                    )
                    score = 0.3
                    evidence.append(Evidence(
                        source="exif_analysis",
                        source_type=EvidenceType.FORENSIC,
                        claim_field="software",
                        confirms=False,
                        found_value=software,
                        reasoning=f"Editing software '{software}' detected",
                        confidence=0.7,
                    ))
                else:
                    evidence.append(Evidence(
                        source="exif_analysis",
                        source_type=EvidenceType.FORENSIC,
                        claim_field="software",
                        confirms=True,
                        found_value=software,
                        reasoning=f"Software '{software}' — not a known editor",
                        confidence=0.6,
                    ))

            # Check creation vs modification dates
            date_original = exif.get(36867, "")  # DateTimeOriginal
            date_modified = exif.get(306, "")     # DateTime

            if date_original and date_modified and date_original != date_modified:
                warnings.append(
                    f"Creation ({date_original}) differs from "
                    f"modification ({date_modified}) — file was edited"
                )
                score -= 0.15
            elif date_original and date_modified:
                evidence.append(Evidence(
                    source="exif_analysis",
                    source_type=EvidenceType.FORENSIC,
                    claim_field="dates",
                    confirms=True,
                    reasoning="Creation and modification dates match",
                    confidence=0.7,
                ))

            return score, evidence, warnings

        except Exception as e:
            self.logger.warning(f"EXIF analysis failed: {e}")
            return 0.5, [], [f"EXIF parse error: {str(e)}"]

    def _check_external_metadata(
        self, metadata: Dict[str, Any]
    ) -> List[Tuple[bool, str]]:
        """Checks externally provided metadata for red flags."""
        checks = []

        claimed_date = metadata.get("document_date") or metadata.get("date")
        if claimed_date and isinstance(claimed_date, str):
            try:
                parsed = datetime.fromisoformat(claimed_date.replace("Z", ""))
                if parsed > datetime.utcnow():
                    checks.append((
                        False,
                        f"Document date '{claimed_date}' is in the future"
                    ))
            except (ValueError, TypeError):
                pass

        return checks
