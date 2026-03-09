"""
File Structure Analyzer.

Validates a file's binary structure: magic bytes, format headers,
and scans for embedded executables or polyglot attacks.

Detects: Renamed extensions, corrupted files, polyglot attacks.
"""
import hashlib
from typing import Any, Dict, List, Optional

from core.verification.analyzers.base import BaseAnalyzer
from core.verification.models import Evidence, EvidenceType, LayerResult

# Magic byte signatures for known file formats
MAGIC_MAP = {
    "pdf":  (b"%PDF", "PDF header"),
    "jpg":  (b"\xff\xd8\xff", "JPEG header"),
    "jpeg": (b"\xff\xd8\xff", "JPEG header"),
    "png":  (b"\x89PNG", "PNG header"),
    "gif":  (b"GIF8", "GIF header"),
    "bmp":  (b"BM", "BMP header"),
    "tiff": (b"II\x2a\x00", "TIFF LE header"),
    "webp": (b"RIFF", "WebP/RIFF header"),
}

# Embedded content that shouldn't be in documents
DANGEROUS_SIGNATURES = [
    (b"MZ", "Windows executable (PE)"),
    (b"\x7fELF", "Linux executable (ELF)"),
    (b"PK\x03\x04", "ZIP archive (hidden content)"),
]


class FileStructureAnalyzer(BaseAnalyzer):
    """Validates file binary structure and detects polyglot attacks."""

    @property
    def name(self) -> str:
        return "file_structure"

    @property
    def supported_types(self) -> List[str]:
        return list(MAGIC_MAP.keys())

    @property
    def dependencies(self) -> List[str]:
        return []  # Pure Python — no external deps

    async def analyze(
        self,
        file_bytes: bytes,
        file_type: str,
        image: Optional[Any] = None,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> LayerResult:
        evidence: List[Evidence] = []
        warnings: List[str] = []
        score = 0.8
        ft = file_type.lower().strip(".")

        # Magic bytes validation
        expected = MAGIC_MAP.get(ft)
        if expected:
            magic, label = expected
            if file_bytes[:len(magic)] == magic:
                score = 0.9
                evidence.append(Evidence(
                    source="file_structure",
                    source_type=EvidenceType.FORENSIC,
                    claim_field="file_format",
                    confirms=True,
                    reasoning=f"Valid {label}: magic bytes match .{ft} extension",
                    confidence=0.9,
                ))
            else:
                score = 0.2
                actual_hex = file_bytes[:8].hex()
                warnings.append(
                    f"Magic bytes mismatch: expected {label}, "
                    f"got 0x{actual_hex}"
                )
                evidence.append(Evidence(
                    source="file_structure",
                    source_type=EvidenceType.FORENSIC,
                    claim_field="file_format",
                    confirms=False,
                    reasoning=(
                        f"Extension .{ft} does not match content "
                        f"(0x{actual_hex})"
                    ),
                    confidence=0.9,
                ))

        # Scan for embedded executables / polyglot attacks
        for sig, desc in DANGEROUS_SIGNATURES:
            pos = file_bytes.find(sig, 10)  # Skip first 10 bytes
            if pos > 0:
                warnings.append(f"Embedded {desc} at offset {pos}")
                score -= 0.4
                evidence.append(Evidence(
                    source="file_structure",
                    source_type=EvidenceType.FORENSIC,
                    claim_field="embedded_content",
                    confirms=False,
                    reasoning=f"Embedded {desc} at byte {pos}",
                    confidence=0.7,
                ))

        score = max(0.0, min(1.0, score))

        self.logger.info(
            f"STRUCTURE: .{ft} ({len(file_bytes)} bytes), "
            f"score={score:.2f}"
        )

        return LayerResult(
            layer_name=self.name,
            score=round(score, 4),
            evidence=evidence,
            warnings=warnings,
            metadata={"file_size_bytes": len(file_bytes)},
        )
