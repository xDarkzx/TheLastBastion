"""
PDF Forensics Analyzer.

PDF-specific analysis: incremental saves (editing history),
embedded JavaScript, producer/creator tool detection.

Detects: Post-creation edits, malicious PDFs, image-editor-produced PDFs.
"""
from typing import Any, Dict, List, Optional

from core.verification.analyzers.base import BaseAnalyzer
from core.verification.models import Evidence, EvidenceType, LayerResult

SUSPICIOUS_PRODUCERS = [
    "photoshop", "gimp", "inkscape",
    "illustrator", "paint",
]


class PDFForensicsAnalyzer(BaseAnalyzer):
    """Analyzes PDF internal structure for tampering indicators."""

    @property
    def name(self) -> str:
        return "pdf_forensics"

    @property
    def supported_types(self) -> List[str]:
        return ["pdf"]

    @property
    def dependencies(self) -> List[str]:
        return []  # Pure Python — parses raw bytes

    async def analyze(
        self,
        file_bytes: bytes,
        file_type: str,
        image: Optional[Any] = None,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> LayerResult:
        evidence: List[Evidence] = []
        warnings: List[str] = []
        score = 0.7

        # Decode first 50KB for text-based analysis
        content = file_bytes[:min(len(file_bytes), 50000)]
        try:
            text = content.decode("latin-1", errors="ignore")
        except Exception:
            text = ""

        # Check incremental saves (%%EOF count)
        eof_count = text.count("%%EOF")
        if eof_count > 1:
            edit_count = eof_count - 1
            warnings.append(
                f"PDF edited {edit_count} time(s) after creation "
                f"({eof_count} %%EOF markers)"
            )
            score -= 0.1 if eof_count <= 3 else 0.2
            evidence.append(Evidence(
                source="pdf_forensics",
                source_type=EvidenceType.FORENSIC,
                claim_field="document_integrity",
                confirms=False,
                reasoning=f"{eof_count} incremental saves — document was modified",
                confidence=0.6,
            ))

        # Check for embedded JavaScript
        if "/JavaScript" in text or "/JS" in text:
            warnings.append("PDF contains JavaScript — potentially malicious")
            score -= 0.3
            evidence.append(Evidence(
                source="pdf_forensics",
                source_type=EvidenceType.FORENSIC,
                claim_field="security",
                confirms=False,
                reasoning="Embedded JavaScript in PDF",
                confidence=0.8,
            ))

        # Check producer/creator tool
        producer = self._extract_producer(text)
        if producer:
            is_suspicious = any(
                s in producer.lower() for s in SUSPICIOUS_PRODUCERS
            )
            if is_suspicious:
                warnings.append(f"PDF from image editor: '{producer}'")
                score -= 0.25

            evidence.append(Evidence(
                source="pdf_forensics",
                source_type=EvidenceType.FORENSIC,
                claim_field="producer",
                confirms=not is_suspicious,
                found_value=producer,
                reasoning=f"PDF producer: '{producer}'",
                confidence=0.5,
            ))

        score = max(0.0, min(1.0, score))

        self.logger.info(
            f"PDF: eof_count={eof_count}, score={score:.2f}"
        )

        return LayerResult(
            layer_name=self.name,
            score=round(score, 4),
            evidence=evidence,
            warnings=warnings,
            metadata={"eof_count": eof_count},
        )

    def _extract_producer(self, text: str) -> Optional[str]:
        """Extracts /Producer or /Creator value from PDF text."""
        for marker in ["/Producer", "/Creator"]:
            idx = text.find(marker)
            if idx >= 0:
                start = text.find("(", idx)
                end = text.find(")", start + 1) if start >= 0 else -1
                if start >= 0 and end >= 0:
                    return text[start + 1:end][:100]
        return None
