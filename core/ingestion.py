"""
Ingestion Pipeline — The Front Door for All Data.

Accepts raw data from any source and format, assigns provenance,
computes content hashes, and routes to document intelligence
for extraction and normalization.

Supported formats:
    - PDF documents (invoices, manuals, reports)
    - Images (scanned docs, photos of physical docs)
    - CSV/Excel (spreadsheets, exports)
    - JSON (API dumps, structured submissions)
    - Free text (emails, notes, unstructured input)

Every piece of data that enters the system gets:
    1. A unique submission_id
    2. A SHA-256 content hash (data_hash)
    3. Source provenance (who submitted, when, via what protocol)
    4. Format detection and routing
    5. Raw bytes stored for audit trail
"""
import hashlib
import io
import json
import logging
import secrets
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

logger = logging.getLogger("Ingestion")


class DataFormat(str, Enum):
    """Supported input data formats."""
    PDF = "pdf"
    IMAGE_JPEG = "image/jpeg"
    IMAGE_PNG = "image/png"
    CSV = "csv"
    EXCEL = "excel"
    DOCX = "docx"
    JSON = "json"
    TEXT = "text"
    UNKNOWN = "unknown"


# Magic bytes for format detection (note: XLSX and DOCX share PK ZIP header)
FORMAT_SIGNATURES: Dict[bytes, DataFormat] = {
    b"%PDF": DataFormat.PDF,
    b"\xff\xd8\xff": DataFormat.IMAGE_JPEG,
    b"\x89PNG": DataFormat.IMAGE_PNG,
    # PK\x03\x04 handled separately in _detect_format to distinguish XLSX vs DOCX
}


@dataclass
class SourceProvenance:
    """
    Records who submitted data, when, and how.

    This is the audit trail that proves where data came from.
    """
    source_agent_id: str            # Which agent submitted (or "human")
    submission_protocol: str        # "m2m", "api", "upload", "webhook"
    source_url: str = ""            # Original URL if scraped
    source_ip: str = ""             # Requester IP (if applicable)
    submission_time: str = ""
    metadata: Dict[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:
        if not self.submission_time:
            self.submission_time = datetime.utcnow().isoformat()

    def to_dict(self) -> Dict[str, Any]:
        return {
            "source_agent_id": self.source_agent_id,
            "submission_protocol": self.submission_protocol,
            "source_url": self.source_url,
            "source_ip": self.source_ip,
            "submission_time": self.submission_time,
            "metadata": self.metadata,
        }


@dataclass
class IngestResult:
    """
    Result of ingesting raw data.

    Contains everything needed to track, extract, and verify
    the submitted data throughout the pipeline.
    """
    submission_id: str
    data_hash: str                  # SHA-256 of raw content
    detected_format: DataFormat
    raw_size_bytes: int
    provenance: SourceProvenance
    extracted_fields: Dict[str, Any] = field(default_factory=dict)
    extraction_confidence: float = 0.0
    warnings: List[str] = field(default_factory=list)
    is_duplicate: bool = False
    duplicate_of: str = ""          # Submission ID of original
    status: str = "ingested"        # ingested, extracting, extracted, failed

    def to_dict(self) -> Dict[str, Any]:
        return {
            "submission_id": self.submission_id,
            "data_hash": self.data_hash,
            "detected_format": self.detected_format.value,
            "raw_size_bytes": self.raw_size_bytes,
            "provenance": self.provenance.to_dict(),
            "extracted_fields": self.extracted_fields,
            "extraction_confidence": self.extraction_confidence,
            "warnings": self.warnings,
            "is_duplicate": self.is_duplicate,
            "status": self.status,
        }


class IngestPipeline:
    """
    Central ingestion point for all incoming data.

    Accepts raw bytes or structured data, detects format,
    assigns provenance, checks for duplicates, and prepares
    data for the extraction and verification stages.
    """

    # Maximum file size (50 MB)
    MAX_FILE_SIZE_BYTES = 50 * 1024 * 1024

    # Minimum file size (empty files rejected)
    MIN_FILE_SIZE_BYTES = 1

    def __init__(self, storage_path: Optional[str] = None) -> None:
        self._submissions: Dict[str, IngestResult] = {}
        self._hash_index: Dict[str, str] = {}  # data_hash -> submission_id
        self._stats = {
            "total_submissions": 0,
            "duplicates_detected": 0,
            "by_format": {},
            "total_bytes_ingested": 0,
        }
        self._storage_path = Path(storage_path) if storage_path else None
        if self._storage_path:
            self._storage_path.mkdir(parents=True, exist_ok=True)

    def ingest_bytes(
        self,
        raw_bytes: bytes,
        provenance: SourceProvenance,
        declared_format: Optional[str] = None,
    ) -> IngestResult:
        """
        Ingests raw binary data (PDF, image, etc.).

        Steps:
            1. Validate size limits
            2. Compute content hash
            3. Detect format from magic bytes
            4. Check for duplicates
            5. Store raw bytes (if storage configured)
            6. Return IngestResult for downstream processing
        """
        # Size validation
        size = len(raw_bytes)
        warnings: List[str] = []

        if size < self.MIN_FILE_SIZE_BYTES:
            return self._create_failed_result(
                provenance, "File is empty", size
            )

        if size > self.MAX_FILE_SIZE_BYTES:
            return self._create_failed_result(
                provenance,
                f"File exceeds {self.MAX_FILE_SIZE_BYTES // (1024*1024)}MB limit",
                size,
            )

        # Content hash
        data_hash = hashlib.sha256(raw_bytes).hexdigest()

        # Format detection
        detected = self._detect_format(raw_bytes, declared_format)

        # Duplicate check
        submission_id = f"sub-{secrets.token_hex(8)}"
        is_duplicate = False
        duplicate_of = ""

        if data_hash in self._hash_index:
            is_duplicate = True
            duplicate_of = self._hash_index[data_hash]
            warnings.append(
                f"Duplicate of submission {duplicate_of}"
            )
            self._stats["duplicates_detected"] += 1
            logger.warning(
                f"DUPLICATE: {data_hash[:16]}... matches {duplicate_of}"
            )

        # Store raw bytes
        if self._storage_path and not is_duplicate:
            raw_path = self._storage_path / f"{submission_id}.raw"
            raw_path.write_bytes(raw_bytes)

        # Create result
        result = IngestResult(
            submission_id=submission_id,
            data_hash=data_hash,
            detected_format=detected,
            raw_size_bytes=size,
            provenance=provenance,
            warnings=warnings,
            is_duplicate=is_duplicate,
            duplicate_of=duplicate_of,
        )

        # Register
        self._submissions[submission_id] = result
        if not is_duplicate:
            self._hash_index[data_hash] = submission_id

        # Stats
        self._stats["total_submissions"] += 1
        self._stats["total_bytes_ingested"] += size
        fmt_key = detected.value
        self._stats["by_format"][fmt_key] = (
            self._stats["by_format"].get(fmt_key, 0) + 1
        )

        logger.info(
            f"INGESTED: {submission_id} "
            f"(format={detected.value}, size={size}, "
            f"hash={data_hash[:16]}..., "
            f"source={provenance.source_agent_id})"
        )
        return result

    def ingest_structured(
        self,
        data: Dict[str, Any],
        provenance: SourceProvenance,
    ) -> IngestResult:
        """
        Ingests pre-structured JSON data (from API calls or agent output).

        The data is serialized deterministically for hashing,
        then stored as a JSON submission.
        """
        # Serialize deterministically for consistent hashing
        canonical = json.dumps(
            data, sort_keys=True, separators=(",", ":")
        ).encode()

        submission_id = f"sub-{secrets.token_hex(8)}"
        data_hash = hashlib.sha256(canonical).hexdigest()

        # Duplicate check
        is_duplicate = data_hash in self._hash_index
        duplicate_of = self._hash_index.get(data_hash, "")

        if is_duplicate:
            self._stats["duplicates_detected"] += 1

        result = IngestResult(
            submission_id=submission_id,
            data_hash=data_hash,
            detected_format=DataFormat.JSON,
            raw_size_bytes=len(canonical),
            provenance=provenance,
            extracted_fields=data,         # Already structured
            extraction_confidence=1.0,     # Already structured
            is_duplicate=is_duplicate,
            duplicate_of=duplicate_of,
            status="extracted",            # No extraction needed
        )

        self._submissions[submission_id] = result
        if not is_duplicate:
            self._hash_index[data_hash] = submission_id

        self._stats["total_submissions"] += 1
        self._stats["total_bytes_ingested"] += len(canonical)
        self._stats["by_format"]["json"] = (
            self._stats["by_format"].get("json", 0) + 1
        )

        logger.info(
            f"INGESTED (structured): {submission_id} "
            f"(fields={len(data)}, hash={data_hash[:16]}..., "
            f"source={provenance.source_agent_id})"
        )
        return result

    def ingest_csv_text(
        self,
        csv_content: str,
        provenance: SourceProvenance,
    ) -> IngestResult:
        """
        Ingests CSV text content.

        Parses rows into a list of field dicts.
        """
        raw_bytes = csv_content.encode("utf-8")
        data_hash = hashlib.sha256(raw_bytes).hexdigest()
        submission_id = f"sub-{secrets.token_hex(8)}"

        # Parse CSV using Python's csv module
        import csv
        import io
        rows = []
        lines = csv_content.strip().split("\n")
        if len(lines) > 1:
            reader = csv.DictReader(io.StringIO(csv_content))
            for row in reader:
                rows.append(dict(row))

        result = IngestResult(
            submission_id=submission_id,
            data_hash=data_hash,
            detected_format=DataFormat.CSV,
            raw_size_bytes=len(raw_bytes),
            provenance=provenance,
            extracted_fields={"rows": rows, "row_count": len(rows)},
            extraction_confidence=0.9 if rows else 0.0,
            status="extracted" if rows else "failed",
            warnings=[] if rows else ["CSV parsing produced 0 rows"],
        )

        self._submissions[submission_id] = result
        self._hash_index.setdefault(data_hash, submission_id)
        self._stats["total_submissions"] += 1
        self._stats["total_bytes_ingested"] += len(raw_bytes)
        self._stats["by_format"]["csv"] = (
            self._stats["by_format"].get("csv", 0) + 1
        )

        logger.info(
            f"INGESTED (CSV): {submission_id} "
            f"(rows={len(rows)}, hash={data_hash[:16]}...)"
        )
        return result

    def get_submission(self, submission_id: str) -> Optional[IngestResult]:
        """Retrieves a submission by ID."""
        return self._submissions.get(submission_id)

    def get_submission_by_hash(self, data_hash: str) -> Optional[IngestResult]:
        """Retrieves a submission by content hash."""
        sub_id = self._hash_index.get(data_hash)
        if sub_id:
            return self._submissions.get(sub_id)
        return None

    @property
    def stats(self) -> Dict[str, Any]:
        return dict(self._stats)

    def _detect_format(
        self,
        raw_bytes: bytes,
        declared: Optional[str] = None,
    ) -> DataFormat:
        """
        Detects data format from magic bytes.

        Falls back to declared format if magic bytes don't match.
        Distinguishes XLSX from DOCX (both are ZIP archives with PK header).
        """
        # Check magic byte signatures
        for signature, fmt in FORMAT_SIGNATURES.items():
            if raw_bytes[:len(signature)] == signature:
                return fmt

        # ZIP-based formats: XLSX and DOCX both start with PK\x03\x04
        if raw_bytes[:4] == b"PK\x03\x04":
            return self._detect_zip_format(raw_bytes, declared)

        # Fallback to declared format
        if declared:
            declared_lower = declared.lower()
            if "docx" in declared_lower or "word" in declared_lower:
                return DataFormat.DOCX
            if "xlsx" in declared_lower or "excel" in declared_lower:
                return DataFormat.EXCEL
            for fmt in DataFormat:
                if declared_lower in fmt.value:
                    return fmt

        # Try to detect text/JSON
        try:
            text = raw_bytes[:1000].decode("utf-8")
            stripped = text.strip()
            if stripped.startswith("{") or stripped.startswith("["):
                return DataFormat.JSON
            if "," in text and "\n" in text:
                return DataFormat.CSV
            return DataFormat.TEXT
        except UnicodeDecodeError:
            return DataFormat.UNKNOWN

    def _detect_zip_format(
        self,
        raw_bytes: bytes,
        declared: Optional[str] = None,
    ) -> DataFormat:
        """
        Distinguishes XLSX from DOCX by examining ZIP contents.
        Both are ZIP archives — XLSX contains 'xl/' entries, DOCX contains 'word/' entries.
        """
        import zipfile
        try:
            with zipfile.ZipFile(io.BytesIO(raw_bytes)) as zf:
                names = zf.namelist()
                has_xl = any(n.startswith("xl/") for n in names)
                has_word = any(n.startswith("word/") for n in names)
                if has_xl:
                    return DataFormat.EXCEL
                if has_word:
                    return DataFormat.DOCX
        except Exception:
            pass

        # Fallback: check declared format
        if declared:
            dl = declared.lower()
            if "docx" in dl or "word" in dl:
                return DataFormat.DOCX
            if "xlsx" in dl or "excel" in dl:
                return DataFormat.EXCEL

        # Default ZIP to EXCEL (more common in data pipelines)
        return DataFormat.EXCEL

    def _create_failed_result(
        self,
        provenance: SourceProvenance,
        error: str,
        size: int,
    ) -> IngestResult:
        """Creates a failed ingestion result."""
        return IngestResult(
            submission_id=f"sub-{secrets.token_hex(8)}",
            data_hash="",
            detected_format=DataFormat.UNKNOWN,
            raw_size_bytes=size,
            provenance=provenance,
            warnings=[error],
            status="failed",
        )
