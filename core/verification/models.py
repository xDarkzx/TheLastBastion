"""
Verification Models (v1.0): Shared data classes for the verification stack.

These models are used across all verification layers to maintain
a consistent evidence chain from ingestion through to verdict.
"""
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from typing import Any, Dict, List, Optional


class Verdict(str, Enum):
    """Final verification verdict."""
    REJECTED = "REJECTED"         # score < 0.40 or veto triggered
    QUARANTINE = "QUARANTINE"     # 0.40 <= score < 0.70
    VERIFIED = "VERIFIED"         # 0.70 <= score < 0.90
    GOLD = "GOLD"                 # score >= 0.90


class EvidenceType(str, Enum):
    """Source type for a piece of evidence."""
    API = "API"
    WEB = "WEB"
    CROSS_REFERENCE = "CROSS_REFERENCE"
    AUTHORITY = "AUTHORITY"
    COMPUTATION = "COMPUTATION"
    FORENSIC = "FORENSIC"
    LOGIC = "LOGIC"
    TEMPORAL = "TEMPORAL"
    ATTESTATION = "ATTESTATION"
    ADVERSARIAL = "ADVERSARIAL"


class FieldType(str, Enum):
    """Expected data types for schema validation."""
    STRING = "str"
    INTEGER = "int"
    FLOAT = "float"
    BOOLEAN = "bool"
    DATE = "date"           # ISO-8601 date string
    DATETIME = "datetime"   # ISO-8601 datetime string
    EMAIL = "email"
    URL = "url"
    CURRENCY = "currency"   # Numeric with 2 decimal places
    PERCENTAGE = "percentage"  # 0-100 or 0.0-1.0
    LIST = "list"
    DICT = "dict"


@dataclass
class DataClaim:
    """
    A single verifiable claim extracted from submitted data.

    Example: {"field_name": "price_kwh", "value": 0.28, "context": "Mercury Energy Auckland"}
    """
    field_name: str
    value: Any
    context: str = ""
    source: str = ""
    source_document: str = ""
    claimed_by: str = ""


@dataclass
class Evidence:
    """
    A piece of evidence for or against a claim.

    Tracks the full chain: what source, what it said,
    whether it confirms or contradicts, and the raw proof.
    """
    source: str                 # "mercury.co.nz", "companies.govt.nz", etc.
    source_type: EvidenceType
    claim_field: str            # Which field this evidence relates to
    confirms: bool              # True = confirms claim, False = contradicts
    found_value: Any = None     # What the source actually says
    expected_value: Any = None  # What the expected/correct value should be
    claimed_value: Any = None   # What was submitted
    confidence: float = 0.0     # How confident we are in this source (0-1)
    reasoning: str = ""         # Why this evidence matters
    timestamp: datetime = field(default_factory=datetime.utcnow)
    raw_proof_hash: str = ""    # SHA-256 of raw response for audit trail


@dataclass
class LayerResult:
    """
    Result from a single verification layer.

    Each layer produces a score (0.0 to 1.0), a list of evidence,
    and optional warnings or anomalies detected.
    """
    layer_name: str
    score: float                        # 0.0 to 1.0
    evidence: List[Evidence] = field(default_factory=list)
    warnings: List[str] = field(default_factory=list)
    anomalies: List[str] = field(default_factory=list)
    is_veto: bool = False               # If True, this layer vetoes the verdict
    veto_reason: str = ""               # Why it vetoed
    metadata: Dict[str, Any] = field(default_factory=dict)

    @property
    def passed(self) -> bool:
        """Layer passes if score >= 0.3 and no veto."""
        return self.score >= 0.3 and not self.is_veto


@dataclass
class PillarResult:
    """
    Result from a verification pillar (forensic, triangulation, attestation).

    A pillar is a group of related layers.
    """
    pillar_name: str
    score: float
    layer_results: List[LayerResult] = field(default_factory=list)
    evidence_chain: List[Evidence] = field(default_factory=list)
    is_veto: bool = False
    veto_reason: str = ""


@dataclass
class VerificationVerdict:
    """
    Final composite verdict from the verification stack.

    Contains the overall score, verdict classification,
    breakdown by pillar, and the complete evidence chain.
    """
    score: float
    verdict: str                # "REJECTED", "QUARANTINE", "VERIFIED", "GOLD"
    pillar_results: Dict[str, Any] = field(default_factory=dict)
    pre_check_results: List[Any] = field(default_factory=list)
    pillar_breakdown: Dict[str, float] = field(default_factory=dict)
    evidence_chain: List[Evidence] = field(default_factory=list)
    layer_details: List[LayerResult] = field(default_factory=list)
    veto_triggered: bool = False
    veto_reason: str = ""
    payload_hash: str = ""
    timestamp: str = ""

    def to_dict(self) -> Dict[str, Any]:
        """Serializes verdict to dict for API/DB storage."""
        breakdown = {}
        for name, pr in self.pillar_results.items():
            if hasattr(pr, "score"):
                breakdown[name] = round(pr.score, 4)

        return {
            "score": round(self.score, 4),
            "verdict": self.verdict,
            "pillar_breakdown": breakdown,
            "evidence_count": len(self.evidence_chain),
            "veto_triggered": self.veto_triggered,
            "veto_reason": self.veto_reason,
            "payload_hash": self.payload_hash,
            "timestamp": self.timestamp,
            "layers": [
                {
                    "name": lr.layer_name,
                    "score": round(lr.score, 4),
                    "warnings": lr.warnings,
                    "anomalies": lr.anomalies,
                    "evidence_count": len(lr.evidence),
                    "is_veto": lr.is_veto,
                }
                for lr in self.layer_details
            ],
        }


# --- Schema Definition Helpers ---

@dataclass
class FieldSpec:
    """
    Specification for a single field in a data schema.

    Used by the Schema Gatekeeper to validate incoming data.
    """
    name: str
    field_type: FieldType
    required: bool = True
    min_value: Optional[float] = None   # For numeric types
    max_value: Optional[float] = None   # For numeric types
    min_length: Optional[int] = None    # For string types
    max_length: Optional[int] = None    # For string types
    allowed_values: Optional[List[Any]] = None  # Enum-style restriction
    pattern: Optional[str] = None       # Regex pattern for strings
    description: str = ""               # Human-readable purpose


@dataclass
class DataSchema:
    """
    Complete schema definition for a data type.

    Defines what fields are expected, their types,
    and constraints for validation.
    """
    name: str
    version: str = "1.0"
    fields: List[FieldSpec] = field(default_factory=list)
    description: str = ""

    def get_field(self, name: str) -> Optional[FieldSpec]:
        """Returns a FieldSpec by name, or None if not found."""
        for f in self.fields:
            if f.name == name:
                return f
        return None

    def required_fields(self) -> List[str]:
        """Returns list of required field names."""
        return [f.name for f in self.fields if f.required]

    def to_dict(self) -> Dict[str, Any]:
        """Serializes the schema for storage."""
        return {
            "name": self.name,
            "version": self.version,
            "description": self.description,
            "fields": [
                {
                    "name": f.name,
                    "type": f.field_type.value,
                    "required": f.required,
                    "min_value": f.min_value,
                    "max_value": f.max_value,
                    "min_length": f.min_length,
                    "max_length": f.max_length,
                    "allowed_values": f.allowed_values,
                    "description": f.description,
                }
                for f in self.fields
            ],
        }
