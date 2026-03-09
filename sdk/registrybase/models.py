"""Pydantic models for SDK request/response types."""

from datetime import datetime
from typing import Any, Dict, List, Optional
from pydantic import BaseModel, Field


# --- Request Models ---

class RegisterAgentRequest(BaseModel):
    agent_id: str
    public_key: str = ""
    role: str = "DATA_PROVIDER"
    capabilities: List[str] = Field(default_factory=list)


class VerifyAgentRequest(BaseModel):
    agent_id: str
    agent_url: str = ""
    capabilities: List[str] = Field(default_factory=list)


class SubmitPayloadRequest(BaseModel):
    payload: Dict[str, Any]
    context: Dict[str, Any] = Field(default_factory=dict)
    source_agent_id: str = ""


class HandoffRequest(BaseModel):
    sender_id: str
    receiver_id: str
    payload: Dict[str, Any]


class StartSessionRequest(BaseModel):
    agent_id: str
    config: Dict[str, Any] = Field(default_factory=dict)


class RunAttacksRequest(BaseModel):
    attack_types: List[str] = Field(default_factory=list)


# --- Response Models ---

class TrustStatus(BaseModel):
    agent_id: str
    status: str
    trust_score: float
    verified_at: str = ""
    expires_at: str = ""
    proof_hash: str = ""
    checks: Dict[str, Any] = Field(default_factory=dict)
    risk_flags: List[str] = Field(default_factory=list)


class VerificationResult(BaseModel):
    verdict: str
    score: float
    proof_hash: str = ""
    submission_id: str = ""
    details: Dict[str, Any] = Field(default_factory=dict)


class SessionResult(BaseModel):
    id: str
    status: str
    agent_id: str
    config: Dict[str, Any] = Field(default_factory=dict)
    results_summary: Dict[str, Any] = Field(default_factory=dict)
    created_at: str = ""
    completed_at: Optional[str] = None


class AttackResult(BaseModel):
    attack_type: str
    passed: bool
    severity: str = "medium"
    details: Dict[str, Any] = Field(default_factory=dict)
    vulnerabilities: List[Dict[str, Any]] = Field(default_factory=list)
    duration_ms: int = 0


class TrustHistoryEntry(BaseModel):
    previous_score: float
    new_score: float
    delta: float
    reason: str
    event_type: str
    created_at: str = ""
