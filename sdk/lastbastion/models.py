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


class IssuePassportRequest(BaseModel):
    agent_id: str
    agent_name: str = ""
    public_key: str = ""
    company_name: str = ""
    company_domain: str = ""
    agent_card_url: str = ""
    geo_ip: str = ""
    geo_country: str = ""
    runtime_fingerprint: str = ""
    ip_allowlist: List[str] = Field(default_factory=list)


class VerifyPassportRequest(BaseModel):
    jwt_token: str


class RenewPassportRequest(BaseModel):
    agent_id: str


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


class PassportResponse(BaseModel):
    passport_id: str
    agent_id: str
    jwt_token: str
    trust_score: float
    trust_level: str
    verdict: str
    issued_at: str
    expires_at: str
    proof_hash: str = ""
    blockchain_tx: str = ""


class PassportVerifyResponse(BaseModel):
    valid: bool
    agent_id: str = ""
    trust_score: float = 0.0
    trust_level: str = ""
    expired: bool = False
    integrity: bool = False
    reasons: List[str] = Field(default_factory=list)


class GatewayDecision(BaseModel):
    allowed: bool
    agent_id: str = ""
    trust_score: float = 0.0
    trust_level: str = ""
    reason: str = ""
    cached: bool = False
    budget_remaining: int = -1    # -1 = not tracked (backward compat)
    budget_max: int = 100
    budget_exhausted: bool = False
    post_exhaustion_strikes: int = 0
    escalation_tier: int = 0           # 0=none, 1/2/3
