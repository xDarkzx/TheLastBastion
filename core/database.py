"""
The Last Bastion Unified Database Schema (v5.0)
Single source of truth. PostgreSQL only. No SQLite.
"""
import logging
import os
import json
import hashlib
from datetime import datetime, timedelta

logger = logging.getLogger("DATABASE")
from sqlalchemy import (
    create_engine, Column, Integer, String, JSON, DateTime,
    Text, Float, ForeignKey, Boolean
)
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker, relationship

Base = declarative_base()


# ---------------------------------------------------------------------------
# 1. MISSION & INTELLIGENCE LAYER
# ---------------------------------------------------------------------------

class Mission(Base):
    """The Industrial Objective (e.g., 'NZ Energy Price Map')."""
    __tablename__ = 'missions'
    id = Column(Integer, primary_key=True)
    parent_id = Column(Integer, ForeignKey('missions.id'), nullable=True)
    name = Column(String(255), nullable=False, index=True)
    category = Column(String(50), nullable=False, index=True)
    status = Column(String(50), default="ACTIVE")
    priority = Column(Integer, default=1)
    goal_logic = Column(Text)
    strategy = Column(Text, nullable=True)
    planning_data = Column(JSON, default=dict)
    learned_optimization = Column(JSON, nullable=True)
    config = Column(JSON, nullable=True)
    massive_status = Column(Text)
    complex_status = Column(Text)
    last_heartbeat = Column(DateTime)
    created_at = Column(DateTime, default=datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

    tasks = relationship("Task", backref="mission")
    sub_missions = relationship("Mission")


class Task(Base):
    """The Granular Work Unit (e.g., 'Extract Pricing Table')."""
    __tablename__ = 'tasks'
    id = Column(Integer, primary_key=True)
    mission_id = Column(Integer, ForeignKey('missions.id'), index=True)
    description = Column(Text, nullable=False)
    tool_type = Column(String(20), default="BROWSER")
    status = Column(String(20), default="PENDING")
    assigned_worker_id = Column(String(100), nullable=True)
    depends_on = Column(JSON, default=list)
    input_data = Column(JSON, default=dict)
    output_data = Column(JSON, default=dict)
    error_log = Column(Text, nullable=True)
    created_at = Column(DateTime, default=datetime.utcnow)


class IntelNode(Base):
    """A specific target for a mission (e.g., 'Mercury Energy' website)."""
    __tablename__ = 'intel_nodes'
    id = Column(Integer, primary_key=True)
    mission_id = Column(Integer, ForeignKey('missions.id'), index=True)
    name = Column(String(255), nullable=False, index=True)
    url = Column(String(1024), nullable=False)
    source_type = Column(String(20), default="WEB")
    status = Column(String(20), default="PENDING")
    last_yield_at = Column(DateTime)
    created_at = Column(DateTime, default=datetime.utcnow)


class GoldYield(Base):
    """Verified, high-value data extracted by the swarm."""
    __tablename__ = 'gold_yield'
    id = Column(Integer, primary_key=True)
    node_id = Column(Integer, ForeignKey('intel_nodes.id'), index=True)
    mission_id = Column(Integer, ForeignKey('missions.id'), index=True)
    company = Column(String(255), index=True)
    country = Column(String(100), index=True)
    region = Column(String(100), index=True)
    suburb = Column(String(100), index=True)
    payload = Column(JSON, nullable=False)
    raw_evidence = Column(Text)
    checksum = Column(String(64), index=True)
    timestamp = Column(DateTime, default=datetime.utcnow, index=True)


class KnowledgeYield(Base):
    """Semantic Memory: Generalized intelligence extracted by the swarm."""
    __tablename__ = 'knowledge_yield'
    id = Column(Integer, primary_key=True)
    mission_id = Column(Integer, ForeignKey('missions.id'), index=True)
    company = Column(String(255), index=True)
    country = Column(String(100), index=True)
    region = Column(String(100), index=True)
    suburb = Column(String(100), nullable=True, index=True)
    data_type = Column(String(100), index=True)
    fact_key = Column(String(100), index=True)
    fact_value = Column(Text)
    confidence = Column(Float, default=1.0)
    source_url = Column(String(1024))
    timestamp = Column(DateTime, default=datetime.utcnow, index=True)
    context_data = Column(JSON, default=dict)


# ---------------------------------------------------------------------------
# 2. SWARM FLEET LAYER
# ---------------------------------------------------------------------------

class SwarmDeployment(Base):
    """A collection of specialized bots working in a region."""
    __tablename__ = 'swarm_deployments'
    id = Column(Integer, primary_key=True)
    name = Column(String(255), nullable=False, unique=True)
    region = Column(String(50), default="NZ")
    category = Column(String(50), default="Energy")
    worker_count = Column(Integer, default=2)
    swarm_type = Column(String(50), default="DATA_SCRAPER")
    status = Column(String(20), default="ACTIVE")
    created_at = Column(DateTime, default=datetime.utcnow)


class RegionalProvider(Base):
    """Known entities discovered by the swarm."""
    __tablename__ = 'regional_providers'
    id = Column(Integer, primary_key=True)
    name = Column(String(255), nullable=False, index=True)
    category = Column(String(50), nullable=False, index=True)
    region = Column(String(50), default="NZ")
    base_url = Column(String(1024))
    status = Column(String(20), default="ACTIVE")
    created_at = Column(DateTime, default=datetime.utcnow)


class ProductionTask(Base):
    """Atomic jobs for the worker fleet (DB-backed queue — replaces Redis)."""
    __tablename__ = 'production_tasks'
    id = Column(Integer, primary_key=True)
    type = Column(String(50), nullable=False, index=True)
    payload = Column(JSON, nullable=False)
    status = Column(String(20), default="QUEUED", index=True)
    priority = Column(Integer, default=0)
    worker_id = Column(String(50), nullable=True, index=True)
    created_at = Column(DateTime, default=datetime.utcnow)


class PricingHistory(Base):
    """Time-series pricing data extracted from providers."""
    __tablename__ = 'pricing_history'
    id = Column(Integer, primary_key=True)
    provider_id = Column(Integer, ForeignKey('regional_providers.id'), index=True)
    data_points = Column(JSON, nullable=False)
    raw_content = Column(Text, nullable=True)
    timestamp = Column(DateTime, default=datetime.utcnow, index=True)


class ExtractionSchedule(Base):
    """Defines when a provider should be re-scraped."""
    __tablename__ = 'extraction_schedules'
    id = Column(Integer, primary_key=True)
    provider_id = Column(Integer, ForeignKey('regional_providers.id'))
    frequency_seconds = Column(Integer, default=86400)
    last_run = Column(DateTime)


# ---------------------------------------------------------------------------
# 3. WORKER REGISTRY & TELEMETRY
# ---------------------------------------------------------------------------

class AgentState(Base):
    """Fleet Observability: Real-time health of the swarm."""
    __tablename__ = 'agent_states'
    id = Column(Integer, primary_key=True)
    worker_id = Column(String(100), unique=True, index=True)
    status = Column(String(20), default="IDLE")
    capabilities = Column(JSON, default=list)
    current_mission_id = Column(Integer, ForeignKey('missions.id'), nullable=True)
    last_heard_at = Column(DateTime, default=datetime.utcnow)


class WorkerRegistry(Base):
    __tablename__ = 'worker_registry'
    id = Column(String(50), primary_key=True)
    status = Column(String(20), default="idle", index=True)
    current_mission_id = Column(Integer, ForeignKey('missions.id'), nullable=True)
    current_node_id = Column(Integer, ForeignKey('intel_nodes.id'), nullable=True)
    current_task = Column(String(255), nullable=True)
    swarm_id = Column(String(50), nullable=True)
    worker_type = Column(String(50), default="SUI_AGENT")
    config_overrides = Column(JSON, nullable=True)
    total_yields = Column(Integer, default=0)
    total_extractions = Column(Integer, default=0)
    last_heartbeat = Column(DateTime, default=datetime.utcnow)


class WorkerTelemetry(Base):
    __tablename__ = 'worker_telemetry'
    id = Column(Integer, primary_key=True)
    worker_id = Column(String(50), nullable=False, index=True)
    mission_id = Column(Integer, index=True)
    swarm_id = Column(String(50), index=True)
    trace_id = Column(String(16), nullable=True, index=True)  # UUID prefix for request tracing
    step_index = Column(Integer, nullable=True)  # Sequential step within a trace
    message = Column(Text, nullable=False)
    level = Column(String(20), default="info")
    timestamp = Column(DateTime, default=datetime.utcnow, index=True)


# Alias for code that imports SwarmTelemetry from the old vault module
SwarmTelemetry = WorkerTelemetry


class TacticalAdjustment(Base):
    """Records of autonomous tactical decisions made by the controller."""
    __tablename__ = 'tactical_adjustments'
    id = Column(Integer, primary_key=True)
    target_worker_id = Column(String(50), nullable=True)
    action = Column(String(50), nullable=False)
    reason = Column(Text)
    settings_applied = Column(JSON, nullable=True)
    created_at = Column(DateTime, default=datetime.utcnow)


class Interaction(Base):
    """Episodic Memory: Every thought and action (Journaling)."""
    __tablename__ = 'interactions'
    id = Column(Integer, primary_key=True)
    task_id = Column(Integer, ForeignKey('tasks.id'), nullable=True, index=True)
    mission_id = Column(Integer, ForeignKey('missions.id'), nullable=True, index=True)
    worker_id = Column(String(100), nullable=True)
    role = Column(String(20))
    message = Column(Text, nullable=True)
    tool_call = Column(JSON, nullable=True)
    tool_output = Column(Text, nullable=True)
    timestamp = Column(DateTime, default=datetime.utcnow)


class UsageMetrics(Base):
    """Tracks token consumption across LLM providers."""
    __tablename__ = 'usage_metrics'
    id = Column(Integer, primary_key=True)
    mission_id = Column(Integer, index=True)
    provider = Column(String(50), nullable=False)
    model = Column(String(100), nullable=False)
    prompt_tokens = Column(Integer, default=0)
    completion_tokens = Column(Integer, default=0)
    total_tokens = Column(Integer, default=0)
    estimated_cost = Column(Float, default=0.0)
    timestamp = Column(DateTime, default=datetime.utcnow, index=True)


class StrategicProcess(Base):
    """The Strategic Memory: Stores Mermaid diagrams and JSON maps."""
    __tablename__ = 'strategic_processes'
    id = Column(Integer, primary_key=True)
    name = Column(String(255), nullable=False)
    mermaid = Column(Text)
    strategic_map = Column(JSON)
    task_list = Column(JSON)
    source = Column(String(50))
    created_at = Column(DateTime, default=datetime.utcnow)


class EpisodicMemory(Base):
    """
    Episodic Memory: Records what happened during each mission.
    Used to recall past experiences when revisiting the same domain.
    Example: 'Last time on mercury.co.nz, cookie banner blocked step 3.'
    """
    __tablename__ = 'episodic_memory'
    id = Column(Integer, primary_key=True)
    mission_id = Column(Integer, ForeignKey('missions.id'), nullable=False, index=True)
    domain = Column(String(255), nullable=False, index=True)  # e.g. 'mercury.co.nz'
    goal = Column(Text, nullable=True)
    outcome = Column(String(30), nullable=False, index=True)  # SUCCESS, FAILED, TIMEOUT, STALLED
    action_history = Column(JSON, nullable=True)  # Full action log from the mission
    thought_log = Column(JSON, nullable=True)  # Brain's reasoning trace
    lessons_learned = Column(Text, nullable=True)  # LLM-generated summary of what to do differently
    total_iterations = Column(Integer, default=0)
    duration_seconds = Column(Float, nullable=True)
    trace_id = Column(String(16), nullable=True)
    created_at = Column(DateTime, default=datetime.utcnow, index=True)


# ---------------------------------------------------------------------------
# 5. REFINERY PIPELINE — Ingestion, Verification, Blockchain Stamps
# ---------------------------------------------------------------------------

class RawSubmission(Base):
    """
    Every piece of data entering the system gets a RawSubmission record.
    This is the audit trail — who submitted it, when, from where, and in what format.
    """
    __tablename__ = 'raw_submissions'
    id = Column(String(50), primary_key=True)           # e.g. "sub-abc12345"
    data_hash = Column(String(64), unique=True, index=True)
    source_agent_id = Column(String(100), index=True)
    submission_protocol = Column(String(50))            # m2m, api, upload, webhook
    source_url = Column(String(1024), nullable=True)
    format = Column(String(50))                         # pdf, json, csv, text, image/jpeg, etc.
    raw_size_bytes = Column(Integer, default=0)
    raw_bytes_path = Column(String(512), nullable=True) # path to stored raw file
    provenance = Column(JSON, default=dict)               # full provenance dict
    status = Column(String(20), default="ingested")     # ingested, extracted, failed
    is_duplicate = Column(Boolean, default=False)
    duplicate_of = Column(String(50), nullable=True)    # submission_id of original
    warnings = Column(JSON, default=list)
    created_at = Column(DateTime, default=datetime.utcnow, index=True)

    cleaned = relationship("CleanedData", back_populates="submission", uselist=False)
    verification = relationship("VerificationResult", back_populates="submission", uselist=False)


class CleanedData(Base):
    """
    Structured/extracted version of a RawSubmission.
    Populated after DocumentIntelligence runs field extraction.
    """
    __tablename__ = 'cleaned_data'
    id = Column(Integer, primary_key=True)
    submission_id = Column(String(50), ForeignKey('raw_submissions.id'), index=True)
    document_type = Column(String(100), nullable=True)  # invoice, receipt, energy_pricing, etc.
    structured_data = Column(JSON, nullable=False)
    schema = Column(JSON, default=dict)                   # inferred field schema
    confidence = Column(Float, default=0.0)             # extraction confidence 0.0–1.0
    warnings = Column(JSON, default=list)
    created_at = Column(DateTime, default=datetime.utcnow)

    submission = relationship("RawSubmission", back_populates="cleaned")


class VerificationResult(Base):
    """
    Records the outcome of running data through the 5-layer verification stack.
    One record per submission — the source of truth for verdicts.
    """
    __tablename__ = 'verification_results'
    id = Column(Integer, primary_key=True)
    submission_id = Column(String(50), ForeignKey('raw_submissions.id'), nullable=True, index=True)
    mission_id = Column(Integer, nullable=True, index=True)
    agent_id = Column(String(100), index=True)
    data_hash = Column(String(64), index=True)
    proof_hash = Column(String(64), unique=True, index=True)
    proof_record_id = Column(Integer, nullable=True)
    layer_scores = Column(JSON, default=dict)             # per-pillar score breakdown
    composite_score = Column(Float)
    verdict = Column(String(20), index=True)            # REJECTED, QUARANTINE, VERIFIED, GOLD
    action = Column(String(30))                         # store_verified, store_gold, quarantine, reject
    details = Column(JSON, default=dict)
    created_at = Column(DateTime, default=datetime.utcnow, index=True)

    submission = relationship("RawSubmission", back_populates="verification")
    quarantine = relationship("DataQuarantine", back_populates="verification_result", uselist=False)
    blockchain_stamp = relationship("BlockchainStamp", back_populates="verification_result", uselist=False)


class DataQuarantine(Base):
    """
    Holds data that scored 40–70 (uncertain) pending human review.
    Human reviewer can APPROVE (promote to VERIFIED) or REJECT (discard).
    Each decision feeds calibration.
    """
    __tablename__ = 'data_quarantine'
    id = Column(Integer, primary_key=True)
    submission_id = Column(String(50), ForeignKey('raw_submissions.id'), nullable=True, index=True)
    verification_result_id = Column(Integer, ForeignKey('verification_results.id'), index=True)
    data_hash = Column(String(64), index=True)
    reason = Column(Text)
    score = Column(Float)
    resolution_status = Column(String(20), default="PENDING")  # PENDING, APPROVED, REJECTED
    resolved_by = Column(String(100), nullable=True)
    resolved_at = Column(DateTime, nullable=True)
    created_at = Column(DateTime, default=datetime.utcnow, index=True)

    verification_result = relationship("VerificationResult", back_populates="quarantine")


class BlockchainStamp(Base):
    """
    On-chain anchoring record — proof that a verification happened and when.
    Created after a VERIFIED or GOLD verdict is anchored to the blockchain.
    """
    __tablename__ = 'blockchain_stamps'
    id = Column(Integer, primary_key=True)
    submission_id = Column(String(50), ForeignKey('raw_submissions.id'), nullable=True, index=True)
    verification_result_id = Column(Integer, ForeignKey('verification_results.id'), nullable=True, index=True)
    data_hash = Column(String(64), index=True)
    proof_hash = Column(String(64), index=True)
    tx_hash = Column(String(66), nullable=True, index=True)
    chain = Column(String(50), default="polygon")
    block_number = Column(Integer, nullable=True)
    confidence = Column(Float)
    verdict = Column(String(20))
    anchor_approved = Column(Boolean, default=False, index=True)
    anchor_approved_by = Column(String(100), nullable=True)
    anchor_approved_at = Column(DateTime, nullable=True)
    created_at = Column(DateTime, default=datetime.utcnow, index=True)

    verification_result = relationship("VerificationResult", back_populates="blockchain_stamp")


class M2MTask(Base):
    """
    M2M task submitted via /m2m/submit.
    Persists task state so it survives restarts.
    """
    __tablename__ = 'm2m_tasks'
    task_id = Column(String(50), primary_key=True)
    agent_id = Column(String(100), nullable=False, index=True)
    service_id = Column(String(100), nullable=False, index=True)
    quote_id = Column(String(100), nullable=True)
    payload = Column(JSON, default=dict)
    target_url = Column(String(1024), nullable=True)
    context = Column(JSON, default=dict)
    status = Column(String(20), default="queued", index=True)  # queued, running, completed, failed
    result = Column(JSON, nullable=True)
    created_at = Column(DateTime, default=datetime.utcnow, index=True)
    completed_at = Column(DateTime, nullable=True)


class AgentVerification(Base):
    """
    Agent trust verification record.
    When an external agent submits itself for verification, we run checks
    on its identity, capabilities, and behavior history.
    The verdict is stamped on-chain so other bots can look up trust status.
    """
    __tablename__ = 'agent_verifications'
    id = Column(Integer, primary_key=True)
    agent_id = Column(String(100), nullable=False, index=True)
    agent_name = Column(String(255), nullable=True)
    agent_url = Column(String(1024), nullable=True)
    public_key = Column(Text, nullable=True)
    capabilities = Column(JSON, default=list)
    agent_metadata = Column(JSON, default=dict)
    # Verification results
    verdict = Column(String(20), default="PENDING", index=True)  # PENDING, TRUSTED, SUSPICIOUS, MALICIOUS
    trust_score = Column(Float, default=0.0)
    checks_passed = Column(JSON, default=dict)   # {check_name: {passed: bool, score: float, detail: str}}
    risk_flags = Column(JSON, default=list)
    # Blockchain anchoring
    proof_hash = Column(String(64), nullable=True, index=True)
    tx_hash = Column(String(66), nullable=True)
    chain = Column(String(50), default="polygon")
    passport_fingerprint = Column(String(64), nullable=True)
    # Timestamps
    submitted_at = Column(DateTime, default=datetime.utcnow, index=True)
    verified_at = Column(DateTime, nullable=True)
    expires_at = Column(DateTime, nullable=True)


class HandoffTransaction(Base):
    """
    Records an A2A handoff between two agents.
    Tracks the full lifecycle: request → passport check → payload verification → accept/reject.
    """
    __tablename__ = 'handoff_transactions'
    id = Column(String(50), primary_key=True)  # "hoff-{uuid}"
    sender_id = Column(String(100), nullable=False, index=True)
    receiver_id = Column(String(100), nullable=False, index=True)
    payload_hash = Column(String(64), nullable=True)
    payload_summary = Column(Text, nullable=True)
    sender_verified = Column(Boolean, default=False)
    sender_trust_score = Column(Float, default=0.0)
    payload_verdict = Column(String(20), nullable=True)   # REJECTED, QUARANTINE, VERIFIED, GOLD
    payload_score = Column(Float, nullable=True)
    status = Column(String(20), default="PENDING", index=True)  # PENDING, ACCEPTED, REJECTED, REDIRECT
    proof_hash = Column(String(64), nullable=True)
    tx_hash = Column(String(66), nullable=True)
    reason = Column(Text, nullable=True)
    created_at = Column(DateTime, default=datetime.utcnow, index=True)
    completed_at = Column(DateTime, nullable=True)


class RegistrationChallenge(Base):
    """Challenge-response record for agent registration."""
    __tablename__ = 'registration_challenges'
    id = Column(String(50), primary_key=True)          # "reg-{uuid}"
    agent_id = Column(String(100), nullable=False, index=True)
    nonce = Column(String(64), nullable=False)
    public_key = Column(Text, nullable=False)
    role = Column(String(50), default="DATA_CONSUMER")
    display_name = Column(String(255), default="")
    capabilities = Column(JSON, default=list)
    status = Column(String(20), default="PENDING", index=True)  # PENDING/COMPLETED/EXPIRED
    expires_at = Column(DateTime, nullable=False)
    created_at = Column(DateTime, default=datetime.utcnow)


class AgentPassportRecord(Base):
    """DB record of an issued Agent Passport."""
    __tablename__ = 'agent_passports'
    id = Column(Integer, primary_key=True)
    passport_id = Column(String(50), unique=True, nullable=False, index=True)
    agent_id = Column(String(100), nullable=False, index=True)
    jwt_token = Column(Text, nullable=False)
    crypto_hash = Column(String(64), nullable=True)
    trust_score = Column(Float, default=0.0)
    verdict = Column(String(20), default="TRUSTED")
    proof_hash = Column(String(64), nullable=True)
    tx_hash = Column(String(66), nullable=True)
    interaction_budget = Column(Integer, default=100)
    interaction_budget_max = Column(Integer, default=100)
    budget_exhausted_at = Column(DateTime, nullable=True)
    budget_refreshed_count = Column(Integer, default=0)
    last_budget_sync = Column(DateTime, nullable=True)
    issued_at = Column(DateTime, default=datetime.utcnow)
    expires_at = Column(DateTime, nullable=True)
    revoked = Column(Boolean, default=False, index=True)
    post_exhaustion_strikes = Column(Integer, default=0)
    escalation_tier = Column(Integer, default=0)       # 0=none, 1, 2, 3
    escalation_locked_at = Column(DateTime, nullable=True)


# Escalation tier thresholds
STRIKE_TIER_1 = 5
STRIKE_TIER_2 = 15
STRIKE_TIER_3 = 30


class AgentAppeal(Base):
    """Formal appeal against escalation lockout."""
    __tablename__ = 'agent_appeals'
    id = Column(Integer, primary_key=True)
    appeal_id = Column(String(50), unique=True, nullable=False, index=True)
    agent_id = Column(String(100), nullable=False, index=True)
    org_id = Column(String(50), nullable=True, index=True)
    filing_api_key_id = Column(String(100), nullable=True)
    reason = Column(Text, nullable=True)
    evidence = Column(Text, nullable=True)
    escalation_tier = Column(Integer, default=0)
    strikes_at_filing = Column(Integer, default=0)
    trust_score_at_filing = Column(Float, default=0.0)
    verdict_at_filing = Column(String(20), nullable=True)
    status = Column(String(20), default="PENDING", index=True)  # PENDING, APPROVED, DENIED
    filed_at = Column(DateTime, default=datetime.utcnow)
    resolved_at = Column(DateTime, nullable=True)
    resolved_by = Column(String(100), nullable=True)
    resolution_notes = Column(Text, nullable=True)
    trust_score_restored_to = Column(Float, nullable=True)
    passport_renewed = Column(Boolean, default=False)


class AgentReport(Base):
    """Peer report against an agent."""
    __tablename__ = 'agent_reports'
    id = Column(Integer, primary_key=True)
    reporter_id = Column(String(100), nullable=False, index=True)
    target_id = Column(String(100), nullable=False, index=True)
    reason = Column(String(50), nullable=False)   # spam, malicious_data, impersonation, sybil, other
    evidence = Column(Text, nullable=True)
    status = Column(String(20), default="OPEN", index=True)  # OPEN, REVIEWED, DISMISSED
    created_at = Column(DateTime, default=datetime.utcnow, index=True)


class MissionPlaybook(Base):
    """
    MissionPlaybook: Reusable extraction recipe for a target domain.

    Supports three extraction modes:
      - BROWSER: Headless navigation via NodriverDriver/Playwright
      - API: Direct HTTP calls to REST/GraphQL/JSON endpoints (no browser)
      - HYBRID: Browser discovers data, then switches to direct API calls
    
    Playbooks guide the agent but don't hard-code paths. The LLM uses
    workflow_steps and navigation_hints as context but adapts autonomously.
    Auto-generated from successful missions when no playbook exists.
    """
    __tablename__ = 'mission_playbooks'

    id = Column(Integer, primary_key=True)
    name = Column(String(255), nullable=False)
    domain = Column(String(255), nullable=False, index=True)
    version = Column(Integer, default=1)
    category = Column(String(50), index=True)  # energy, finance, gov, health, etc.

    # Extraction mode
    extraction_mode = Column(String(20), default="BROWSER")  # BROWSER | API | HYBRID

    # WHAT to extract
    goal = Column(Text, nullable=False)
    output_schema = Column(JSON, nullable=False)  # {"plan_name": "str", "price": "float"}

    # HOW to get there (browser mode)
    entry_url = Column(String(1024), nullable=False)
    workflow_steps = Column(JSON, default=list)     # ordered steps for navigation
    known_obstacles = Column(JSON, default=list)    # [{type, selector, action}]
    navigation_hints = Column(JSON, default=list)   # free-text hints for LLM

    # API mode config
    extraction_config = Column(JSON, default=dict)
    # Structure for API mode:
    # {
    #   "endpoints": [
    #     {
    #       "url": "https://api.example.com/v1/prices",
    #       "method": "GET",
    #       "headers": {"Authorization": "Bearer ..."},
    #       "params": {"region": "auckland"},
    #       "response_path": "data.prices",  # jmespath to extract
    #       "pagination": {"type": "offset", "param": "page", "max_pages": 5}
    #     }
    #   ],
    #   "auth": {"type": "bearer", "token_env": "EXAMPLE_API_KEY"},
    #   "rate_limit": {"requests_per_second": 2}
    # }

    # HEALTH tracking
    success_rate = Column(Float, default=0.0)
    total_runs = Column(Integer, default=0)
    total_successes = Column(Integer, default=0)
    last_validated_at = Column(DateTime, nullable=True)
    stale_after_days = Column(Integer, default=30)

    # SCHEDULING
    priority = Column(Integer, default=5)               # 1=low, 10=critical
    schedule_cron = Column(String(50), nullable=True)   # "0 6 * * 1"

    # STATE
    is_active = Column(Boolean, default=True)
    created_by = Column(String(50), default="manual")   # manual | auto_generated | evolved

    created_at = Column(DateTime, default=datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

# ---------------------------------------------------------------------------
# 7. SANDBOX MODELS
# ---------------------------------------------------------------------------

class SandboxOrganization(Base):
    """Tenant/org registration for the sandbox."""
    __tablename__ = 'sandbox_organizations'
    id = Column(String(50), primary_key=True)  # "org-{uuid}"
    name = Column(String(255), nullable=False)
    email = Column(String(255), nullable=False, unique=True, index=True)
    tier = Column(String(20), default="free")  # free, pro
    max_agents = Column(Integer, default=5)
    max_sandbox_runs = Column(Integer, default=100)
    sandbox_runs_used = Column(Integer, default=0)
    is_active = Column(Boolean, default=True)
    created_at = Column(DateTime, default=datetime.utcnow)

    api_keys = relationship("PersistentAPIKey", back_populates="organization")
    sessions = relationship("SandboxSession", back_populates="organization")


class PersistentAPIKey(Base):
    """DB-backed API key that survives restarts."""
    __tablename__ = 'persistent_api_keys'
    key_id = Column(String(100), primary_key=True)  # "sandbox_sk_xxx" or "live_sk_xxx"
    key_hash = Column(String(64), nullable=False)     # SHA-256 of secret
    agent_id = Column(String(100), nullable=False, index=True)
    org_id = Column(String(50), ForeignKey('sandbox_organizations.id'), nullable=True, index=True)
    environment = Column(String(20), default="sandbox")  # sandbox, production
    permissions = Column(JSON, default=list)
    rate_limit_per_minute = Column(Integer, default=60)
    is_active = Column(Boolean, default=True)
    expires_at = Column(DateTime, nullable=True)
    last_used_at = Column(DateTime, nullable=True)
    created_at = Column(DateTime, default=datetime.utcnow)

    organization = relationship("SandboxOrganization", back_populates="api_keys")


class SandboxSession(Base):
    """Tracks a sandbox test run."""
    __tablename__ = 'sandbox_sessions'
    id = Column(String(50), primary_key=True)  # "sess-{uuid}"
    org_id = Column(String(50), ForeignKey('sandbox_organizations.id'), nullable=False, index=True)
    agent_id = Column(String(100), nullable=False, index=True)
    status = Column(String(20), default="active", index=True)  # active, completed, expired
    config = Column(JSON, default=dict)          # attack types, timeout, etc.
    results_summary = Column(JSON, default=dict)
    created_at = Column(DateTime, default=datetime.utcnow)
    completed_at = Column(DateTime, nullable=True)
    expires_at = Column(DateTime, nullable=True)

    organization = relationship("SandboxOrganization", back_populates="sessions")
    attack_results = relationship("SandboxAttackResult", back_populates="session")


class TrustScoreHistory(Base):
    """Audit trail for trust score changes."""
    __tablename__ = 'trust_score_history'
    id = Column(Integer, primary_key=True)
    agent_id = Column(String(100), nullable=False, index=True)
    previous_score = Column(Float, default=0.0)
    new_score = Column(Float, default=0.0)
    delta = Column(Float, default=0.0)
    reason = Column(Text, nullable=True)
    event_type = Column(String(50), nullable=False)  # verification, attack_test, manual
    session_id = Column(String(50), nullable=True, index=True)
    created_at = Column(DateTime, default=datetime.utcnow, index=True)


class SandboxAttackResult(Base):
    """Result of a single attack simulation run."""
    __tablename__ = 'sandbox_attack_results'
    id = Column(Integer, primary_key=True)
    session_id = Column(String(50), ForeignKey('sandbox_sessions.id'), nullable=False, index=True)
    agent_id = Column(String(100), nullable=False, index=True)
    attack_type = Column(String(50), nullable=False, index=True)
    passed = Column(Boolean, default=False)
    severity = Column(String(20), default="medium")  # low, medium, high, critical
    details = Column(JSON, default=dict)
    vulnerabilities = Column(JSON, default=list)
    duration_ms = Column(Integer, default=0)
    created_at = Column(DateTime, default=datetime.utcnow)

    session = relationship("SandboxSession", back_populates="attack_results")


# ---------------------------------------------------------------------------
# 10. CART — Vulnerability & Countermeasure Tracking
# ---------------------------------------------------------------------------

class Vulnerability(Base):
    """A verified security vulnerability discovered by the Think Tank CART."""
    __tablename__ = 'vulnerabilities'
    id = Column(Integer, primary_key=True)
    vuln_id = Column(String(50), unique=True, nullable=False, index=True)
    round_number = Column(Integer, nullable=False, index=True)
    threat_category = Column(String(100), nullable=False, index=True)
    threat_class = Column(String(50), nullable=False, index=True)
    attack_payload = Column(JSON, default=dict)
    attack_description = Column(Text, default="")
    layers_bypassed = Column(JSON, default=list)
    layers_caught = Column(JSON, default=list)
    full_stack_result = Column(JSON, default=dict)
    severity_score = Column(Float, default=0.0)
    severity_label = Column(String(20), default="LOW", index=True)
    exploitability = Column(Float, default=0.0)
    impact = Column(Float, default=0.0)
    countermeasure_id = Column(Integer, ForeignKey('countermeasures.id'), nullable=True)
    status = Column(String(30), default="OPEN", index=True)
    mitigated_at = Column(DateTime, nullable=True)
    created_at = Column(DateTime, default=datetime.utcnow, index=True)

    countermeasure = relationship("Countermeasure", back_populates="vulnerabilities", foreign_keys=[countermeasure_id])


class Countermeasure(Base):
    """An auto-deployed defense against a discovered vulnerability."""
    __tablename__ = 'countermeasures'
    id = Column(Integer, primary_key=True)
    cm_id = Column(String(50), unique=True, nullable=False, index=True)
    pattern_type = Column(String(20), default="regex")  # regex, rule, weight
    pattern_value = Column(Text, nullable=False)
    target_layer = Column(String(50), default="schema_gatekeeper")
    description = Column(Text, default="")
    true_positives = Column(Integer, default=0)
    false_positives = Column(Integer, default=0)
    true_negatives = Column(Integer, default=0)
    false_negatives = Column(Integer, default=0)
    status = Column(String(20), default="PROPOSED", index=True)
    deployed_at = Column(DateTime, nullable=True)
    reverted_at = Column(DateTime, nullable=True)
    created_at = Column(DateTime, default=datetime.utcnow, index=True)

    vulnerabilities = relationship("Vulnerability", back_populates="countermeasure", foreign_keys=[Vulnerability.countermeasure_id])


class DashboardAgent(Base):
    """
    Persistent record of agents registered via the dashboard.
    Previously only lived in the in-memory _dashboard_agents list.
    Now survives server restarts.
    """
    __tablename__ = 'dashboard_agents'
    id = Column(Integer, primary_key=True)
    agent_id = Column(String(100), unique=True, nullable=False, index=True)
    name = Column(String(255), nullable=False)
    url = Column(String(1024), default="")
    port = Column(Integer, default=0)
    role = Column(String(100), default="supply_chain")
    skills = Column(JSON, default=list)
    version = Column(String(50), default="1.0")
    status = Column(String(50), default="online")
    description = Column(Text, default="")
    reputation_score = Column(Float, default=1.0)
    registered_at = Column(DateTime, default=datetime.utcnow)
    last_seen = Column(DateTime, default=datetime.utcnow)


# ---------------------------------------------------------------------------
# ENGINE — PostgreSQL Only
# ---------------------------------------------------------------------------

DATABASE_URL = os.getenv(
    "DATABASE_URL",
    "postgresql://industrial_admin:swarm_secret_2026@127.0.0.1:5432/registry_base_vault"
)
if DATABASE_URL.startswith("postgres://"):
    DATABASE_URL = DATABASE_URL.replace("postgres://", "postgresql+psycopg2://")

engine = create_engine(
    DATABASE_URL,
    pool_pre_ping=True,
    pool_size=10,
    max_overflow=20,
    pool_timeout=30,
    pool_recycle=3600,
)
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)


# ---------------------------------------------------------------------------
# UTILITY FUNCTIONS
# ---------------------------------------------------------------------------

def _migrate_missing_columns():
    """Add columns that were added to models after initial table creation.

    Compares each model's columns against the live DB and ALTERs in any missing ones.
    Safe to run repeatedly — only adds columns that don't exist yet.
    """
    from sqlalchemy import text, inspect as sa_inspect
    try:
        insp = sa_inspect(engine)
        existing_tables = set(insp.get_table_names())

        # Map of table -> list of (column_name, SQL type default)
        migrations = {
            "blockchain_stamps": [
                ("anchor_approved", "BOOLEAN DEFAULT FALSE"),
                ("anchor_approved_by", "VARCHAR(100)"),
                ("anchor_approved_at", "TIMESTAMP"),
            ],
            "agent_verifications": [
                ("passport_fingerprint", "VARCHAR(64)"),
            ],
        }

        with engine.begin() as conn:
            for table, columns in migrations.items():
                if table not in existing_tables:
                    continue
                existing_cols = {c["name"] for c in insp.get_columns(table)}
                for col_name, col_type in columns:
                    if col_name not in existing_cols:
                        conn.execute(text(f"ALTER TABLE {table} ADD COLUMN {col_name} {col_type}"))
                        logger.info(f"Schema migration: added {table}.{col_name}")

        logger.info("Schema migration check complete.")
    except Exception as e:
        logger.warning(f"Schema migration check skipped: {e}")


def init_db():
    """Creates all tables in PostgreSQL."""
    Base.metadata.create_all(bind=engine)
    _migrate_missing_columns()
    logger.info("Unified PostgreSQL schema initialized.")


# Alias used by vault.core imports
init_vault = init_db


def save_process(name: str, mermaid: str, strategic_map: dict, task_list: list, source: str = "direct"):
    """Saves a strategic process map for later recall."""
    db = SessionLocal()
    try:
        new_p = StrategicProcess(
            name=name, mermaid=mermaid,
            strategic_map=strategic_map, task_list=task_list, source=source
        )
        db.add(new_p)
        db.commit()
    finally:
        db.close()


def get_all_processes():
    """Retrieves all strategic maps."""
    db = SessionLocal()
    try:
        return db.query(StrategicProcess).all()
    finally:
        db.close()


def log_telemetry(worker_id: str, message: str, level: str = "info",
                  mission_id: int = None, swarm_id: str = None,
                  trace_id: str = None, step_index: int = None):
    """Universal Telemetry: Logs activity to the Industrial Pulse with optional trace context."""
    db = SessionLocal()
    try:
        log = WorkerTelemetry(
            worker_id=worker_id, message=message, level=level,
            mission_id=mission_id, swarm_id=swarm_id,
            trace_id=trace_id, step_index=step_index
        )
        db.add(log)
        db.commit()
    finally:
        db.close()


def update_worker_status(worker_id: str, status: str, current_task: str = None,
                         worker_type: str = "SUI_AGENT", swarm_id: str = None):
    """Atomic Worker Heartbeat."""
    db = SessionLocal()
    try:
        worker = db.query(WorkerRegistry).filter(WorkerRegistry.id == worker_id).first()
        if not worker:
            worker = WorkerRegistry(
                id=worker_id, status=status,
                worker_type=worker_type, swarm_id=swarm_id
            )
            db.add(worker)
        worker.status = status
        worker.last_heartbeat = datetime.utcnow()
        if current_task:
            worker.current_task = current_task
        db.commit()
    finally:
        db.close()


def get_system_stats():
    """Aggregated Industrial Metrics."""
    db = SessionLocal()
    try:
        return {
            "total_workers": db.query(WorkerRegistry).count(),
            "active_workers": db.query(WorkerRegistry).filter(
                WorkerRegistry.status != "offline"
            ).count(),
            "total_providers": db.query(RegionalProvider).count(),
            "total_data_points": db.query(PricingHistory).count(),
            "pending_tasks": db.query(ProductionTask).filter(
                ProductionTask.status == "QUEUED"
            ).count(),
            "last_heartbeat": datetime.utcnow().isoformat()
        }
    finally:
        db.close()


def claim_next_task(worker_id: str, task_types: list):
    """Atomic Claim: Uses SELECT FOR UPDATE SKIP LOCKED to prevent double-claiming."""
    db = SessionLocal()
    try:
        task = db.query(ProductionTask).filter(
            ProductionTask.status == "QUEUED",
            ProductionTask.type.in_(task_types)
        ).order_by(
            ProductionTask.priority.desc(),
            ProductionTask.created_at.asc()
        ).with_for_update(skip_locked=True).first()

        if task:
            task.status = "CLAIMED"
            task.worker_id = worker_id
            db.commit()
            db.refresh(task)
            return task
        return None
    finally:
        db.close()


def complete_task(task_id: int):
    """Marks a production job as finished."""
    db = SessionLocal()
    try:
        task = db.query(ProductionTask).filter(ProductionTask.id == task_id).first()
        if task:
            task.status = "COMPLETE"
            db.commit()
    finally:
        db.close()


def save_pricing_data(provider_id: int, data_points: dict, raw_content: str = ""):
    """Archives extracted pricing data to the time-series history."""
    db = SessionLocal()
    try:
        entry = PricingHistory(
            provider_id=provider_id,
            data_points=data_points,
            raw_content=raw_content
        )
        db.add(entry)
        db.commit()
        logger.info("Pricing data saved for provider %s", provider_id)
    finally:
        db.close()


def verify_yield_integrity(mission_id: int, payload: dict) -> bool:
    """
    Industrial-grade truth verification.
    Validates that extracted gold contains real, structured data
    and not just metadata or placeholder values.
    """
    if not payload or len(payload) == 0:
        logger.warning("REJECTED - Empty payload.")
        return False

    # Must have at least one data key beyond internal metadata
    data_keys = {k for k in payload.keys() if not k.startswith("_")}
    metadata_only = {"status", "confidence_score", "source_summary"}
    real_keys = data_keys - metadata_only
    if not real_keys:
        logger.warning("REJECTED - Payload contains only metadata, no real data.")
        return False

    # Check for placeholder/garbage values
    placeholder_patterns = [
        "not found", "n/a", "undefined", "null", "none",
        "example", "test", "placeholder", "lorem"
    ]
    for key, value in payload.items():
        if key.startswith("_"):
            continue
        if isinstance(value, str) and value.strip().lower() in placeholder_patterns:
            logger.warning("REJECTED - Placeholder value detected: %s='%s'", key, value)
            return False

    return True


def commit_gold_yield(node_id: int, payload: dict, evidence: str = "",
                      mission_id: int = None):
    """Commits verified 'Liquid Gold' to the database."""
    db = SessionLocal()
    try:
        checksum = hashlib.sha256(
            json.dumps(payload, sort_keys=True).encode()
        ).hexdigest()

        yield_entry = GoldYield(
            node_id=node_id,
            mission_id=mission_id,
            payload=payload,
            raw_evidence=evidence,
            checksum=checksum
        )
        db.add(yield_entry)
        db.commit()
        logger.info("Gold Yield committed for Node %s", node_id)
    finally:
        db.close()


def record_usage(mission_id: int, provider: str, model: str,
                 prompt_tokens: int, completion_tokens: int):
    """Records token consumption for cost observability."""
    db = SessionLocal()
    try:
        usage = UsageMetrics(
            mission_id=mission_id,
            provider=provider,
            model=model,
            prompt_tokens=prompt_tokens,
            completion_tokens=completion_tokens,
            total_tokens=prompt_tokens + completion_tokens
        )
        db.add(usage)
        db.commit()
    except Exception as e:
        logger.error("Usage tracking failure: %s", e)
    finally:
        db.close()


# ---------------------------------------------------------------------------
# REFINERY HELPERS
# ---------------------------------------------------------------------------

def save_raw_submission(
    submission_id: str,
    data_hash: str,
    source_agent_id: str,
    submission_protocol: str,
    format: str,
    raw_size_bytes: int,
    provenance: dict,
    status: str = "ingested",
    is_duplicate: bool = False,
    duplicate_of: str = "",
    warnings: list = None,
    source_url: str = "",
    raw_bytes_path: str = "",
) -> "RawSubmission":
    """Persists an ingestion record to raw_submissions table."""
    db = SessionLocal()
    try:
        # Check if already exists (duplicate submission_id or data_hash is a no-op)
        existing = db.query(RawSubmission).filter(
            RawSubmission.id == submission_id
        ).first()
        if existing:
            return existing
        existing_hash = db.query(RawSubmission).filter(
            RawSubmission.data_hash == data_hash
        ).first()
        if existing_hash:
            return existing_hash

        record = RawSubmission(
            id=submission_id,
            data_hash=data_hash,
            source_agent_id=source_agent_id,
            submission_protocol=submission_protocol,
            source_url=source_url or "",
            format=format,
            raw_size_bytes=raw_size_bytes,
            raw_bytes_path=raw_bytes_path or "",
            provenance=provenance,
            status=status,
            is_duplicate=is_duplicate,
            duplicate_of=duplicate_of or None,
            warnings=warnings or [],
        )
        db.add(record)
        db.commit()
        db.refresh(record)
        logger.info("RawSubmission %s saved (hash=%s...)", submission_id, data_hash[:16])
        return record
    except Exception as e:
        db.rollback()
        logger.error("RawSubmission save failed: %s", e)
        raise
    finally:
        db.close()


def save_cleaned_data(
    submission_id: str,
    structured_data: dict,
    confidence: float,
    document_type: str = "",
    schema: dict = None,
    warnings: list = None,
) -> "CleanedData":
    """Persists extracted/cleaned data for a submission."""
    db = SessionLocal()
    try:
        record = CleanedData(
            submission_id=submission_id,
            document_type=document_type or "",
            structured_data=structured_data,
            schema=schema or {},
            confidence=confidence,
            warnings=warnings or [],
        )
        db.add(record)
        # Update parent submission status
        sub = db.query(RawSubmission).filter(
            RawSubmission.id == submission_id
        ).first()
        if sub:
            sub.status = "extracted"
        db.commit()
        db.refresh(record)
        return record
    except Exception as e:
        db.rollback()
        logger.error("CleanedData save failed: %s", e)
        raise
    finally:
        db.close()


def save_verification_result(
    data_hash: str,
    proof_hash: str,
    verdict: str,
    composite_score: float,
    action: str,
    agent_id: str = "",
    mission_id: int = None,
    submission_id: str = None,
    proof_record_id: int = None,
    layer_scores: dict = None,
    details: dict = None,
) -> "VerificationResult":
    """Persists a verification verdict to the database."""
    db = SessionLocal()
    try:
        # Idempotent — proof_hash is unique
        existing = db.query(VerificationResult).filter(
            VerificationResult.proof_hash == proof_hash
        ).first()
        if existing:
            return existing

        record = VerificationResult(
            submission_id=submission_id,
            mission_id=mission_id,
            agent_id=agent_id or "",
            data_hash=data_hash,
            proof_hash=proof_hash,
            proof_record_id=proof_record_id,
            layer_scores=layer_scores or {},
            composite_score=composite_score,
            verdict=verdict,
            action=action,
            details=details or {},
        )
        db.add(record)
        db.commit()
        db.refresh(record)
        logger.info(
            "VerificationResult saved — %s (score=%.4f, proof=%s...)",
            verdict, composite_score, proof_hash[:16]
        )
        return record
    except Exception as e:
        db.rollback()
        logger.error("VerificationResult save failed: %s", e)
        raise
    finally:
        db.close()


def save_quarantine(
    verification_result_id: int,
    data_hash: str,
    reason: str,
    score: float,
    submission_id: str = None,
) -> "DataQuarantine":
    """Adds a submission to the quarantine queue for human review."""
    db = SessionLocal()
    try:
        record = DataQuarantine(
            submission_id=submission_id,
            verification_result_id=verification_result_id,
            data_hash=data_hash,
            reason=reason,
            score=score,
            resolution_status="PENDING",
        )
        db.add(record)
        db.commit()
        db.refresh(record)
        logger.info("DataQuarantine entry created for hash=%s...", data_hash[:16])
        return record
    except Exception as e:
        db.rollback()
        logger.error("DataQuarantine save failed: %s", e)
        raise
    finally:
        db.close()


def save_blockchain_stamp(
    proof_hash: str,
    data_hash: str,
    verdict: str,
    confidence: float,
    verification_result_id: int = None,
    submission_id: str = None,
    tx_hash: str = "",
    chain: str = "polygon",
    block_number: int = None,
) -> "BlockchainStamp":
    """Records a blockchain anchoring event."""
    db = SessionLocal()
    try:
        record = BlockchainStamp(
            submission_id=submission_id,
            verification_result_id=verification_result_id,
            data_hash=data_hash,
            proof_hash=proof_hash,
            tx_hash=tx_hash or None,
            chain=chain,
            block_number=block_number,
            confidence=confidence,
            verdict=verdict,
        )
        db.add(record)
        db.commit()
        db.refresh(record)
        logger.info(
            "BlockchainStamp saved — tx=%s...",
            tx_hash[:16] if tx_hash else "pending"
        )
        return record
    except Exception as e:
        db.rollback()
        logger.error("BlockchainStamp save failed: %s", e)
        raise
    finally:
        db.close()


def get_pending_anchors(limit: int = 50) -> list:
    """Returns BlockchainStamp records awaiting human approval for on-chain anchoring."""
    db = SessionLocal()
    try:
        items = db.query(BlockchainStamp).filter(
            BlockchainStamp.anchor_approved == False,
            BlockchainStamp.tx_hash.is_(None),
        ).order_by(BlockchainStamp.created_at.desc()).limit(limit).all()
        results = []
        for item in items:
            results.append({
                "id": item.id,
                "proof_hash": item.proof_hash,
                "data_hash": item.data_hash,
                "verdict": item.verdict,
                "confidence": item.confidence,
                "chain": item.chain,
                "created_at": item.created_at.isoformat() if item.created_at else None,
                "submission_id": item.submission_id,
                "verification_result_id": item.verification_result_id,
            })
        return results
    except Exception as e:
        logger.error("get_pending_anchors failed: %s", e)
        return []
    finally:
        db.close()


def approve_anchor(stamp_id: int, approved_by: str = "human") -> dict:
    """
    Marks a BlockchainStamp as human-approved for on-chain anchoring.
    Returns the stamp details needed to perform the actual anchor transaction.
    """
    db = SessionLocal()
    try:
        item = db.query(BlockchainStamp).filter(
            BlockchainStamp.id == stamp_id
        ).first()
        if not item:
            return {"error": "not_found"}
        if item.anchor_approved:
            return {"error": "already_approved", "tx_hash": item.tx_hash}

        item.anchor_approved = True
        item.anchor_approved_by = approved_by
        item.anchor_approved_at = datetime.utcnow()
        db.commit()
        logger.info("Anchor %s approved by %s", stamp_id, approved_by)
        return {
            "id": item.id,
            "proof_hash": item.proof_hash,
            "data_hash": item.data_hash,
            "verdict": item.verdict,
            "confidence": item.confidence,
            "approved": True,
        }
    except Exception as e:
        db.rollback()
        logger.error("approve_anchor failed: %s", e)
        return {"error": str(e)}
    finally:
        db.close()


def update_anchor_tx(stamp_id: int, tx_hash: str, block_number: int = None) -> bool:
    """Updates a BlockchainStamp with the actual on-chain transaction hash after anchoring."""
    db = SessionLocal()
    try:
        item = db.query(BlockchainStamp).filter(
            BlockchainStamp.id == stamp_id
        ).first()
        if not item:
            return False
        item.tx_hash = tx_hash
        if block_number:
            item.block_number = block_number
        db.commit()
        logger.info("Anchor %s tx_hash updated: %s...", stamp_id, tx_hash[:16])
        return True
    except Exception as e:
        db.rollback()
        logger.error("update_anchor_tx failed: %s", e)
        return False
    finally:
        db.close()


def get_verification_by_hash(data_hash: str) -> dict:
    """Looks up the latest verification result for a given data hash."""
    db = SessionLocal()
    try:
        result = db.query(VerificationResult).filter(
            VerificationResult.data_hash == data_hash
        ).order_by(VerificationResult.created_at.desc()).first()
        if not result:
            return {}
        return {
            "status": "verified",
            "data_hash": result.data_hash,
            "proof_hash": result.proof_hash,
            "verdict": result.verdict,
            "score": result.composite_score,
            "action": result.action,
            "agent_id": result.agent_id,
            "submission_id": result.submission_id,
            "details": result.details,
            "created_at": result.created_at.isoformat() if result.created_at else "",
        }
    finally:
        db.close()


def get_verification_by_proof_hash(proof_hash: str) -> dict:
    """Looks up a verification result by its proof hash."""
    db = SessionLocal()
    try:
        result = db.query(VerificationResult).filter(
            VerificationResult.proof_hash == proof_hash
        ).first()
        if not result:
            return {}
        return {
            "data_hash": result.data_hash,
            "proof_hash": result.proof_hash,
            "verdict": result.verdict,
            "score": result.composite_score,
            "action": result.action,
            "agent_id": result.agent_id,
            "submission_id": result.submission_id,
            "details": result.details,
            "created_at": result.created_at.isoformat() if result.created_at else "",
        }
    finally:
        db.close()


def get_quarantine_queue(limit: int = 50) -> list:
    """Returns pending quarantine items for human review."""
    db = SessionLocal()
    try:
        items = db.query(DataQuarantine).filter(
            DataQuarantine.resolution_status == "PENDING"
        ).order_by(DataQuarantine.created_at.desc()).limit(limit).all()
        return [
            {
                "id": item.id,
                "submission_id": item.submission_id,
                "data_hash": item.data_hash,
                "score": item.score,
                "reason": item.reason,
                "created_at": item.created_at.isoformat() if item.created_at else "",
            }
            for item in items
        ]
    finally:
        db.close()


def resolve_quarantine(quarantine_id: int, resolution: str, resolved_by: str = "human") -> bool:
    """
    Resolves a quarantine item.
    resolution: 'APPROVED' (promote to verified) or 'REJECTED' (discard)
    """
    db = SessionLocal()
    try:
        item = db.query(DataQuarantine).filter(
            DataQuarantine.id == quarantine_id
        ).first()
        if not item:
            return False
        item.resolution_status = resolution
        item.resolved_by = resolved_by
        item.resolved_at = datetime.utcnow()
        db.commit()
        logger.info("Quarantine %s resolved as %s by %s", quarantine_id, resolution, resolved_by)
        return True
    except Exception as e:
        db.rollback()
        logger.error("resolve_quarantine failed: %s", e)
        return False
    finally:
        db.close()


def get_refinery_stats() -> dict:
    """Returns aggregate refinery statistics."""
    db = SessionLocal()
    try:
        total_submissions = db.query(RawSubmission).count()
        duplicates = db.query(RawSubmission).filter(
            RawSubmission.is_duplicate == True
        ).count()
        verdicts = {}
        for v in ["VERIFIED", "GOLD", "QUARANTINE", "REJECTED"]:
            verdicts[v.lower()] = db.query(VerificationResult).filter(
                VerificationResult.verdict == v
            ).count()
        quarantine_pending = db.query(DataQuarantine).filter(
            DataQuarantine.resolution_status == "PENDING"
        ).count()
        stamps = db.query(BlockchainStamp).count()
        # Resolution stats for calibration (reversal rate, threshold tuning)
        total_approved = db.query(DataQuarantine).filter(
            DataQuarantine.resolution_status == "APPROVED"
        ).count()
        total_rejected_q = db.query(DataQuarantine).filter(
            DataQuarantine.resolution_status == "REJECTED"
        ).count()
        total_resolved = total_approved + total_rejected_q

        # Average scores by verdict (for threshold tuning)
        from sqlalchemy import func
        avg_scores = {}
        for v in ["VERIFIED", "GOLD", "QUARANTINE", "REJECTED"]:
            avg = db.query(func.avg(VerificationResult.composite_score)).filter(
                VerificationResult.verdict == v
            ).scalar()
            avg_scores[v.lower()] = round(float(avg), 4) if avg else 0.0

        return {
            "total_submissions": total_submissions,
            "duplicates": duplicates,
            "verdicts": verdicts,
            "quarantine_pending": quarantine_pending,
            "blockchain_stamps": stamps,
            "resolution": {
                "total_resolved": total_resolved,
                "approved": total_approved,
                "rejected": total_rejected_q,
                "reversal_rate": round(total_approved / total_resolved, 4) if total_resolved > 0 else 0.0,
            },
            "avg_scores": avg_scores,
        }
    finally:
        db.close()


# -----------------------------------------------------------------------
# PRODUCTION TASK HELPERS (M2M /m2m/submit persistence)
# -----------------------------------------------------------------------

def save_production_task(
    task_id: str,
    agent_id: str,
    service_id: str,
    payload: dict,
    quote_id: str = "",
    target_url: str = "",
    context: dict = None,
    status: str = "queued",
) -> "M2MTask":
    """Persists an M2M task to survive restarts."""
    db = SessionLocal()
    try:
        existing = db.query(M2MTask).filter(
            M2MTask.task_id == task_id
        ).first()
        if existing:
            return existing
        record = M2MTask(
            task_id=task_id,
            agent_id=agent_id,
            service_id=service_id,
            quote_id=quote_id or "",
            payload=payload,
            target_url=target_url or "",
            context=context or {},
            status=status,
        )
        db.add(record)
        db.commit()
        db.refresh(record)
        return record
    except Exception as e:
        db.rollback()
        logger.error("M2MTask save failed: %s", e)
        raise
    finally:
        db.close()


def get_orphaned_tasks(statuses: list = None) -> list:
    """Returns tasks stuck in queued/running state (for restart recovery)."""
    statuses = statuses or ["queued", "running"]
    db = SessionLocal()
    try:
        tasks = db.query(M2MTask).filter(
            M2MTask.status.in_(statuses)
        ).order_by(M2MTask.created_at.asc()).all()
        return [
            {
                "task_id": t.task_id,
                "agent_id": t.agent_id,
                "service_id": t.service_id,
                "quote_id": t.quote_id,
                "payload": t.payload,
                "target_url": t.target_url,
                "context": t.context,
                "status": t.status,
                "result": t.result,
                "created_at": t.created_at.isoformat() if t.created_at else "",
                "completed_at": t.completed_at.isoformat() if t.completed_at else None,
            }
            for t in tasks
        ]
    except Exception as e:
        logger.warning(f"get_orphaned_tasks failed: {e}")
        return []
    finally:
        db.close()


def update_production_task(
    task_id: str,
    status: str,
    result: dict = None,
) -> bool:
    """Updates task status and result after execution."""
    db = SessionLocal()
    try:
        task = db.query(M2MTask).filter(
            M2MTask.task_id == task_id
        ).first()
        if not task:
            return False
        task.status = status
        if result is not None:
            task.result = result
        if status in ("completed", "failed"):
            task.completed_at = datetime.utcnow()
        db.commit()
        return True
    except Exception as e:
        db.rollback()
        logger.error("M2MTask update failed: %s", e)
        return False
    finally:
        db.close()


def get_production_task(task_id: str) -> dict:
    """Looks up a task by ID. Returns empty dict if not found."""
    db = SessionLocal()
    try:
        task = db.query(M2MTask).filter(
            M2MTask.task_id == task_id
        ).first()
        if not task:
            return {}
        return {
            "task_id": task.task_id,
            "agent_id": task.agent_id,
            "service_id": task.service_id,
            "quote_id": task.quote_id,
            "payload": task.payload,
            "target_url": task.target_url,
            "context": task.context,
            "status": task.status,
            "result": task.result,
            "created_at": task.created_at.isoformat() if task.created_at else "",
            "completed_at": task.completed_at.isoformat() if task.completed_at else None,
        }
    finally:
        db.close()


# -----------------------------------------------------------------------
# AGENT VERIFICATION HELPERS
# -----------------------------------------------------------------------

def save_agent_verification(
    agent_id: str,
    agent_name: str = "",
    agent_url: str = "",
    public_key: str = "",
    capabilities: list = None,
    agent_metadata: dict = None,
) -> "AgentVerification":
    """Creates a new agent verification request (PENDING)."""
    db = SessionLocal()
    try:
        record = AgentVerification(
            agent_id=agent_id,
            agent_name=agent_name or "",
            agent_url=agent_url or "",
            public_key=public_key or "",
            capabilities=capabilities or [],
            agent_metadata=agent_metadata or {},
            verdict="PENDING",
            trust_score=0.0,
        )
        db.add(record)
        db.commit()
        db.refresh(record)
        return record
    except Exception as e:
        db.rollback()
        logger.error("AgentVerification save failed: %s", e)
        raise
    finally:
        db.close()


def update_agent_verification(
    verification_id: int,
    verdict: str,
    trust_score: float,
    checks_passed: dict = None,
    risk_flags: list = None,
    proof_hash: str = "",
    tx_hash: str = "",
    expires_at: "datetime" = None,
    passport_fingerprint: str = "",
) -> bool:
    """Updates an agent verification with results."""
    db = SessionLocal()
    try:
        record = db.query(AgentVerification).filter(
            AgentVerification.id == verification_id
        ).first()
        if not record:
            return False
        record.verdict = verdict
        record.trust_score = trust_score
        record.checks_passed = checks_passed or {}
        record.risk_flags = risk_flags or []
        record.proof_hash = proof_hash
        record.tx_hash = tx_hash
        record.verified_at = datetime.utcnow()
        if passport_fingerprint:
            record.passport_fingerprint = passport_fingerprint
        if expires_at:
            record.expires_at = expires_at
        db.commit()
        return True
    except Exception as e:
        db.rollback()
        logger.error("AgentVerification update failed: %s", e)
        return False
    finally:
        db.close()


def get_agent_trust(agent_id: str) -> dict:
    """
    Looks up the latest verification for an agent.
    Returns trust status for quick lookups by other bots.
    """
    db = SessionLocal()
    try:
        record = db.query(AgentVerification).filter(
            AgentVerification.agent_id == agent_id,
            AgentVerification.verdict != "PENDING",
        ).order_by(AgentVerification.verified_at.desc()).first()
        if not record:
            return {"agent_id": agent_id, "status": "UNKNOWN", "trust_score": 0.0}
        expired = record.expires_at and record.expires_at < datetime.utcnow()
        return {
            "agent_id": record.agent_id,
            "status": "EXPIRED" if expired else record.verdict,
            "trust_score": record.trust_score,
            "verified_at": record.verified_at.isoformat() if record.verified_at else "",
            "expires_at": record.expires_at.isoformat() if record.expires_at else "",
            "proof_hash": record.proof_hash or "",
            "tx_hash": record.tx_hash or "",
            "chain": record.chain,
            "checks": record.checks_passed or {},
            "risk_flags": record.risk_flags or [],
            "capabilities": record.capabilities or [],
            "passport_fingerprint": record.passport_fingerprint or "",
        }
    finally:
        db.close()


def list_agent_verifications(limit: int = 50) -> list:
    """Returns recent agent verifications."""
    db = SessionLocal()
    try:
        records = db.query(AgentVerification).order_by(
            AgentVerification.submitted_at.desc()
        ).limit(limit).all()
        return [
            {
                "id": r.id,
                "agent_id": r.agent_id,
                "agent_name": r.agent_name,
                "verdict": r.verdict,
                "trust_score": r.trust_score,
                "submitted_at": r.submitted_at.isoformat() if r.submitted_at else "",
                "verified_at": r.verified_at.isoformat() if r.verified_at else "",
                "proof_hash": r.proof_hash or "",
            }
            for r in records
        ]
    finally:
        db.close()


# ---------------------------------------------------------------------------
# DASHBOARD AGENT PERSISTENCE
# ---------------------------------------------------------------------------

def save_dashboard_agent(agent_data: dict) -> "DashboardAgent":
    """Upsert a dashboard agent record. Returns the DB record."""
    db = SessionLocal()
    try:
        record = db.query(DashboardAgent).filter(
            DashboardAgent.agent_id == agent_data["agent_id"]
        ).first()
        if record:
            record.name = agent_data.get("name", record.name)
            record.url = agent_data.get("url", record.url)
            record.port = agent_data.get("port", record.port)
            record.role = agent_data.get("role", record.role)
            record.skills = agent_data.get("skills", record.skills)
            record.version = agent_data.get("version", record.version)
            record.status = agent_data.get("status", record.status)
            record.description = agent_data.get("description", record.description)
            record.last_seen = datetime.utcnow()
        else:
            record = DashboardAgent(
                agent_id=agent_data["agent_id"],
                name=agent_data.get("name", ""),
                url=agent_data.get("url", ""),
                port=agent_data.get("port", 0),
                role=agent_data.get("role", "supply_chain"),
                skills=agent_data.get("skills", []),
                version=agent_data.get("version", "1.0"),
                status=agent_data.get("status", "online"),
                description=agent_data.get("description", ""),
            )
            db.add(record)
        db.commit()
        db.refresh(record)
        return record
    except Exception as e:
        db.rollback()
        logger.error("DashboardAgent save failed: %s", e)
        raise
    finally:
        db.close()


def load_all_dashboard_agents() -> list:
    """Load all dashboard agents from DB. Used on startup to repopulate in-memory cache."""
    db = SessionLocal()
    try:
        records = db.query(DashboardAgent).order_by(DashboardAgent.registered_at).all()
        return [
            {
                "agent_id": r.agent_id,
                "name": r.name,
                "url": r.url,
                "port": r.port,
                "role": r.role,
                "skills": r.skills or [],
                "version": r.version,
                "status": r.status,
                "description": r.description,
                "reputation_score": r.reputation_score,
                "registered_at": r.registered_at.isoformat() if r.registered_at else "",
                "last_seen": r.last_seen.isoformat() if r.last_seen else "",
            }
            for r in records
        ]
    except Exception as e:
        logger.error("DashboardAgent load failed: %s", e)
        return []
    finally:
        db.close()


# ---------------------------------------------------------------------------
# AGENT VERIFICATION QUERY HELPERS (for 10-check trust pipeline)
# ---------------------------------------------------------------------------

def get_agent_submission_stats(agent_id: str) -> dict:
    """VerificationResult verdict counts for an agent."""
    db = SessionLocal()
    try:
        results = db.query(VerificationResult).filter(
            VerificationResult.agent_id == agent_id
        ).all()
        stats = {"total": len(results), "VERIFIED": 0, "REJECTED": 0, "QUARANTINE": 0, "GOLD": 0}
        for r in results:
            if r.verdict in stats:
                stats[r.verdict] += 1
        return stats
    except Exception as e:
        logger.warning(f"get_agent_submission_stats failed for {agent_id}: {e}")
        return {"total": 0, "VERIFIED": 0, "REJECTED": 0, "QUARANTINE": 0, "GOLD": 0}
    finally:
        db.close()


def get_agent_task_history(agent_id: str) -> list:
    """M2MTask records for an agent, grouped by service_id."""
    db = SessionLocal()
    try:
        tasks = db.query(M2MTask).filter(
            M2MTask.agent_id == agent_id
        ).order_by(M2MTask.created_at.desc()).limit(100).all()
        return [
            {
                "task_id": t.task_id,
                "service_id": t.service_id,
                "status": t.status,
                "created_at": t.created_at.isoformat() if t.created_at else "",
            }
            for t in tasks
        ]
    except Exception as e:
        logger.warning(f"get_agent_task_history failed: {e}")
        return []
    finally:
        db.close()


def get_agent_handoff_stats(agent_id: str) -> dict:
    """HandoffTransaction success/failure rates for an agent (as sender or receiver)."""
    db = SessionLocal()
    try:
        as_sender = db.query(HandoffTransaction).filter(
            HandoffTransaction.sender_id == agent_id
        ).all()
        as_receiver = db.query(HandoffTransaction).filter(
            HandoffTransaction.receiver_id == agent_id
        ).all()
        all_handoffs = as_sender + as_receiver
        total = len(all_handoffs)
        accepted = sum(1 for h in all_handoffs if h.status == "ACCEPTED")
        rejected = sum(1 for h in all_handoffs if h.status == "REJECTED")
        # Unique trusted partners
        partner_ids = set()
        for h in all_handoffs:
            if h.status == "ACCEPTED":
                partner = h.receiver_id if h.sender_id == agent_id else h.sender_id
                partner_ids.add(partner)
        return {
            "total": total,
            "accepted": accepted,
            "rejected": rejected,
            "success_rate": accepted / total if total > 0 else 0.0,
            "trusted_partners": list(partner_ids),
            "trusted_partner_count": len(partner_ids),
        }
    except Exception as e:
        logger.warning(f"get_agent_handoff_stats failed: {e}")
        return {"total": 0, "accepted": 0, "rejected": 0, "success_rate": 0.0, "trusted_partners": [], "trusted_partner_count": 0}
    finally:
        db.close()


def get_agent_verification_history(agent_id: str) -> list:
    """Score trajectory over time for an agent. Most recent first."""
    db = SessionLocal()
    try:
        records = db.query(AgentVerification).filter(
            AgentVerification.agent_id == agent_id,
            AgentVerification.verdict != "PENDING",
        ).order_by(AgentVerification.verified_at.desc()).all()
        return [
            {
                "id": r.id,
                "trust_score": r.trust_score,
                "verdict": r.verdict,
                "verified_at": r.verified_at.isoformat() if r.verified_at else "",
                "submitted_at": r.submitted_at.isoformat() if r.submitted_at else "",
                "passport_fingerprint": r.passport_fingerprint or "",
                "proof_hash": r.proof_hash or "",
                "tx_hash": r.tx_hash or "",
                "risk_flags": r.risk_flags or [],
                "risk_category": "",
                "checks_passed": r.checks_passed or {},
                "expires_at": r.expires_at.isoformat() if r.expires_at else "",
            }
            for r in records
        ]
    except Exception as e:
        logger.warning(f"get_agent_verification_history failed: {e}")
        return []
    finally:
        db.close()


def find_agents_by_public_key(public_key: str, exclude_agent_id: str = "") -> list:
    """Anti-Sybil: find other agents using the same public key."""
    if not public_key:
        return []
    db = SessionLocal()
    try:
        query = db.query(AgentVerification).filter(
            AgentVerification.public_key == public_key,
            AgentVerification.verdict != "PENDING",
        )
        if exclude_agent_id:
            query = query.filter(AgentVerification.agent_id != exclude_agent_id)
        records = query.all()
        return list({r.agent_id for r in records})
    except Exception as e:
        logger.warning(f"find_agents_by_public_key failed: {e}")
        return []
    finally:
        db.close()


def find_agents_by_url(url: str, exclude_agent_id: str = "") -> list:
    """Anti-Sybil: find other agents at the same URL."""
    if not url:
        return []
    db = SessionLocal()
    try:
        query = db.query(AgentVerification).filter(
            AgentVerification.agent_url == url,
            AgentVerification.verdict != "PENDING",
        )
        if exclude_agent_id:
            query = query.filter(AgentVerification.agent_id != exclude_agent_id)
        records = query.all()
        return list({r.agent_id for r in records})
    except Exception as e:
        logger.warning(f"find_agents_by_url failed: {e}")
        return []
    finally:
        db.close()


def get_recent_submissions_by_agent(agent_id: str, limit: int = 20) -> list:
    """Last N RawSubmission records joined with VerificationResult for payload quality analysis."""
    db = SessionLocal()
    try:
        subs = db.query(RawSubmission).filter(
            RawSubmission.source_agent_id == agent_id
        ).order_by(RawSubmission.created_at.desc()).limit(limit).all()
        results = []
        for s in subs:
            vr = db.query(VerificationResult).filter(
                VerificationResult.submission_id == s.id
            ).first()
            results.append({
                "submission_id": s.id,
                "data_hash": s.data_hash,
                "format": s.format,
                "raw_size_bytes": s.raw_size_bytes,
                "is_duplicate": s.is_duplicate,
                "created_at": s.created_at.isoformat() if s.created_at else "",
                "verdict": vr.verdict if vr else None,
                "score": vr.composite_score if vr else None,
            })
        return results
    except Exception:
        return []
    finally:
        db.close()


def get_agent_registration_burst(agent_id: str, window_minutes: int = 60) -> list:
    """Sybil burst detection: agents registered within a time window of this agent's registration."""
    db = SessionLocal()
    try:
        # Find this agent's first registration
        this_agent = db.query(AgentVerification).filter(
            AgentVerification.agent_id == agent_id
        ).order_by(AgentVerification.submitted_at.asc()).first()
        if not this_agent or not this_agent.submitted_at:
            return []
        window_start = this_agent.submitted_at - timedelta(minutes=window_minutes)
        window_end = this_agent.submitted_at + timedelta(minutes=window_minutes)
        nearby = db.query(AgentVerification).filter(
            AgentVerification.agent_id != agent_id,
            AgentVerification.submitted_at >= window_start,
            AgentVerification.submitted_at <= window_end,
        ).all()
        return list({r.agent_id for r in nearby})
    except Exception:
        return []
    finally:
        db.close()


# ---------------------------------------------------------------------------
# HANDOFF TRANSACTION helpers
# ---------------------------------------------------------------------------

def save_handoff_transaction(
    handoff_id: str,
    sender_id: str,
    receiver_id: str,
    payload_hash: str = "",
    payload_summary: str = "",
    status: str = "PENDING",
) -> dict:
    """Creates a new handoff transaction record."""
    db = SessionLocal()
    try:
        record = HandoffTransaction(
            id=handoff_id,
            sender_id=sender_id,
            receiver_id=receiver_id,
            payload_hash=payload_hash,
            payload_summary=payload_summary,
            status=status,
        )
        db.add(record)
        db.commit()
        return {
            "id": handoff_id,
            "sender_id": sender_id,
            "receiver_id": receiver_id,
            "status": status,
        }
    except Exception as e:
        db.rollback()
        logger.error("HandoffTransaction save failed: %s", e)
        raise
    finally:
        db.close()


def update_handoff_transaction(
    handoff_id: str,
    status: str = None,
    sender_verified: bool = None,
    sender_trust_score: float = None,
    payload_verdict: str = None,
    payload_score: float = None,
    proof_hash: str = None,
    tx_hash: str = None,
    reason: str = None,
) -> bool:
    """Updates an existing handoff transaction."""
    db = SessionLocal()
    try:
        record = db.query(HandoffTransaction).filter(
            HandoffTransaction.id == handoff_id
        ).first()
        if not record:
            return False
        if status is not None:
            record.status = status
        if sender_verified is not None:
            record.sender_verified = sender_verified
        if sender_trust_score is not None:
            record.sender_trust_score = sender_trust_score
        if payload_verdict is not None:
            record.payload_verdict = payload_verdict
        if payload_score is not None:
            record.payload_score = payload_score
        if proof_hash is not None:
            record.proof_hash = proof_hash
        if tx_hash is not None:
            record.tx_hash = tx_hash
        if reason is not None:
            record.reason = reason
        if status in ("ACCEPTED", "REJECTED"):
            record.completed_at = datetime.utcnow()
        db.commit()
        return True
    except Exception as e:
        db.rollback()
        logger.error("HandoffTransaction update failed: %s", e)
        return False
    finally:
        db.close()


def get_handoff_transaction(handoff_id: str) -> dict:
    """Retrieves a handoff transaction by ID."""
    db = SessionLocal()
    try:
        record = db.query(HandoffTransaction).filter(
            HandoffTransaction.id == handoff_id
        ).first()
        if not record:
            return {}
        return {
            "id": record.id,
            "sender_id": record.sender_id,
            "receiver_id": record.receiver_id,
            "payload_hash": record.payload_hash,
            "payload_summary": record.payload_summary,
            "sender_verified": record.sender_verified,
            "sender_trust_score": record.sender_trust_score,
            "payload_verdict": record.payload_verdict,
            "payload_score": record.payload_score,
            "status": record.status,
            "proof_hash": record.proof_hash,
            "tx_hash": record.tx_hash,
            "reason": record.reason,
            "created_at": record.created_at.isoformat() if record.created_at else "",
            "completed_at": record.completed_at.isoformat() if record.completed_at else "",
        }
    finally:
        db.close()


# ---------------------------------------------------------------------------
# SANDBOX HELPERS
# ---------------------------------------------------------------------------

def save_sandbox_organization(
    org_id: str,
    name: str,
    email: str,
    tier: str = "free",
    max_agents: int = 5,
    max_sandbox_runs: int = 100,
) -> "SandboxOrganization":
    """Creates a new sandbox organization."""
    db = SessionLocal()
    try:
        existing = db.query(SandboxOrganization).filter(
            SandboxOrganization.email == email
        ).first()
        if existing:
            return existing
        record = SandboxOrganization(
            id=org_id,
            name=name,
            email=email,
            tier=tier,
            max_agents=max_agents,
            max_sandbox_runs=max_sandbox_runs,
        )
        db.add(record)
        db.commit()
        db.refresh(record)
        logger.info("SandboxOrganization %s created (%s)", org_id, email)
        return record
    except Exception as e:
        db.rollback()
        logger.error("SandboxOrganization save failed: %s", e)
        raise
    finally:
        db.close()


def get_sandbox_organization(org_id: str) -> dict:
    """Looks up an organization by ID."""
    db = SessionLocal()
    try:
        record = db.query(SandboxOrganization).filter(
            SandboxOrganization.id == org_id
        ).first()
        if not record:
            return {}
        return {
            "id": record.id,
            "name": record.name,
            "email": record.email,
            "tier": record.tier,
            "max_agents": record.max_agents,
            "max_sandbox_runs": record.max_sandbox_runs,
            "sandbox_runs_used": record.sandbox_runs_used,
            "is_active": record.is_active,
            "created_at": record.created_at.isoformat() if record.created_at else "",
        }
    finally:
        db.close()


def save_persistent_api_key(
    key_id: str,
    key_hash: str,
    agent_id: str,
    org_id: str = None,
    environment: str = "sandbox",
    permissions: list = None,
    rate_limit_per_minute: int = 60,
    expires_at: "datetime" = None,
) -> "PersistentAPIKey":
    """Persists an API key to survive restarts."""
    db = SessionLocal()
    try:
        existing = db.query(PersistentAPIKey).filter(
            PersistentAPIKey.key_id == key_id
        ).first()
        if existing:
            return existing
        record = PersistentAPIKey(
            key_id=key_id,
            key_hash=key_hash,
            agent_id=agent_id,
            org_id=org_id,
            environment=environment,
            permissions=permissions or [],
            rate_limit_per_minute=rate_limit_per_minute,
            expires_at=expires_at,
        )
        db.add(record)
        db.commit()
        db.refresh(record)
        logger.info("PersistentAPIKey %s saved (env=%s)", key_id, environment)
        return record
    except Exception as e:
        db.rollback()
        logger.error("PersistentAPIKey save failed: %s", e)
        raise
    finally:
        db.close()


def get_persistent_api_key(key_id: str) -> dict:
    """Looks up an API key by key_id."""
    db = SessionLocal()
    try:
        record = db.query(PersistentAPIKey).filter(
            PersistentAPIKey.key_id == key_id
        ).first()
        if not record:
            return {}
        return {
            "key_id": record.key_id,
            "key_hash": record.key_hash,
            "agent_id": record.agent_id,
            "org_id": record.org_id,
            "environment": record.environment,
            "permissions": record.permissions or [],
            "rate_limit_per_minute": record.rate_limit_per_minute,
            "is_active": record.is_active,
            "expires_at": record.expires_at.isoformat() if record.expires_at else None,
            "last_used_at": record.last_used_at.isoformat() if record.last_used_at else None,
            "created_at": record.created_at.isoformat() if record.created_at else "",
        }
    finally:
        db.close()


def revoke_persistent_api_key(key_id: str) -> bool:
    """Deactivates an API key in the database."""
    db = SessionLocal()
    try:
        record = db.query(PersistentAPIKey).filter(
            PersistentAPIKey.key_id == key_id
        ).first()
        if not record:
            return False
        record.is_active = False
        db.commit()
        logger.info("PersistentAPIKey %s revoked", key_id)
        return True
    except Exception as e:
        db.rollback()
        logger.error("revoke_persistent_api_key failed: %s", e)
        return False
    finally:
        db.close()


def list_persistent_api_keys(org_id: str = None, environment: str = None) -> list:
    """Lists API keys, optionally filtered by org and environment."""
    db = SessionLocal()
    try:
        query = db.query(PersistentAPIKey).filter(PersistentAPIKey.is_active == True)
        if org_id:
            query = query.filter(PersistentAPIKey.org_id == org_id)
        if environment:
            query = query.filter(PersistentAPIKey.environment == environment)
        records = query.order_by(PersistentAPIKey.created_at.desc()).all()
        return [
            {
                "key_id": r.key_id,
                "agent_id": r.agent_id,
                "org_id": r.org_id,
                "environment": r.environment,
                "rate_limit_per_minute": r.rate_limit_per_minute,
                "created_at": r.created_at.isoformat() if r.created_at else "",
            }
            for r in records
        ]
    finally:
        db.close()


def load_all_api_keys() -> list:
    """Loads all active API keys from DB for startup warm-load into authenticator cache."""
    db = SessionLocal()
    try:
        records = db.query(PersistentAPIKey).filter(
            PersistentAPIKey.is_active == True
        ).all()
        return [
            {
                "key_id": r.key_id,
                "key_hash": r.key_hash,
                "agent_id": r.agent_id,
                "org_id": r.org_id,
                "environment": r.environment,
                "permissions": r.permissions or [],
                "rate_limit_per_minute": r.rate_limit_per_minute,
                "expires_at": r.expires_at.isoformat() if r.expires_at else None,
            }
            for r in records
        ]
    except Exception as e:
        logger.error("load_all_api_keys failed: %s", e)
        return []
    finally:
        db.close()


def save_sandbox_session(
    session_id: str,
    org_id: str,
    agent_id: str,
    config: dict = None,
    expires_at: "datetime" = None,
) -> "SandboxSession":
    """Creates a new sandbox test session."""
    db = SessionLocal()
    try:
        record = SandboxSession(
            id=session_id,
            org_id=org_id,
            agent_id=agent_id,
            config=config or {},
            expires_at=expires_at,
        )
        db.add(record)
        # Increment org usage
        org = db.query(SandboxOrganization).filter(
            SandboxOrganization.id == org_id
        ).first()
        if org:
            org.sandbox_runs_used = (org.sandbox_runs_used or 0) + 1
        db.commit()
        db.refresh(record)
        logger.info("SandboxSession %s created for agent %s", session_id, agent_id)
        return record
    except Exception as e:
        db.rollback()
        logger.error("SandboxSession save failed: %s", e)
        raise
    finally:
        db.close()


def update_sandbox_session(
    session_id: str,
    status: str = None,
    results_summary: dict = None,
) -> bool:
    """Updates a sandbox session status and/or results."""
    db = SessionLocal()
    try:
        record = db.query(SandboxSession).filter(
            SandboxSession.id == session_id
        ).first()
        if not record:
            return False
        if status:
            record.status = status
        if results_summary is not None:
            record.results_summary = results_summary
        if status == "completed":
            record.completed_at = datetime.utcnow()
        db.commit()
        return True
    except Exception as e:
        db.rollback()
        logger.error("SandboxSession update failed: %s", e)
        return False
    finally:
        db.close()


def get_sandbox_session(session_id: str) -> dict:
    """Retrieves a sandbox session by ID."""
    db = SessionLocal()
    try:
        record = db.query(SandboxSession).filter(
            SandboxSession.id == session_id
        ).first()
        if not record:
            return {}
        return {
            "id": record.id,
            "org_id": record.org_id,
            "agent_id": record.agent_id,
            "status": record.status,
            "config": record.config or {},
            "results_summary": record.results_summary or {},
            "created_at": record.created_at.isoformat() if record.created_at else "",
            "completed_at": record.completed_at.isoformat() if record.completed_at else None,
            "expires_at": record.expires_at.isoformat() if record.expires_at else None,
        }
    finally:
        db.close()


def list_sandbox_sessions(org_id: str = None, status: str = None, limit: int = 50) -> list:
    """Lists sandbox sessions, optionally filtered."""
    db = SessionLocal()
    try:
        query = db.query(SandboxSession)
        if org_id:
            query = query.filter(SandboxSession.org_id == org_id)
        if status:
            query = query.filter(SandboxSession.status == status)
        records = query.order_by(SandboxSession.created_at.desc()).limit(limit).all()
        return [
            {
                "id": r.id,
                "org_id": r.org_id,
                "agent_id": r.agent_id,
                "status": r.status,
                "created_at": r.created_at.isoformat() if r.created_at else "",
                "completed_at": r.completed_at.isoformat() if r.completed_at else None,
            }
            for r in records
        ]
    finally:
        db.close()


def save_trust_score_history(
    agent_id: str,
    previous_score: float,
    new_score: float,
    reason: str,
    event_type: str,
    session_id: str = None,
) -> "TrustScoreHistory":
    """Records a trust score change for audit trail."""
    db = SessionLocal()
    try:
        record = TrustScoreHistory(
            agent_id=agent_id,
            previous_score=previous_score,
            new_score=new_score,
            delta=round(new_score - previous_score, 6),
            reason=reason,
            event_type=event_type,
            session_id=session_id,
        )
        db.add(record)
        db.commit()
        db.refresh(record)
        return record
    except Exception as e:
        db.rollback()
        logger.error("TrustScoreHistory save failed: %s", e)
        raise
    finally:
        db.close()


def get_trust_score_history(agent_id: str, limit: int = 50) -> list:
    """Returns trust score audit trail for an agent."""
    db = SessionLocal()
    try:
        records = db.query(TrustScoreHistory).filter(
            TrustScoreHistory.agent_id == agent_id
        ).order_by(TrustScoreHistory.created_at.desc()).limit(limit).all()
        return [
            {
                "id": r.id,
                "agent_id": r.agent_id,
                "previous_score": r.previous_score,
                "new_score": r.new_score,
                "delta": r.delta,
                "reason": r.reason,
                "event_type": r.event_type,
                "session_id": r.session_id,
                "created_at": r.created_at.isoformat() if r.created_at else "",
            }
            for r in records
        ]
    finally:
        db.close()


def save_sandbox_attack_result(
    session_id: str,
    agent_id: str,
    attack_type: str,
    passed: bool,
    severity: str = "medium",
    details: dict = None,
    vulnerabilities: list = None,
    duration_ms: int = 0,
) -> "SandboxAttackResult":
    """Records the result of a single attack simulation."""
    db = SessionLocal()
    try:
        record = SandboxAttackResult(
            session_id=session_id,
            agent_id=agent_id,
            attack_type=attack_type,
            passed=passed,
            severity=severity,
            details=details or {},
            vulnerabilities=vulnerabilities or [],
            duration_ms=duration_ms,
        )
        db.add(record)
        db.commit()
        db.refresh(record)
        return record
    except Exception as e:
        db.rollback()
        logger.error("SandboxAttackResult save failed: %s", e)
        raise
    finally:
        db.close()


def get_sandbox_attack_results(session_id: str) -> list:
    """Returns all attack results for a session."""
    db = SessionLocal()
    try:
        records = db.query(SandboxAttackResult).filter(
            SandboxAttackResult.session_id == session_id
        ).order_by(SandboxAttackResult.created_at.asc()).all()
        return [
            {
                "id": r.id,
                "session_id": r.session_id,
                "agent_id": r.agent_id,
                "attack_type": r.attack_type,
                "passed": r.passed,
                "severity": r.severity,
                "details": r.details or {},
                "vulnerabilities": r.vulnerabilities or [],
                "duration_ms": r.duration_ms,
                "created_at": r.created_at.isoformat() if r.created_at else "",
            }
            for r in records
        ]
    finally:
        db.close()


def get_sandbox_leaderboard(limit: int = 25) -> list:
    """Returns agents ranked by trust score from their most recent verification."""
    db = SessionLocal()
    try:
        from sqlalchemy import func, distinct
        # Get latest verification per agent_id
        subq = db.query(
            AgentVerification.agent_id,
            func.max(AgentVerification.id).label("max_id")
        ).filter(
            AgentVerification.verdict != "PENDING"
        ).group_by(AgentVerification.agent_id).subquery()

        records = db.query(AgentVerification).join(
            subq, AgentVerification.id == subq.c.max_id
        ).order_by(AgentVerification.trust_score.desc()).limit(limit).all()

        return [
            {
                "agent_id": r.agent_id,
                "agent_name": r.agent_name or r.agent_id,
                "trust_score": r.trust_score,
                "verdict": r.verdict,
                "verified_at": r.verified_at.isoformat() if r.verified_at else "",
            }
            for r in records
        ]
    except Exception:
        return []
    finally:
        db.close()


def get_sandbox_stats() -> dict:
    """Aggregate sandbox statistics."""
    db = SessionLocal()
    try:
        total_orgs = db.query(SandboxOrganization).count()
        active_orgs = db.query(SandboxOrganization).filter(
            SandboxOrganization.is_active == True
        ).count()
        total_sessions = db.query(SandboxSession).count()
        active_sessions = db.query(SandboxSession).filter(
            SandboxSession.status == "active"
        ).count()
        total_attacks = db.query(SandboxAttackResult).count()
        attacks_passed = db.query(SandboxAttackResult).filter(
            SandboxAttackResult.passed == True
        ).count()
        total_keys = db.query(PersistentAPIKey).filter(
            PersistentAPIKey.is_active == True
        ).count()
        return {
            "organizations": {"total": total_orgs, "active": active_orgs},
            "sessions": {"total": total_sessions, "active": active_sessions},
            "attacks": {
                "total": total_attacks,
                "passed": attacks_passed,
                "failed": total_attacks - attacks_passed,
                "pass_rate": round(attacks_passed / total_attacks, 4) if total_attacks > 0 else 0.0,
            },
            "api_keys_active": total_keys,
        }
    except Exception:
        return {"organizations": {}, "sessions": {}, "attacks": {}, "api_keys_active": 0}
    finally:
        db.close()


def get_all_attack_results(limit: int = 50, offset: int = 0, attack_type: str = None) -> list:
    """Paginated attack results across all sessions, newest first."""
    db = SessionLocal()
    try:
        q = db.query(SandboxAttackResult)
        if attack_type:
            q = q.filter(SandboxAttackResult.attack_type == attack_type)
        records = q.order_by(SandboxAttackResult.created_at.desc()).offset(offset).limit(limit).all()
        return [
            {
                "id": r.id,
                "session_id": r.session_id,
                "agent_id": r.agent_id,
                "attack_type": r.attack_type,
                "passed": r.passed,
                "severity": r.severity,
                "details": r.details or {},
                "vulnerabilities": r.vulnerabilities or [],
                "duration_ms": r.duration_ms,
                "created_at": r.created_at.isoformat() if r.created_at else "",
            }
            for r in records
        ]
    except Exception:
        return []
    finally:
        db.close()


def get_agent_attack_summary(agent_id: str) -> dict:
    """Aggregate attack stats for an agent: {attack_type: {total, passed, failed}} + overall."""
    db = SessionLocal()
    try:
        from sqlalchemy import func, case
        rows = db.query(
            SandboxAttackResult.attack_type,
            func.count().label("total"),
            func.sum(case((SandboxAttackResult.passed == True, 1), else_=0)).label("passed"),
        ).filter(
            SandboxAttackResult.agent_id == agent_id
        ).group_by(SandboxAttackResult.attack_type).all()

        by_type = {}
        grand_total = 0
        grand_passed = 0
        for row in rows:
            t, total, passed = row
            passed = int(passed or 0)
            by_type[t] = {"total": total, "passed": passed, "failed": total - passed}
            grand_total += total
            grand_passed += passed

        return {
            "by_type": by_type,
            "total": grand_total,
            "passed": grand_passed,
            "failed": grand_total - grand_passed,
            "resilience_score": round(grand_passed / grand_total, 4) if grand_total > 0 else 0.0,
        }
    except Exception:
        return {"by_type": {}, "total": 0, "passed": 0, "failed": 0, "resilience_score": 0.0}
    finally:
        db.close()


# ---------------------------------------------------------------------------
# RESEARCH LOOP HELPERS
# ---------------------------------------------------------------------------

def get_research_discoveries(limit: int = 50, offset: int = 0, category: str = None) -> list:
    """KnowledgeYield where company='research_loop', ordered by created_at desc."""
    db = SessionLocal()
    try:
        query = db.query(KnowledgeYield).filter(
            KnowledgeYield.company == "research_loop"
        )
        if category:
            query = query.filter(KnowledgeYield.fact_key == category)
        records = query.order_by(KnowledgeYield.timestamp.desc()).offset(offset).limit(limit).all()
        return [
            {
                "id": r.id,
                "category": r.fact_key,
                "finding": r.fact_value,
                "data_type": r.data_type,
                "confidence": r.confidence,
                "severity": r.context_data.get("severity", "medium") if r.context_data else "medium",
                "round": r.context_data.get("round", 0) if r.context_data else 0,
                "schema_score": r.context_data.get("schema_score") if r.context_data else None,
                "consistency_score": r.context_data.get("consistency_score") if r.context_data else None,
                "timestamp": r.timestamp.isoformat() if r.timestamp else None,
            }
            for r in records
        ]
    except Exception as e:
        logger.error(f"get_research_discoveries failed: {e}")
        return []
    finally:
        db.close()


def get_research_rounds(limit: int = 20) -> list:
    """EpisodicMemory where domain='think_tank', newest first. Full conversation in each."""
    db = SessionLocal()
    try:
        records = db.query(EpisodicMemory).filter(
            EpisodicMemory.domain == "think_tank"
        ).order_by(EpisodicMemory.created_at.desc()).limit(limit).all()

        result = []
        for r in records:
            import re
            match = re.search(r"Round (\d+)", r.goal or "")
            round_num = int(match.group(1)) if match else r.id
            thought = r.thought_log or {}
            cat = thought.get("category", {})
            result.append({
                "db_id": r.id,
                "round": round_num,
                "category": cat.get("id", "") if isinstance(cat, dict) else str(cat),
                "category_name": cat.get("name", "") if isinstance(cat, dict) else "",
                "threat_class": cat.get("threat_class", "") if isinstance(cat, dict) else "",
                "outcome": r.outcome,
                "turns": r.total_iterations,
                "lessons": r.lessons_learned,
                "conversation": r.action_history or [],
                "attack_payload": thought.get("attack_payload"),
                "attack_result": thought.get("attack_result", {}),
                "defense": thought.get("defense", ""),
                "timestamp": r.created_at.isoformat() if r.created_at else None,
            })
        return result
    except Exception as e:
        logger.error(f"get_research_rounds failed: {e}")
        return []
    finally:
        db.close()


def get_research_stats() -> dict:
    """Counts: total rounds, bypasses, defenses proposed."""
    db = SessionLocal()
    try:
        from sqlalchemy import func
        total_rounds = db.query(func.count(EpisodicMemory.id)).filter(
            EpisodicMemory.domain == "think_tank"
        ).scalar() or 0

        bypasses = db.query(func.count(EpisodicMemory.id)).filter(
            EpisodicMemory.domain == "think_tank",
            EpisodicMemory.outcome == "VULNERABLE",
        ).scalar() or 0

        defenses = db.query(func.count(EpisodicMemory.id)).filter(
            EpisodicMemory.domain == "think_tank",
            EpisodicMemory.outcome.in_(["DEFENDED", "PARTIAL"]),
        ).scalar() or 0

        discoveries = db.query(func.count(KnowledgeYield.id)).filter(
            KnowledgeYield.company == "research_loop"
        ).scalar() or 0

        return {
            "total_rounds": total_rounds,
            "bypasses": bypasses,
            "defenses_proposed": defenses,
            "discoveries": discoveries,
        }
    except Exception as e:
        logger.error(f"get_research_stats failed: {e}")
        return {"total_rounds": 0, "bypasses": 0, "defenses_proposed": 0, "discoveries": 0}
    finally:
        db.close()


def _summarize_action_history(action_history) -> str:
    """Summarize conversation action_history JSON for display."""
    if not action_history or not isinstance(action_history, list):
        return ""
    parts = []
    for entry in action_history[:4]:
        role = entry.get("role", "?")
        msg = (entry.get("message", ""))[:80]
        tools = len(entry.get("tool_calls", []))
        tool_str = f" [{tools} tools]" if tools else ""
        parts.append(f"[{role}]{tool_str}: {msg}")
    return " | ".join(parts)


# ---------------------------------------------------------------------------
# REGISTRATION CHALLENGE helpers (Phase A)
# ---------------------------------------------------------------------------

def save_registration_challenge(
    challenge_id: str,
    agent_id: str,
    nonce: str,
    public_key: str,
    role: str = "DATA_CONSUMER",
    display_name: str = "",
    capabilities: list = None,
    expires_at: "datetime" = None,
) -> "RegistrationChallenge":
    """Creates a registration challenge for agent identity verification."""
    db = SessionLocal()
    try:
        record = RegistrationChallenge(
            id=challenge_id,
            agent_id=agent_id,
            nonce=nonce,
            public_key=public_key,
            role=role,
            display_name=display_name or agent_id,
            capabilities=capabilities or [],
            status="PENDING",
            expires_at=expires_at or (datetime.utcnow() + timedelta(minutes=10)),
        )
        db.add(record)
        db.commit()
        db.refresh(record)
        return record
    except Exception as e:
        db.rollback()
        logger.error("RegistrationChallenge save failed: %s", e)
        raise
    finally:
        db.close()


def get_registration_challenge(challenge_id: str) -> dict:
    """Looks up a registration challenge by ID."""
    db = SessionLocal()
    try:
        record = db.query(RegistrationChallenge).filter(
            RegistrationChallenge.id == challenge_id
        ).first()
        if not record:
            return {}
        return {
            "id": record.id,
            "agent_id": record.agent_id,
            "nonce": record.nonce,
            "public_key": record.public_key,
            "role": record.role,
            "display_name": record.display_name,
            "capabilities": record.capabilities or [],
            "status": record.status,
            "expires_at": record.expires_at.isoformat() if record.expires_at else "",
            "created_at": record.created_at.isoformat() if record.created_at else "",
        }
    finally:
        db.close()


def complete_registration_challenge(challenge_id: str) -> bool:
    """Marks a registration challenge as COMPLETED."""
    db = SessionLocal()
    try:
        record = db.query(RegistrationChallenge).filter(
            RegistrationChallenge.id == challenge_id
        ).first()
        if not record:
            return False
        record.status = "COMPLETED"
        db.commit()
        return True
    except Exception as e:
        db.rollback()
        logger.error("complete_registration_challenge failed: %s", e)
        return False
    finally:
        db.close()


# ---------------------------------------------------------------------------
# TRUST DECAY helpers (Phase E)
# ---------------------------------------------------------------------------

def ensure_agent_verification_columns():
    """Adds last_active_at column to agent_verifications if missing."""
    try:
        from sqlalchemy import text as sa_text
        db = SessionLocal()
        try:
            db.execute(sa_text(
                "ALTER TABLE agent_verifications ADD COLUMN IF NOT EXISTS "
                "last_active_at TIMESTAMP"
            ))
            db.commit()
        except Exception:
            db.rollback()
        finally:
            db.close()
    except Exception as e:
        logger.warning("ensure_agent_verification_columns skipped: %s", e)


def update_agent_last_active(agent_id: str) -> bool:
    """Touch last_active_at on every submission."""
    db = SessionLocal()
    try:
        record = db.query(AgentVerification).filter(
            AgentVerification.agent_id == agent_id,
            AgentVerification.verdict != "PENDING",
        ).order_by(AgentVerification.verified_at.desc()).first()
        if not record:
            return False
        try:
            record.last_active_at = datetime.utcnow()
        except Exception:
            pass  # Column may not exist yet
        db.commit()
        return True
    except Exception:
        db.rollback()
        return False
    finally:
        db.close()


def get_agents_for_decay(inactive_days: int = 7) -> list:
    """Returns agents inactive longer than inactive_days."""
    db = SessionLocal()
    try:
        from sqlalchemy import text as sa_text
        cutoff = datetime.utcnow() - timedelta(days=inactive_days)
        # Use raw SQL since last_active_at may be added via ALTER
        rows = db.execute(sa_text(
            "SELECT agent_id, trust_score, last_active_at FROM agent_verifications "
            "WHERE verdict NOT IN ('PENDING', 'MALICIOUS') "
            "AND trust_score > 0.10 "
            "AND (last_active_at IS NULL OR last_active_at < :cutoff) "
            "ORDER BY last_active_at ASC"
        ), {"cutoff": cutoff}).fetchall()
        return [{"agent_id": r[0], "trust_score": r[1], "last_active_at": r[2]} for r in rows]
    except Exception as e:
        logger.warning(f"get_agents_for_decay failed: {e}")
        return []
    finally:
        db.close()


def apply_trust_decay(agent_id: str, new_score: float, reason: str) -> bool:
    """Applies trust decay: updates score + records in TrustScoreHistory."""
    db = SessionLocal()
    try:
        record = db.query(AgentVerification).filter(
            AgentVerification.agent_id == agent_id,
            AgentVerification.verdict != "PENDING",
        ).order_by(AgentVerification.verified_at.desc()).first()
        if not record:
            return False
        old_score = record.trust_score
        record.trust_score = max(0.0, new_score)
        db.commit()
        # Record in history
        save_trust_score_history(
            agent_id=agent_id,
            previous_score=old_score,
            new_score=max(0.0, new_score),
            reason=reason,
            event_type="decay",
        )
        return True
    except Exception as e:
        db.rollback()
        logger.error("apply_trust_decay failed: %s", e)
        return False
    finally:
        db.close()


def get_agent_rejection_rate(agent_id: str, last_n: int = 20) -> float:
    """Returns % of REJECTED verdicts in the last N submissions for an agent."""
    db = SessionLocal()
    try:
        results = db.query(VerificationResult).filter(
            VerificationResult.agent_id == agent_id,
        ).order_by(VerificationResult.created_at.desc()).limit(last_n).all()
        if not results:
            return 0.0
        rejected = sum(1 for r in results if r.verdict == "REJECTED")
        return rejected / len(results)
    except Exception:
        return 0.0
    finally:
        db.close()


def get_agent_sandbox_graduation(agent_id: str) -> dict:
    """Checks if an agent has passed sandbox requirements for live key upgrade."""
    db = SessionLocal()
    try:
        sessions = db.query(SandboxSession).filter(
            SandboxSession.agent_id == agent_id,
            SandboxSession.status == "completed",
        ).all()
        if not sessions:
            return {"passed": False, "best_resilience_score": 0.0, "sessions_completed": 0}
        best_score = 0.0
        for sess in sessions:
            attacks = db.query(SandboxAttackResult).filter(
                SandboxAttackResult.session_id == sess.id
            ).all()
            if attacks:
                passed = sum(1 for a in attacks if a.passed)
                score = passed / len(attacks)
                best_score = max(best_score, score)
        return {
            "passed": best_score >= 0.5,
            "best_resilience_score": round(best_score, 4),
            "sessions_completed": len(sessions),
        }
    except Exception as e:
        logger.warning("get_agent_sandbox_graduation failed: %s", e)
        return {"passed": False, "best_resilience_score": 0.0, "sessions_completed": 0}
    finally:
        db.close()


def revoke_agent_live_keys(agent_id: str) -> int:
    """Revokes all live_sk_ keys for an agent. Returns count revoked."""
    db = SessionLocal()
    try:
        keys = db.query(PersistentAPIKey).filter(
            PersistentAPIKey.agent_id == agent_id,
            PersistentAPIKey.is_active == True,
            PersistentAPIKey.key_id.like("live_sk_%"),
        ).all()
        count = 0
        for k in keys:
            k.is_active = False
            count += 1
        db.commit()
        if count:
            logger.info("Revoked %s live keys for agent %s", count, agent_id)
        return count
    except Exception as e:
        db.rollback()
        logger.error("revoke_agent_live_keys failed: %s", e)
        return 0
    finally:
        db.close()


# ---------------------------------------------------------------------------
# PEER REPORTING helpers (Phase F)
# ---------------------------------------------------------------------------

def save_agent_report(
    reporter_id: str,
    target_id: str,
    reason: str,
    evidence: str = "",
) -> "AgentReport":
    """Creates a peer report against an agent."""
    db = SessionLocal()
    try:
        record = AgentReport(
            reporter_id=reporter_id,
            target_id=target_id,
            reason=reason,
            evidence=evidence or "",
        )
        db.add(record)
        db.commit()
        db.refresh(record)
        logger.info("AgentReport created: %s -> %s (%s)", reporter_id, target_id, reason)
        return record
    except Exception as e:
        db.rollback()
        logger.error("AgentReport save failed: %s", e)
        raise
    finally:
        db.close()


def get_reports_against(target_id: str, status: str = None) -> list:
    """Returns reports filed against an agent."""
    db = SessionLocal()
    try:
        query = db.query(AgentReport).filter(AgentReport.target_id == target_id)
        if status:
            query = query.filter(AgentReport.status == status)
        records = query.order_by(AgentReport.created_at.desc()).all()
        return [
            {
                "id": r.id,
                "reporter_id": r.reporter_id,
                "target_id": r.target_id,
                "reason": r.reason,
                "evidence": r.evidence,
                "status": r.status,
                "created_at": r.created_at.isoformat() if r.created_at else "",
            }
            for r in records
        ]
    finally:
        db.close()


def count_unique_reporters(target_id: str) -> int:
    """Counts unique agents that have reported a target (OPEN reports only)."""
    db = SessionLocal()
    try:
        from sqlalchemy import func
        count = db.query(func.count(func.distinct(AgentReport.reporter_id))).filter(
            AgentReport.target_id == target_id,
            AgentReport.status == "OPEN",
        ).scalar()
        return count or 0
    finally:
        db.close()


def has_reported(reporter_id: str, target_id: str) -> bool:
    """Checks if reporter has already filed an OPEN report against target."""
    db = SessionLocal()
    try:
        exists = db.query(AgentReport).filter(
            AgentReport.reporter_id == reporter_id,
            AgentReport.target_id == target_id,
            AgentReport.status == "OPEN",
        ).first()
        return exists is not None
    finally:
        db.close()


def get_reporter_false_report_rate(reporter_id: str) -> float:
    """Returns the fraction of a reporter's reports that were dismissed."""
    db = SessionLocal()
    try:
        total = db.query(AgentReport).filter(
            AgentReport.reporter_id == reporter_id,
        ).count()
        if total == 0:
            return 0.0
        dismissed = db.query(AgentReport).filter(
            AgentReport.reporter_id == reporter_id,
            AgentReport.status == "DISMISSED",
        ).count()
        return dismissed / total
    finally:
        db.close()


# ---------------------------------------------------------------------------
# CART — Vulnerability & Countermeasure Helpers
# ---------------------------------------------------------------------------

def save_vulnerability(
    vuln_id: str, round_number: int, threat_category: str, threat_class: str,
    attack_payload: dict, attack_description: str,
    layers_bypassed: list, layers_caught: list, full_stack_result: dict,
    severity_score: float, severity_label: str,
    exploitability: float, impact: float,
) -> Vulnerability:
    db = SessionLocal()
    try:
        vuln = Vulnerability(
            vuln_id=vuln_id, round_number=round_number,
            threat_category=threat_category, threat_class=threat_class,
            attack_payload=attack_payload, attack_description=attack_description,
            layers_bypassed=layers_bypassed, layers_caught=layers_caught,
            full_stack_result=full_stack_result,
            severity_score=severity_score, severity_label=severity_label,
            exploitability=exploitability, impact=impact,
        )
        db.add(vuln)
        db.commit()
        db.refresh(vuln)
        return vuln
    finally:
        db.close()


def save_countermeasure(
    cm_id: str, pattern_type: str, pattern_value: str,
    target_layer: str, description: str, status: str = "PROPOSED",
) -> Countermeasure:
    db = SessionLocal()
    try:
        cm = Countermeasure(
            cm_id=cm_id, pattern_type=pattern_type,
            pattern_value=pattern_value, target_layer=target_layer,
            description=description, status=status,
            deployed_at=datetime.utcnow() if status == "DEPLOYED" else None,
        )
        db.add(cm)
        db.commit()
        db.refresh(cm)
        return cm
    finally:
        db.close()


def link_vulnerability_countermeasure(vuln_id: str, cm_db_id: int):
    db = SessionLocal()
    try:
        vuln = db.query(Vulnerability).filter(Vulnerability.vuln_id == vuln_id).first()
        if vuln:
            vuln.countermeasure_id = cm_db_id
            vuln.status = "MITIGATED"
            vuln.mitigated_at = datetime.utcnow()
            db.commit()
    finally:
        db.close()


def get_vulnerabilities(status: str = None, severity: str = None, threat_class: str = None, limit: int = 50, offset: int = 0) -> list:
    db = SessionLocal()
    try:
        query = db.query(Vulnerability)
        if status:
            query = query.filter(Vulnerability.status == status)
        if severity:
            query = query.filter(Vulnerability.severity_label == severity)
        if threat_class:
            query = query.filter(Vulnerability.threat_class == threat_class)
        records = query.order_by(Vulnerability.created_at.desc()).offset(offset).limit(limit).all()
        return [
            {
                "id": r.id, "vuln_id": r.vuln_id, "round_number": r.round_number,
                "threat_category": r.threat_category, "threat_class": r.threat_class,
                "severity_score": r.severity_score, "severity_label": r.severity_label,
                "exploitability": r.exploitability, "impact": r.impact,
                "layers_bypassed": r.layers_bypassed or [],
                "layers_caught": r.layers_caught or [],
                "status": r.status,
                "countermeasure_id": r.countermeasure_id,
                "attack_description": (r.attack_description or "")[:200],
                "created_at": r.created_at.isoformat() if r.created_at else None,
                "mitigated_at": r.mitigated_at.isoformat() if r.mitigated_at else None,
            }
            for r in records
        ]
    except Exception as e:
        logger.error(f"get_vulnerabilities failed: {e}")
        return []
    finally:
        db.close()


def get_countermeasures(status: str = None, limit: int = 50, offset: int = 0) -> list:
    db = SessionLocal()
    try:
        query = db.query(Countermeasure)
        if status:
            query = query.filter(Countermeasure.status == status)
        records = query.order_by(Countermeasure.created_at.desc()).offset(offset).limit(limit).all()
        return [
            {
                "id": r.id, "cm_id": r.cm_id,
                "pattern_type": r.pattern_type,
                "pattern_value": r.pattern_value[:200],
                "target_layer": r.target_layer,
                "description": (r.description or "")[:200],
                "true_positives": r.true_positives, "false_positives": r.false_positives,
                "true_negatives": r.true_negatives, "false_negatives": r.false_negatives,
                "status": r.status,
                "deployed_at": r.deployed_at.isoformat() if r.deployed_at else None,
                "created_at": r.created_at.isoformat() if r.created_at else None,
            }
            for r in records
        ]
    except Exception as e:
        logger.error(f"get_countermeasures failed: {e}")
        return []
    finally:
        db.close()



# ---------------------------------------------------------------------------
# AGENT PASSPORT helpers
# ---------------------------------------------------------------------------

def save_agent_passport(
    passport_id: str,
    agent_id: str,
    jwt_token: str,
    crypto_hash: str = "",
    trust_score: float = 0.0,
    verdict: str = "TRUSTED",
    proof_hash: str = "",
    tx_hash: str = "",
    expires_at: datetime = None,
    interaction_budget: int = 100,
    interaction_budget_max: int = 100,
) -> "AgentPassportRecord":
    """Save an issued Agent Passport to the database."""
    db = SessionLocal()
    try:
        record = AgentPassportRecord(
            passport_id=passport_id,
            agent_id=agent_id,
            jwt_token=jwt_token,
            crypto_hash=crypto_hash,
            trust_score=trust_score,
            verdict=verdict,
            proof_hash=proof_hash,
            tx_hash=tx_hash,
            expires_at=expires_at,
            interaction_budget=interaction_budget,
            interaction_budget_max=interaction_budget_max,
        )
        db.add(record)
        db.commit()
        db.refresh(record)
        logger.info("AgentPassport saved: %s for %s", passport_id, agent_id)
        return record
    except Exception as e:
        db.rollback()
        logger.error("AgentPassport save failed: %s", e)
        raise
    finally:
        db.close()


def get_agent_passport(agent_id: str) -> dict:
    """Get the latest non-revoked passport for an agent."""
    db = SessionLocal()
    try:
        record = db.query(AgentPassportRecord).filter(
            AgentPassportRecord.agent_id == agent_id,
            AgentPassportRecord.revoked == False,
        ).order_by(AgentPassportRecord.issued_at.desc()).first()
        if not record:
            return {}
        return {
            "passport_id": record.passport_id,
            "agent_id": record.agent_id,
            "jwt_token": record.jwt_token,
            "crypto_hash": record.crypto_hash,
            "trust_score": record.trust_score,
            "verdict": record.verdict,
            "proof_hash": record.proof_hash,
            "tx_hash": record.tx_hash,
            "issued_at": record.issued_at.isoformat() if record.issued_at else "",
            "expires_at": record.expires_at.isoformat() if record.expires_at else "",
            "revoked": record.revoked,
            "interaction_budget": record.interaction_budget if record.interaction_budget is not None else 100,
            "interaction_budget_max": record.interaction_budget_max if record.interaction_budget_max is not None else 100,
            "budget_exhausted_at": record.budget_exhausted_at.isoformat() if record.budget_exhausted_at else None,
            "budget_refreshed_count": record.budget_refreshed_count or 0,
        }
    finally:
        db.close()


def get_passport_by_id(passport_id: str) -> dict:
    """Get a passport by its passport_id."""
    db = SessionLocal()
    try:
        record = db.query(AgentPassportRecord).filter(
            AgentPassportRecord.passport_id == passport_id,
        ).first()
        if not record:
            return {}
        return {
            "passport_id": record.passport_id,
            "agent_id": record.agent_id,
            "jwt_token": record.jwt_token,
            "crypto_hash": record.crypto_hash,
            "trust_score": record.trust_score,
            "verdict": record.verdict,
            "proof_hash": record.proof_hash,
            "tx_hash": record.tx_hash,
            "issued_at": record.issued_at.isoformat() if record.issued_at else "",
            "expires_at": record.expires_at.isoformat() if record.expires_at else "",
            "revoked": record.revoked,
            "interaction_budget": record.interaction_budget if record.interaction_budget is not None else 100,
            "interaction_budget_max": record.interaction_budget_max if record.interaction_budget_max is not None else 100,
            "budget_exhausted_at": record.budget_exhausted_at.isoformat() if record.budget_exhausted_at else None,
            "budget_refreshed_count": record.budget_refreshed_count or 0,
        }
    finally:
        db.close()


def revoke_passport(passport_id: str) -> bool:
    """Revoke a passport by marking it as revoked."""
    db = SessionLocal()
    try:
        record = db.query(AgentPassportRecord).filter(
            AgentPassportRecord.passport_id == passport_id,
        ).first()
        if not record:
            return False
        record.revoked = True
        db.commit()
        logger.info("AgentPassport revoked: %s", passport_id)
        return True
    except Exception as e:
        db.rollback()
        logger.error("AgentPassport revoke failed: %s", e)
        return False
    finally:
        db.close()


def update_passport_budget(passport_id: str, remaining: int) -> bool:
    """Update the interaction budget for a passport. Returns True on success."""
    db = SessionLocal()
    try:
        record = db.query(AgentPassportRecord).filter(
            AgentPassportRecord.passport_id == passport_id,
        ).first()
        if not record:
            return False
        record.interaction_budget = max(0, remaining)
        record.last_budget_sync = datetime.utcnow()
        if remaining <= 0 and not record.budget_exhausted_at:
            record.budget_exhausted_at = datetime.utcnow()
        db.commit()
        return True
    except Exception as e:
        db.rollback()
        logger.error("Budget update failed for %s: %s", passport_id, e)
        return False
    finally:
        db.close()


def get_security_posture() -> dict:
    db = SessionLocal()
    try:
        from sqlalchemy import func

        # Vulnerability counts by severity
        severity_counts = {}
        for label in ("CRITICAL", "HIGH", "MEDIUM", "LOW"):
            count = db.query(func.count(Vulnerability.id)).filter(
                Vulnerability.status == "OPEN",
                Vulnerability.severity_label == label,
            ).scalar() or 0
            severity_counts[label] = count

        total_open = sum(severity_counts.values())
        total_mitigated = db.query(func.count(Vulnerability.id)).filter(
            Vulnerability.status == "MITIGATED"
        ).scalar() or 0
        total_vulns = db.query(func.count(Vulnerability.id)).scalar() or 0

        # Countermeasure stats
        deployed_cms = db.query(func.count(Countermeasure.id)).filter(
            Countermeasure.status == "DEPLOYED"
        ).scalar() or 0
        total_tp = db.query(func.sum(Countermeasure.true_positives)).filter(
            Countermeasure.status == "DEPLOYED"
        ).scalar() or 0
        total_fp = db.query(func.sum(Countermeasure.false_positives)).filter(
            Countermeasure.status == "DEPLOYED"
        ).scalar() or 0

        # Bypass rate — use Vulnerability table for bypasses, EpisodicMemory (think_tank only) for rounds
        # EpisodicMemory has 4 rows per round (1 think_tank + 3 per-agent), so filter domain=think_tank
        total_rounds = db.query(func.count(EpisodicMemory.id)).filter(
            EpisodicMemory.domain == "think_tank"
        ).scalar() or 0
        # Use actual Vulnerability records for bypass count (authoritative, 1 per bypass)
        bypass_count = total_vulns  # Every vulnerability IS a bypass
        bypass_rate = round(bypass_count / max(total_rounds, 1), 4)

        # Leakiest layers — which layers get bypassed most
        leaky_layers = {}
        try:
            vulns_with_layers = db.query(Vulnerability.layers_bypassed).filter(
                Vulnerability.layers_bypassed.isnot(None)
            ).limit(200).all()
            for (layers,) in vulns_with_layers:
                if isinstance(layers, list):
                    for layer in layers:
                        leaky_layers[layer] = leaky_layers.get(layer, 0) + 1
        except Exception:
            pass

        return {
            "open_vulnerabilities": severity_counts,
            "total_open": total_open,
            "total_mitigated": total_mitigated,
            "total_vulnerabilities": total_vulns,
            "deployed_countermeasures": deployed_cms,
            "attacks_blocked": total_tp,
            "false_positives": total_fp,
            "bypass_rate": bypass_rate,
            "total_rounds": total_rounds,
            "leaky_layers": leaky_layers,
        }
    except Exception as e:
        logger.error(f"get_security_posture failed: {e}")
        return {
            "open_vulnerabilities": {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0},
            "total_open": 0, "total_mitigated": 0, "total_vulnerabilities": 0,
            "deployed_countermeasures": 0, "attacks_blocked": 0, "false_positives": 0,
            "bypass_rate": 0.0, "total_rounds": 0,
        }
    finally:
        db.close()


# ---------------------------------------------------------------------------
# ESCALATION & APPEAL HELPERS
# ---------------------------------------------------------------------------

def record_budget_strike(passport_id: str, agent_id: str) -> dict:
    """
    Increment post-exhaustion strikes on a passport.
    Returns {strikes, tier_triggered, escalation_tier}.
    tier_triggered is the tier boundary just crossed (1/2/3) or None.
    """
    db = SessionLocal()
    try:
        record = db.query(AgentPassportRecord).filter(
            AgentPassportRecord.passport_id == passport_id,
        ).first()
        if not record:
            return {"strikes": 0, "tier_triggered": None, "escalation_tier": 0, "error": "passport_not_found"}

        old_strikes = record.post_exhaustion_strikes or 0
        new_strikes = old_strikes + 1
        record.post_exhaustion_strikes = new_strikes

        # Determine if we just crossed a tier boundary
        tier_triggered = None
        if new_strikes == STRIKE_TIER_1:
            tier_triggered = 1
            record.escalation_tier = 1
        elif new_strikes == STRIKE_TIER_2:
            tier_triggered = 2
            record.escalation_tier = 2
        elif new_strikes >= STRIKE_TIER_3 and (record.escalation_tier or 0) < 3:
            tier_triggered = 3
            record.escalation_tier = 3
            record.escalation_locked_at = datetime.utcnow()

        db.commit()
        return {
            "strikes": new_strikes,
            "tier_triggered": tier_triggered,
            "escalation_tier": record.escalation_tier or 0,
            "agent_id": agent_id,
            "passport_id": passport_id,
        }
    except Exception as e:
        db.rollback()
        logger.error(f"record_budget_strike failed: {e}")
        return {"strikes": 0, "tier_triggered": None, "escalation_tier": 0, "error": str(e)}
    finally:
        db.close()


def save_agent_appeal(
    agent_id: str,
    reason: str = "",
    evidence: str = "",
    org_id: str = None,
    filing_api_key_id: str = None,
    escalation_tier: int = 0,
    strikes_at_filing: int = 0,
    trust_score_at_filing: float = 0.0,
    verdict_at_filing: str = "",
) -> dict:
    """Creates a PENDING appeal. Returns appeal dict."""
    import uuid
    db = SessionLocal()
    try:
        appeal_id = f"apl-{uuid.uuid4().hex[:12]}"
        appeal = AgentAppeal(
            appeal_id=appeal_id,
            agent_id=agent_id,
            org_id=org_id,
            filing_api_key_id=filing_api_key_id,
            reason=reason,
            evidence=evidence,
            escalation_tier=escalation_tier,
            strikes_at_filing=strikes_at_filing,
            trust_score_at_filing=trust_score_at_filing,
            verdict_at_filing=verdict_at_filing,
            status="PENDING",
        )
        db.add(appeal)
        db.commit()
        db.refresh(appeal)
        return {
            "appeal_id": appeal.appeal_id,
            "agent_id": appeal.agent_id,
            "status": appeal.status,
            "escalation_tier": appeal.escalation_tier,
            "strikes_at_filing": appeal.strikes_at_filing,
            "filed_at": appeal.filed_at.isoformat() if appeal.filed_at else "",
        }
    except Exception as e:
        db.rollback()
        logger.error(f"save_agent_appeal failed: {e}")
        raise
    finally:
        db.close()


def get_agent_appeal(appeal_id: str) -> dict:
    """Retrieve an appeal by ID."""
    db = SessionLocal()
    try:
        appeal = db.query(AgentAppeal).filter(
            AgentAppeal.appeal_id == appeal_id,
        ).first()
        if not appeal:
            return {}
        return {
            "appeal_id": appeal.appeal_id,
            "agent_id": appeal.agent_id,
            "org_id": appeal.org_id,
            "reason": appeal.reason,
            "evidence": appeal.evidence,
            "escalation_tier": appeal.escalation_tier,
            "strikes_at_filing": appeal.strikes_at_filing,
            "trust_score_at_filing": appeal.trust_score_at_filing,
            "verdict_at_filing": appeal.verdict_at_filing,
            "status": appeal.status,
            "filed_at": appeal.filed_at.isoformat() if appeal.filed_at else "",
            "resolved_at": appeal.resolved_at.isoformat() if appeal.resolved_at else None,
            "resolved_by": appeal.resolved_by,
            "resolution_notes": appeal.resolution_notes,
            "trust_score_restored_to": appeal.trust_score_restored_to,
            "passport_renewed": appeal.passport_renewed or False,
        }
    finally:
        db.close()


def resolve_agent_appeal(
    appeal_id: str,
    status: str,
    resolved_by: str = "admin",
    resolution_notes: str = "",
    trust_score_restored_to: float = None,
    passport_renewed: bool = False,
) -> dict:
    """Resolve an appeal (APPROVED or DENIED). Returns updated appeal dict."""
    db = SessionLocal()
    try:
        appeal = db.query(AgentAppeal).filter(
            AgentAppeal.appeal_id == appeal_id,
        ).first()
        if not appeal:
            return {}
        appeal.status = status
        appeal.resolved_at = datetime.utcnow()
        appeal.resolved_by = resolved_by
        appeal.resolution_notes = resolution_notes
        if trust_score_restored_to is not None:
            appeal.trust_score_restored_to = trust_score_restored_to
        appeal.passport_renewed = passport_renewed
        db.commit()
        return get_agent_appeal(appeal_id)
    except Exception as e:
        db.rollback()
        logger.error(f"resolve_agent_appeal failed: {e}")
        raise
    finally:
        db.close()


def list_agent_appeals(agent_id: str = None, status: str = None, limit: int = 50) -> list:
    """List appeals, optionally filtered by agent_id and/or status."""
    db = SessionLocal()
    try:
        query = db.query(AgentAppeal)
        if agent_id:
            query = query.filter(AgentAppeal.agent_id == agent_id)
        if status:
            query = query.filter(AgentAppeal.status == status)
        appeals = query.order_by(AgentAppeal.filed_at.desc()).limit(limit).all()
        return [
            {
                "appeal_id": a.appeal_id,
                "agent_id": a.agent_id,
                "status": a.status,
                "escalation_tier": a.escalation_tier,
                "strikes_at_filing": a.strikes_at_filing,
                "filed_at": a.filed_at.isoformat() if a.filed_at else "",
                "resolved_at": a.resolved_at.isoformat() if a.resolved_at else None,
            }
            for a in appeals
        ]
    finally:
        db.close()


def clear_passport_escalation(passport_id: str) -> bool:
    """Reset escalation state on a passport (after appeal approval)."""
    db = SessionLocal()
    try:
        record = db.query(AgentPassportRecord).filter(
            AgentPassportRecord.passport_id == passport_id,
        ).first()
        if not record:
            return False
        record.post_exhaustion_strikes = 0
        record.escalation_tier = 0
        record.escalation_locked_at = None
        db.commit()
        return True
    except Exception as e:
        db.rollback()
        logger.error(f"clear_passport_escalation failed: {e}")
        return False
    finally:
        db.close()


def get_passport_escalation(passport_id: str) -> dict:
    """Get current escalation state for a passport."""
    db = SessionLocal()
    try:
        record = db.query(AgentPassportRecord).filter(
            AgentPassportRecord.passport_id == passport_id,
        ).first()
        if not record:
            return {}
        return {
            "passport_id": passport_id,
            "agent_id": record.agent_id,
            "post_exhaustion_strikes": record.post_exhaustion_strikes or 0,
            "escalation_tier": record.escalation_tier or 0,
            "escalation_locked_at": record.escalation_locked_at.isoformat() if record.escalation_locked_at else None,
            "revoked": record.revoked,
        }
    finally:
        db.close()
