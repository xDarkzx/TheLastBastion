"""
Root database proxy: re-exports everything from core.database.
Ensures root-level scripts can 'from database import ...' without issues.
"""
from core.database import (
    Base, engine, SessionLocal, init_db,
    # Models
    Mission, Task, AgentState, Interaction, KnowledgeYield,
    IntelNode, GoldYield, SwarmTelemetry, UsageMetrics,
    WorkerRegistry, WorkerTelemetry, TacticalAdjustment,
    SwarmDeployment, RegionalProvider, ProductionTask,
    PricingHistory, ExtractionSchedule, StrategicProcess,
    # Functions
    save_process, get_all_processes,
    log_telemetry, update_worker_status, get_system_stats,
    claim_next_task, complete_task, save_pricing_data,
    verify_yield_integrity, commit_gold_yield, record_usage,
    init_vault,
)
