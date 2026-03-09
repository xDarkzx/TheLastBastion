# The Last Bastion Data Refinery — System Architecture
**Version**: 1.0 | **Date**: 2026-03-04 | **Status**: DRAFT (Updated: 2026-03-09)

---

## 1. System Overview

```
┌─────────────────────────────────────────────────────────────────┐
│                    The Last Bastion Data Refinery                        │
│                                                                 │
│  ┌──────────┐  ┌──────────┐  ┌──────────┐  ┌───────┐  ┌──────┐│
│  │  INGEST  │→ │  CLEAN   │→ │  VERIFY  │→ │ STAMP │→ │ SERVE││
│  │          │  │          │  │ (5-Layer)│  │       │  │      ││
│  └──────────┘  └──────────┘  └──────────┘  └───────┘  └──────┘│
│       ↑                           ↕                       ↑    │
│  ┌──────────┐              ┌──────────┐             ┌──────────┐│
│  │ MCP/M2M  │              │ Playbooks│             │Blockchain││
│  │ Gateway  │              │ + Lessons│             │  Ledger  ││
│  └──────────┘              └──────────┘             └──────────┘│
└─────────────────────────────────────────────────────────────────┘
```

## 2. Pipeline Stages

### Stage 1: INGEST
Accepts raw data from any source via MCP protocol, REST API, or file upload.

**Supported Formats:**
| Format | Handler | Output |
|---|---|---|
| PDF | `pdfplumber` / `PyMuPDF` | Extracted text + tables |
| Image/Photo | `DocTR` / `Tesseract` OCR | Recognized text |
| CSV/Excel | `pandas` | Structured rows |
| JSON/API dump | Direct parse | Structured dict |
| Free text | LLM extraction | Structured dict |

**New Module**: `core/ingestion.py`
- `IngestPipeline.accept(file, source_id, metadata)` → returns `IngestResult`
- Assigns a unique `data_hash` (SHA-256 of raw input)
- Records source provenance (who submitted, when, via what protocol)
- Stores raw input in `raw_data` table for audit trail

### Stage 2: CLEAN
Transforms raw extracted content into normalized, schema-conformant JSON.

**New Module**: `core/document_intelligence.py`
- OCR pipeline for images → text → structured fields
- PDF table extraction → normalized rows
- LLM-assisted field mapping: "which field is the price? the date? the entity?"
- Schema inference: auto-detects data type from content patterns
- Outputs: `CleanedData(schema, fields, confidence, warnings)`

### Stage 3: VERIFY (5-Layer Stack)
The core differentiator. Each layer runs independently and contributes to a composite confidence score.

**Existing Modules (reused):**
- `core/truth_engine.py` — ConsensusEngine (Layer 3, 5)
- `core/auditor.py` — AdversarialAuditor (Layer 5)
- `core/playbook_engine.py` — Verification playbooks
- `core/api_extractor.py` — Cross-reference API calls (Layer 3)

**New Module**: `core/verification_stack.py`

```python
class VerificationStack:
    async def verify(self, data: CleanedData) -> VerificationResult:
        score = 0.0

        # L1: Schema (is it structurally valid?)
        l1 = self.check_schema(data)           # +10%

        # L2: Internal Consistency (do the numbers add up?)
        l2 = self.check_consistency(data)      # +15%

        # L3: Cross-Reference (confirm against 2+ sources)
        l3 = await self.cross_reference(data)  # +30%

        # L4: Temporal (matches historical patterns?)
        l4 = self.check_temporal(data)         # +15%

        # L5: Adversarial Audit (agent tries to disprove)
        l5 = await self.adversarial_audit(data)# +30%

        score = l1 + l2 + l3 + l4 + l5
        verdict = self.classify(score)
        # REJECTED (<40%) | QUARANTINE (40-69%) | VERIFIED (70-89%) | GOLD (90%+)

        return VerificationResult(score, verdict, layers=[l1,l2,l3,l4,l5])
```

### Stage 4: STAMP
Creates an immutable proof-of-verification on-chain.

**New Module**: `core/blockchain_stamp.py`
- Generates stamp: `{data_hash, verification_hash, timestamp, confidence, method}`
- Writes to smart contract on L2 chain (Polygon/Base/Arbitrum)
- **Only writes for VERIFIED (70%+) or GOLD (90%+) data**
- Quarantined data → NOT stamped, held for future corroboration
- Rejected data → NOT stamped, submitter notified

**On-chain record (minimal gas):**
```solidity
struct DataStamp {
    bytes32 dataHash;         // SHA-256 of verified data
    bytes32 verificationHash; // SHA-256 of verification proof
    uint64  timestamp;
    uint8   confidence;       // 0-100
    address verifier;         // The Last Bastion's address
}
```

### Stage 5: SERVE
Provides verified data to M2M/MCP consumers.

**Endpoints (added to `regional_core.py`):**
| Endpoint | Method | Purpose |
|---|---|---|
| `/refinery/submit` | POST | Submit raw data for verification |
| `/refinery/status/{hash}` | GET | Check verification status |
| `/refinery/data/{hash}` | GET | Retrieve verified data + proof |
| `/refinery/verify/{hash}` | GET | Quick on-chain stamp lookup |
| `/refinery/bulk` | POST | Batch submission |

## 3. Data Model Additions

```
raw_submissions        — Source provenance + raw bytes
cleaned_data           — Normalized JSON + schema
verification_results   — 5-layer scores + composite
blockchain_stamps      — On-chain tx hash + stamp data
data_quarantine        — Held data pending corroboration
```

## 4. Existing Systems — Reuse Map

| Existing System | New Role |
|---|---|
| MissionPlaybook | **Verification Playbook** — defines how to verify a data type |
| APIExtractor | **Cross-Reference Engine** — calls external APIs for Layer 3 |
| TruthEngine + Consensus | **Layer 5** — multi-agent adversarial verification |
| AdversarialAuditor | **Layer 5** — structural diff + challenge |
| Proof-of-Task | **Stamp Foundation** — SHA-256 hashing |
| PlaybookScheduler | **Re-verification scheduler** — periodic audits |
| LessonsEngine | **Verification learning** — improves methods per data type |
| EpisodicMemory | **Verification history** — context for temporal checks |
| GraphOrchestrator | **Verification pipeline** — runs the 5 layers as a DAG |

## 5. What's NOT Changing
- Docker architecture (containerized workers)
- PostgreSQL + Redis backbone
- LLM client (Ollama/Groq)
- FastAPI surface
- Agent daemon structure
- HiveSupervisor fleet management
