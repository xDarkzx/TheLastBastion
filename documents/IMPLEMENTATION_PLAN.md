# The Last Bastion Data Refinery — Implementation Plan
**Version**: 1.0 | **Date**: 2026-03-04 | **Status**: DRAFT (Updated: 2026-03-09)

---

## Build Order (Dependencies First)

### Phase 1: Ingestion Pipeline (Week 1)
> **Goal**: Accept raw data from any source, store with provenance

**New Files:**
- `core/ingestion.py` — `IngestPipeline` class
  - `accept(file_bytes, filename, source_id, metadata)` → `IngestResult`
  - Detects format (PDF, image, CSV, JSON, text)
  - Computes SHA-256 of raw input
  - Stores in `raw_submissions` table
  - Returns `{submission_id, data_hash, format_detected}`

- `core/document_intelligence.py` — `DocumentIntelligence` class
  - `extract_text(file_bytes, format)` → raw text
  - `extract_structured(raw_text, hints)` → structured JSON
  - Uses LLM for field mapping when schema unknown
  - OCR pipeline: DocTR/Tesseract for images
  - PDF extraction: pdfplumber for tables + text

**DB Changes (core/database.py):**
- `RawSubmission` model: id, data_hash, source_id, format, raw_bytes_path, metadata, status, created_at
- `CleanedData` model: id, submission_id, schema, structured_data, confidence, warnings, created_at

**API Endpoints (regional_core.py):**
- `POST /refinery/submit` — file upload + metadata
- `GET /refinery/status/{submission_id}` — processing status

**Dependencies:** `pdfplumber`, `doctr` or `pytesseract`, `Pillow`

---

### Phase 2: Verification Stack (Week 2-3)
> **Goal**: 5-layer autonomous verification with confidence scoring

**New Files:**
- `core/verification_stack.py` — `VerificationStack` class
  - `verify(cleaned_data, playbook)` → `VerificationResult`
  - Layer 1: Schema validation (existing `validate_output`)
  - Layer 2: Internal consistency (new — statistical checks, range validation)
  - Layer 3: Cross-reference (existing `APIExtractor` + web verification)
  - Layer 4: Temporal analysis (existing `EpisodicMemory` patterns)
  - Layer 5: Adversarial audit (existing `AdversarialAuditor` + `ConsensusEngine`)

**DB Changes:**
- `VerificationResult` model: id, submission_id, layer_scores (JSON), composite_score, verdict, details, created_at
- `DataQuarantine` model: id, submission_id, reason, resolution_status, resolved_at

**Verdict Classification:**
```
score < 40   → REJECTED  (submitter notified, data discarded)
40 ≤ s < 70  → QUARANTINE (held, not stamped, awaiting corroboration)
70 ≤ s < 90  → VERIFIED  (stamped, standard confidence)
90 ≤ s       → GOLD      (stamped, highest trust)
```

**Playbook Evolution:**
- Existing `MissionPlaybook` repurposed: `extraction_mode` → `verification_mode`
- Playbooks define which verification layers apply to which data types
- Auto-generation: first verified data of a new type creates a verification playbook

---

### Phase 3: Blockchain Stamps (Week 4)
> **Goal**: Immutable on-chain proof of verification

**New Files:**
- `core/blockchain_stamp.py` — `BlockchainStamper` class
  - `stamp(data_hash, verification_hash, confidence)` → tx_hash
  - `lookup(data_hash)` → stamp_record or None
  - Uses Web3.py for smart contract interaction
  - Targets Polygon/Base L2 (< $0.001 per stamp)

- `contracts/DataStamp.sol` — Solidity smart contract
  - `stamp(bytes32 dataHash, bytes32 verificationHash, uint8 confidence)`
  - `lookup(bytes32 dataHash) → (timestamp, confidence, verifier)`
  - Minimal gas: stores only hashes, not data

**DB Changes:**
- `BlockchainStamp` model: id, submission_id, data_hash, verification_hash, tx_hash, chain, block_number, confidence, created_at

**API Endpoints:**
- `GET /refinery/verify/{data_hash}` — on-chain lookup (read-only, no gas)
- `GET /refinery/proof/{submission_id}` — full verification proof + stamp

**Dependencies:** `web3`, smart contract deployment tools

---

### Phase 4: MCP/M2M Gateway (Week 5)
> **Goal**: Standard protocol interface for machine-to-machine data exchange

**New Files:**
- `core/mcp_server.py` — MCP protocol server
  - Exposes verified data as MCP resources
  - Accepts data submissions via MCP tools
  - Authentication via API keys or bearer tokens

**API Endpoints:**
- `POST /refinery/bulk` — batch submission (up to 100 items)
- `GET /refinery/feed` — streaming verified data feed (WebSocket)
- Full MCP tool/resource interface

---

### Phase 5: Calibration Mode (Week 5-6)
> **Goal**: Human calibration UI for tuning confidence thresholds

- Dashboard showing quarantined data with layer-by-layer scores
- Human reviewer: APPROVE (promote to verified) or REJECT (discard)
- Each decision feeds back into confidence threshold calibration
- After 500 calibrations → system runs autonomously
- Statistical monitoring: reversal rate alerts

---

## What Stays Unchanged

| System | Status |
|---|---|
| PostgreSQL + Redis backbone | ✅ No changes |
| Docker containerization | ✅ No changes |
| LLM Client (Ollama/Groq) | ✅ No changes |
| HiveSupervisor fleet management | ✅ No changes |
| GraphOrchestrator pipeline | ✅ Verification becomes the pipeline |
| Proof-of-Task hashing | ✅ Foundation for stamps |
| PlaybookScheduler | ✅ Handles re-verification scheduling |
| LessonsEngine | ✅ Learns verification methods |
| EpisodicMemory | ✅ Verification history for temporal checks |
| FastAPI surface | ✅ New endpoints added alongside existing |

## Verification Plan

### After Phase 1
- Submit PDF, image, CSV → confirm structured JSON output
- Test phase 14: Ingestion

### After Phase 2
- Submit known-good data → confirm VERIFIED/GOLD verdict
- Submit known-bad data → confirm REJECTED
- Submit ambiguous data → confirm QUARANTINE
- Test phase 15: Verification Stack

### After Phase 3
- Stamp verified data → confirm on-chain record
- Lookup stamped data → confirm instant response
- Test phase 16: Blockchain

### After Phase 4
- M2M submission via MCP → full pipeline → stamp
- Test phase 17: End-to-end
