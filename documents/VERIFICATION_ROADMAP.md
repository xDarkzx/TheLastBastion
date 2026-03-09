# Verification Roadmap

Comprehensive analysis of The Last Bastion's verification systems -- what works, what doesn't, and what to build next.

Last updated: 2026-03-06

---

## 1. Agent Verification -- What We Verify and Why

File: `core/agent_verifier.py`

When an external agent registers with The Last Bastion or requests trust verification, we run a 6-check pipeline to produce a trust verdict: **TRUSTED** (>= 0.60), **SUSPICIOUS** (0.30-0.60), or **MALICIOUS** (< 0.30).

### The 6 Checks

| # | Check | What It Does Now | Status |
|---|-------|-----------------|--------|
| 1 | **Identity** | Validates agent_id length (>= 3), agent_name presence, URL validity (HTTP/HTTPS with HTTPS bonus), metadata completeness. Scores 0.0-1.0 based on field presence. | **Basic but functional.** Only checks presence, not truthfulness. Does not verify the URL actually resolves or that the identity is unique. |
| 2 | **Cryptographic** | Checks if a public key is provided. Validates format: Ed25519 (64 hex chars) gets 1.0, PEM format gets 0.9, any key >= 32 chars gets 0.6, no key gets 0.2. | **Format-only.** Does NOT verify the agent can actually sign with this key. No challenge-response. No signature verification against submitted data. This is the biggest gap. |
| 3 | **Capabilities** | Checks declared capabilities against a known set of 9 valid capability strings. Penalizes excessive declarations (> 20). Ratio of known/total drives score. | **Reasonable.** But capabilities are self-declared and never tested. An agent claiming "data_extraction" is never asked to prove it. |
| 4 | **Reputation** | Analyzes `history` list for success/failure rates. New agents get 0.5 (neutral). High failure rate (> 50%) drops score. | **Works if history is provided.** Problem: history is self-reported by the agent. We do not yet pull from our own DB of past interactions with this agent. |
| 5 | **Behavioral** | Scans metadata for: excessive registration attempts (> 5), suspicious keywords in description ("exploit", "bypass", "injection"), suspicious IP addresses (0.x.x.x, 127.0.0.1). | **Basic heuristic.** No actual behavioral analysis over time. No request pattern analysis. No anomaly detection. |
| 6 | **Network** | HTTPS bonus (+0.2), verified_domain metadata flag (+0.2), rate_limit_compliant flag (+0.1). Base 0.5. | **Placeholder-level.** Reads metadata flags that the agent sets itself. Does not actually verify domain ownership, check DNS, or test network behavior. |

### Critical Checks (Veto Power)

Identity and Cryptographic are marked as critical checks (`core/agent_verifier.py:116`). If either scores below 0.2, the verdict is forced to MALICIOUS regardless of other scores.

### What a Complete Agent Verification Would Need

1. **Challenge-response authentication** -- Send a nonce, agent signs it, we verify against their public key. This is the single most important missing piece. Without it, cryptographic check is theater.
2. **DB-backed reputation** -- Query our own `M2MTask` and `AgentVerification` tables for this agent's actual history, not their self-reported history.
3. **Domain verification** -- Actually fetch the agent's URL, check for a well-known verification file (like `.well-known/lastbastion-agent.json`), verify TLS certificate.
4. **Behavioral profiling** -- Track request patterns over time. Sudden spikes, unusual hours, rapid repeated submissions should flag.
5. **Cross-agent reputation** -- If agents A and B both submit data, and A's data is consistently REJECTED while B's is VERIFIED, that history should feed back into trust scores.

---

## 2. Payload Verification -- What We Verify and Why

Files: `core/verification/pipeline.py`, `core/verification/verification_stack.py`

Every data submission flows through the `VerificationPipeline`, which calls `VerificationOrchestrator.verify()`. The pipeline is structured as 2 gates + 3 pillars + 1 adversarial challenge.

### Gate 1: Schema Gatekeeper

File: `core/verification/schema_gatekeeper.py`

**What it checks:**
- Required field presence
- Type validation (STRING, INTEGER, FLOAT, BOOLEAN, DATE, DATETIME, EMAIL, URL, CURRENCY, PERCENTAGE, LIST, DICT)
- Range validation (min/max on numeric fields, default ranges for PERCENTAGE 0-100 and CURRENCY 0-1B)
- Allowed values (enum-style restrictions)
- Injection detection (8 regex patterns: XSS, SQL injection, template injection, Python injection)
- String length constraints

**Scoring:** `passed_checks / total_checks`. Injection triggers veto. All required fields missing triggers veto.

**Current behavior when no schema provided:** The gatekeeper is skipped entirely (`verification_stack.py:114-116`). The orchestrator logs "Gate 1 (Schema): skipped -- no schema provided" and moves on. This means most submissions bypass structural validation completely because callers rarely pass a `DataSchema` object.

### Gate 2: Consistency Analyzer

File: `core/verification/consistency.py`

**What it checks:**
- Arithmetic: subtotal + tax = total, quantity * unit_price = line_total, discount calculations
- Cross-field logic: start_date < end_date, dates not in future, percentage fields in 0-100
- Statistical anomalies: z-score against known distributions (only if `known_distributions` passed -- it never is in practice)
- Magnitude reasonableness: negative currency, very high prices (> $10,000)
- Duplicate values: flags when > 2 unrelated fields share the same non-zero numeric value

**Scoring:** `passed_checks / total_checks`. Hard arithmetic failures cap score at 0.3. Returns 0.5 ("no checks applicable") when no checks fire.

**Key limitation:** Most checks are pattern-matching on field names (e.g., looking for fields named "subtotal", "tax", "total"). If the payload uses different field names (e.g., "base_charge", "gst_component", "invoice_total"), none of the arithmetic checks trigger. The analyzer returns 0.5 (neutral) because zero checks ran.

### Pillar 1: Forensic Integrity (Weight: 0.30 with attestation, 0.40 without)

File: `core/verification/forensic_integrity.py`

**Orchestrates 8 sub-analyzers:**

| Analyzer | File | Supported Types | Dependencies | What It Does |
|----------|------|----------------|-------------|-------------|
| FileStructure | `analyzers/file_structure.py` | jpg, jpeg, png, gif, bmp, tiff, webp, pdf | None | Magic byte validation, polyglot/embedded executable detection |
| MetadataForensics | `analyzers/metadata_forensics.py` | jpg, jpeg, png, tiff, bmp, webp, pdf | None (PIL optional) | EXIF analysis, software detection (Photoshop etc), date consistency, file size checks |
| ELA | `analyzers/ela.py` | jpg, jpeg, png, bmp, tiff, webp | numpy, Pillow | Error Level Analysis -- detects regions re-saved at different compression levels |
| Noise | `analyzers/noise.py` | jpg, jpeg, png, bmp, tiff, webp | numpy, Pillow | Noise pattern consistency -- edited regions have different noise profiles |
| CopyMove | `analyzers/copy_move.py` | jpg, jpeg, png, bmp, tiff, webp | numpy, Pillow | Detects copy-paste cloning within an image |
| Lighting | `analyzers/lighting.py` | jpg, jpeg, png, bmp, tiff, webp | numpy, Pillow | Verifies lighting direction consistency across the image |
| FabricationDetector | `analyzers/fabrication_detector.py` | jpg, jpeg, png, bmp, tiff, webp | numpy, Pillow | Distinguishes camera photos from digitally fabricated images |
| PDFForensics | `analyzers/pdf_forensics.py` | pdf | None | PDF structure validation, JavaScript detection, producer/creator analysis |

**Key behavior:** When no attachments are provided, this entire pillar is skipped (`verification_stack.py:187-188`). Since most JSON API submissions have no file attachments, forensic integrity never runs for structured data.

**Suspicion correlation** (`forensic_integrity.py:223-274`): If all tamper-detection layers (ELA, noise, copy-move, lighting) score >= 0.88, a 0.15 penalty is applied. Real documents always have imperfections; too-perfect scores suggest digital fabrication.

### Pillar 2: Logic Triangulation (Weight: 0.45 with attestation, 0.60 without)

File: `core/verification/logic_triangulation.py`

**Orchestrates 3 strategies:**

| Strategy | File | What It Does |
|----------|------|-------------|
| DomainLogic | `triangulation/domain_logic.py` | Checks values against hardcoded domain ranges (e.g., NZ electricity 0.15-0.50 NZD/kWh), date validity, negative value detection, placeholder string detection, cross-claim arithmetic |
| TemporalConsistency | `triangulation/temporal.py` | Compares against historical values. Flags changes exceeding thresholds (50% for price, 30% for rate, 100% for quantity). Uses in-memory history store. |
| CrossReference | `triangulation/cross_reference.py` | Checks claims against previously verified data in an in-memory store. 5% tolerance for numeric comparison. |

**Scoring rules** (`logic_triangulation.py:155-170`):
- 0 confirmations, 0 contradictions = 0.00 (UNVERIFIABLE)
- 1 confirmation = 0.40 (WEAK)
- 2 confirmations = 0.75 (STRONG)
- 3+ confirmations = 0.90 (VERY STRONG)
- Any contradiction present = 0.20 (CONTESTED)
- Only contradictions = 0.00 (DISPROVED)

Final score blends 60% corroboration rules + 40% layer average.

**Key limitation:** Both TemporalConsistency and CrossReference use **in-memory stores** that start empty on every service restart. They are injectable (you can pass a `history_store` or `verified_store`), but the pipeline does not wire them to the database. So on a fresh boot, temporal = 0.5 (neutral), cross-reference = 0.5 (neutral). DomainLogic is the only strategy that works without accumulated state, but it only fires when field names match its hardcoded `DOMAIN_RANGES` keys.

### Pillar 3: Attestation (Weight: 0.25)

File: `core/verification/attestation.py`

**5 checks:**
- GPS plausibility: valid range, not null island (0,0), accuracy < 500m
- Temporal plausibility: timestamp parseable, not future, not stale (> 24h)
- Depth authenticity: depth variance > 0.01 (real paper vs flat screen)
- Device consistency: tracks device fingerprint across submissions, builds trust over repeated use
- Anti-replay: detects duplicate provenance hashes (in-memory set, lost on restart)

**Scoring:** 70% check results + 30% completeness bonus. Completeness = how many of 6 possible provenance fields are present.

**Key behavior:** Only runs when an `AttestationBundle` is provided (`verification_stack.py:220-244`). API submissions almost never include GPS, depth maps, or device fingerprints. When absent, attestation is skipped and weights redistribute: forensic goes from 0.30 to 0.40, triangulation goes from 0.45 to 0.60.

### Adversarial Challenge Agent

File: `core/verification/adversarial.py`

**5 challenges, each adding penalties:**
- Evidence sufficiency: penalizes pillars with high scores but < 2 evidence pieces (+0.05 penalty per)
- Score consistency: flags large gaps between pillar scores (> 0.4 difference) or gate-vs-pillar mismatches (+0.08 per)
- Perfect pattern detection: flags when >= 80% of layers score >= 0.9, or score std dev < 0.05 (+0.10 per)
- Confidence calibration: penalizes high-confidence evidence from weak sources (computation-only) (+0.06 per)
- Missing pillar coverage: penalizes when >= 2 of 3 pillars are missing (+0.05 per)

The adversarial penalty is subtracted from the final score (`verification_stack.py:353-356`).

### Verdict Scoring

| Score Range | Verdict | Action |
|------------|---------|--------|
| < 0.40 | REJECTED | `reject` -- do not store, flag agent |
| 0.40-0.70 | QUARANTINE | `quarantine` -- hold for human review |
| 0.70-0.90 | VERIFIED | `store_verified` -- store + blockchain stamp |
| >= 0.90 | GOLD | `store_gold` -- requires forensic >= 0.80 AND (attestation OR triangulation >= 0.85) |

**Veto rights:** Schema Gatekeeper (Gate 1), Logic Triangulation (Pillar 2 -- at 5+ contradictions). A veto forces score to 0.0 (REJECTED).

**Score computation** (`verification_stack.py:327-399`):
1. Weighted average of present pillars
2. Multiply by `min(1.0, pre_check_avg)` -- pre-checks can lower but not raise
3. Subtract adversarial penalty
4. Apply forensic floor (< 0.3 caps score at 0.15)
5. Apply triangulation veto (caps at 0.1)

**Critical path for "only pre-checks ran":** When no pillar data exists (no attachments, no claims matched), the formula at line 348 produces `score = pre_check_avg * 0.5`. Even with perfect pre-checks (1.0), the maximum score is **0.50** -- which is QUARANTINE. This is the most common path for JSON-only submissions.

---

## 3. Data Type Coverage -- What Can Actually Be Verified

### JSON Structured Data (supply chain records, financial data, energy pricing)

**What works:**
- Gate 2 (Consistency): Arithmetic checks fire IF field names match patterns (`subtotal`, `tax`, `total`, `quantity`, `unit_price`). Cross-field date logic works. Percentage range checks work.
- Pillar 2 (Triangulation/DomainLogic): Magnitude checks fire IF field names match `DOMAIN_RANGES` keys (electricity_price_kwh, gas_price_kwh, temperature, percentage, gst_rate, weight, distance). Placeholder detection works. Negative value detection works.

**What doesn't work:**
- Gate 1 (Schema): Skipped unless caller explicitly passes a `DataSchema` object. The auto-inferred schema (`_build_minimal_schema` at `verification_stack.py:402-437`) only infers types from Python types and marks all fields as `required=False`, so it does nothing useful for the gatekeeper since it's only used by the consistency analyzer.
- Pillar 1 (Forensic): Completely inapplicable. No files to analyze.
- Pillar 2 (Triangulation/Temporal + CrossRef): Empty stores. Return 0.5 neutral.
- Pillar 3 (Attestation): No bundle provided. Skipped.
- **Maximum achievable score for clean JSON: ~0.50** (QUARANTINE). The math: no pillars run, pre_check_avg (consistency) returns ~0.5 for "no checks applicable", so score = 0.5 * 0.5 = 0.25 before adversarial. In practice most JSON submissions score 0.10-0.35.

### CSV/Tabular Data

**Current flow:** CSV is parsed into JSON by `DocumentIntelligence` before reaching verification. Same limitations as JSON above. The tabular structure is lost -- column relationships, row consistency, and statistical properties of columns are not checked.

**What could work but doesn't:** Statistical anomaly detection in consistency analyzer accepts `known_distributions` but nobody passes them.

### PDF Documents

**What works:**
- Pillar 1 (Forensic): FileStructureAnalyzer validates PDF magic bytes. PDFForensicsAnalyzer checks structure, JavaScript presence, producer/creator fields.
- MetadataForensicsAnalyzer checks file size (< 1KB flagged).

**What doesn't work:**
- Text content inside the PDF is not extracted for verification (OCR pipeline is stubbed).
- No comparison of PDF text content against the structured payload.
- Image-based forensic analyzers (ELA, noise, copy-move, lighting, fabrication) don't apply to PDFs.

### Images (photos, scanned documents)

**What works well:**
- Pillar 1 (Forensic): All 7 image analyzers fire for JPEG/PNG. Magic bytes, EXIF metadata, ELA, noise analysis, copy-move detection, lighting consistency, fabrication detection. This is the strongest part of the verification stack.
- Suspicion correlation catches too-perfect scores.
- Pillar 3 (Attestation): If the submission includes GPS, depth map, device fingerprint, and timestamp, all 5 attestation checks run. This is the path designed for field agents photographing physical documents.

**What doesn't work:**
- No OCR to extract text from images for cross-verification against structured data.
- Forensic analyzers require numpy and Pillow. Without them, analyzers return 0.5 neutral.

### Text/Unstructured Data

**What works:** Minimal. If text is submitted as a JSON payload field, domain logic checks for placeholder strings. Injection detection in schema gatekeeper catches attack patterns.

**What doesn't work:** No NLP analysis, no entity extraction, no semantic verification.

### Binary/Unknown Formats

**What works:** FileStructureAnalyzer will flag magic byte mismatches. Everything else returns neutral (0.5).

---

## 4. The Hard Problem -- Why Submissions Get REJECTED

### Root Cause Analysis

A typical JSON-only submission through `/refinery/submit` follows this path:

```
Gate 1 (Schema):     SKIPPED -- no schema provided
Gate 2 (Consistency): 0.50 -- "no consistency checks applicable"
Pillar 1 (Forensic): SKIPPED -- no attachments
Pillar 2 (Triangulation):
  - DomainLogic:       0.50 -- no field names match DOMAIN_RANGES
  - TemporalConsistency: 0.50 -- empty history store
  - CrossReference:    0.50 -- empty verified store
  -> Composite: 0 confirmations, 0 contradictions
  -> Corroboration score: 0.00 (UNVERIFIABLE)
  -> Blended: 0.00 * 0.6 + 0.50 * 0.4 = 0.20
Pillar 3 (Attestation): SKIPPED -- no bundle

Verdict computation:
  - Weights (no attestation): forensic=0.40, triangulation=0.60
  - Only triangulation ran: weighted_sum = 0.20 * 0.60 = 0.12
  - total_weight = 0.60
  - pillar_score = 0.12 / 0.60 = 0.20
  - pre_check_avg = 0.50 (consistency)
  - score = 0.20 * min(1.0, 0.50) = 0.10

Adversarial penalties:
  - Missing pillar (forensic + attestation): +0.05
  - Evidence gap: +0.05
  - Total penalty: ~0.10

Final score: max(0.0, 0.10 - 0.10) = 0.00 -> REJECTED
```

### The Five Contributing Factors

**1. The Corroboration Score Cliff (BIGGEST ISSUE)**

At `logic_triangulation.py:170`, when confirmations = 0 and contradictions = 0, the corroboration score is **0.00** (UNVERIFIABLE). This is correct in theory -- unverified data shouldn't score high. But in practice, the domain logic checks only fire for ~12 specific field name patterns. Any payload with field names like `monthly_charge`, `provider_name`, `plan_type` gets zero confirmations because they don't match the hardcoded `DOMAIN_RANGES` keys. The system treats "I don't know how to check this" the same as "I checked and found nothing."

**2. Empty History/Reference Stores**

TemporalConsistency and CrossReference both return 0.5 (neutral) on empty stores. But the corroboration scoring treats their evidence as "0 confirmations" since they produce `confirms=True` evidence with low confidence that doesn't count as a strong confirmation. The layer average (0.5) gets blended at 40% weight, which helps somewhat, but the 60% corroboration score of 0.0 dominates.

**3. Schema Gatekeeper Bypass**

Most callers don't pass a `DataSchema`, so Gate 1 is skipped. The `_build_minimal_schema` function only builds a schema for the consistency analyzer, not the gatekeeper. The consistency analyzer's auto-inferred schema marks everything as `required=False`, meaning no required-field checks fire.

**4. Adversarial Penalty Stacking**

With 2 out of 3 pillars missing, the adversarial agent correctly flags weak coverage (+0.05) and evidence gaps (+0.05). On already-low scores, these penalties push below zero. The adversarial system is working as designed -- the problem is that the base score is already too low due to issues 1-3.

**5. Pre-check Multiplier**

The pre_check_avg acts as a multiplier (`verification_stack.py:345`): `score = pillar_score * min(1.0, pre_check_avg)`. When consistency returns 0.5, this halves the already-low pillar score. A score of 0.20 becomes 0.10.

### Is the Schema Gatekeeper Too Strict?

No. The gatekeeper is actually well-designed and reasonable. The problem is the opposite: **it's never called.** When it does run (with a proper schema), it produces useful scores. The issue is that no schemas are defined for common data types.

### Are Forensic Analyzers the Problem?

Not for JSON. They're inapplicable. For images, they work well. The problem is that JSON submissions get penalized for missing forensic data that doesn't make sense for JSON.

---

## 5. Gap Analysis -- What's Missing for Complete Verification

### For JSON Payload Verification to Work Well

**Gap 1: Pre-defined schemas for common data types**

The system needs a schema registry -- a collection of `DataSchema` objects for known data types:
- Energy pricing (provider, region, plan_name, rate_kwh, daily_charge, etc.)
- Supply chain records (item, quantity, unit_price, total, supplier, date)
- Financial data (amount, currency, date, description, category)
- Insurance quotes (provider, coverage_type, premium, excess, etc.)

These schemas should be loadable by name: `schema_registry.get("energy_pricing_nz")`.

**Gap 2: Broader domain logic coverage**

`DOMAIN_RANGES` in `domain_logic.py` only covers 7 domain patterns. Expanding to 30+ common patterns would dramatically increase the number of claims that get verified:
- Insurance premium ranges by region
- Freight costs per km/mile
- Currency exchange rate bounds
- Common tax rates by country
- Real estate price ranges by region

**Gap 3: Persistent triangulation stores**

TemporalConsistency and CrossReference need to be wired to the database:
- On verification completion, write verified values to a `VerifiedDataPoint` table
- On next verification, query that table for temporal/cross-reference comparisons
- This creates a virtuous cycle: each verified submission makes future verification better

**Gap 4: Better handling of "no data" situations**

The corroboration scoring should distinguish between:
- "I checked and found contradictions" (score = 0.00, correct)
- "I checked and found nothing to compare against" (score = 0.50, should be neutral)
- "I couldn't even check because field names don't match" (should not count against)

Currently all three cases depress the final score.

**Gap 5: Dynamic weight redistribution**

When forensic and attestation pillars are completely inapplicable (JSON-only submission), their weight redistributes to triangulation. But the system should also recognize that triangulation alone cannot produce VERIFIED scores. The `pre_check_results` cap at line 348 (`score = pre_check_avg * 0.5`) is overly conservative for data types where pre-checks are the primary signal.

### What Schemas We Need Defined

Priority schemas (based on The Last Bastion's target use cases):

1. **energy_pricing** -- NZ/AU/UK electricity and gas pricing. Fields: provider, region, plan_name, rate_per_kwh, daily_charge, total_monthly, gst_rate, effective_date
2. **supply_chain_invoice** -- Purchase orders and invoices. Fields: supplier, buyer, items (quantity, unit_price, line_total), subtotal, tax, total, invoice_date, due_date
3. **insurance_quote** -- NZ/AU insurance products. Fields: provider, product_type, coverage_amount, premium_monthly, excess, effective_date, expiry_date
4. **market_data** -- Financial market data points. Fields: ticker, price, volume, timestamp, exchange, currency
5. **property_listing** -- Real estate data. Fields: address, price, bedrooms, bathrooms, land_area, listing_date

### What "Complete" Verification Looks Like Per Data Type

**JSON + Schema:** Gate 1 (schema validation) + Gate 2 (consistency) + Pillar 2 (domain logic + temporal + cross-ref from DB). Achievable score: 0.00-0.85. GOLD requires attestation or very strong triangulation.

**JSON + Schema + Attestation:** All of above + Pillar 3. Achievable: 0.00-0.92. GOLD possible.

**Image + JSON:** Pillar 1 (all 7 analyzers) + Pillar 2 (domain logic on extracted text via OCR). Achievable: 0.00-0.90. GOLD requires attestation.

**Image + JSON + Attestation:** Full stack. Achievable: 0.00-0.95. GOLD achievable.

**PDF + JSON:** Pillar 1 (file_structure + metadata + pdf_forensics) + Pillar 2 (domain logic). Achievable: 0.00-0.80.

---

## 6. Future Work -- Priority Roadmap

### Priority 1: Fix JSON Verification Scoring (CRITICAL)

**1a. Schema Registry** -- Create `core/verification/schema_registry.py` with pre-defined schemas for 5+ common data types. Wire into the submission endpoints so that callers can specify `schema_name` and the pipeline loads the correct `DataSchema`.
- Effort: **Small** (1-2 hours)
- Impact: **High** -- enables Gate 1 to actually run, immediately improves scores

**1b. Fix corroboration score for "no data" case** -- In `logic_triangulation.py:170`, change the 0-confirmations-0-contradictions case from 0.00 to 0.50 (neutral). The current behavior penalizes data for being unverifiable, which is wrong when the system simply lacks the knowledge to check.
- Effort: **Small** (30 minutes)
- Impact: **High** -- immediately stops JSON submissions from getting 0.00 corroboration

**1c. Adjust weight redistribution for JSON-only** -- When no attachments and no attestation, the effective pipeline is just pre-checks + triangulation. The cap at `pre_check_avg * 0.5` (line 348) should be `pre_check_avg * 0.7` when at least one pillar ran.
- Effort: **Small** (30 minutes)
- Impact: **Medium** -- raises ceiling from QUARANTINE to VERIFIED for clean JSON

### Priority 2: Wire Triangulation to Database (HIGH)

**2a. Persistent verified data store** -- After each VERIFIED/GOLD result, write key-value pairs to a `VerifiedDataPoint` table (domain, field_name, value, confidence, timestamp). Wire `CrossReferenceTriangulator` to query this table.
- Effort: **Medium** (3-4 hours)
- Impact: **High** -- creates the virtuous cycle where verification improves over time

**2b. Persistent temporal history** -- Same pattern for `TemporalConsistencyTriangulator`. Store verified values with timestamps, query for change detection.
- Effort: **Medium** (2-3 hours)
- Impact: **High** -- enables temporal anomaly detection to actually function

### Priority 3: Expand Domain Logic (MEDIUM)

**3a. Expand DOMAIN_RANGES** -- Add 20+ domain patterns to `domain_logic.py`: insurance premiums, freight costs, exchange rates, tax rates, property prices, common utility charges.
- Effort: **Medium** (2-3 hours)
- Impact: **Medium** -- more claims get domain-logic verification

**3b. Configurable domain rules** -- Move `DOMAIN_RANGES` from hardcoded dict to a JSON config file or DB table. Allow admins to add new ranges without code changes.
- Effort: **Medium** (3-4 hours)
- Impact: **Medium** -- long-term maintainability

### Priority 4: Agent Verification Improvements (MEDIUM)

**4a. Challenge-response authentication** -- When an agent registers, generate a nonce, require the agent to sign it with their declared public key. Verify signature. This closes the biggest gap in agent verification.
- Effort: **Medium** (3-4 hours)
- Impact: **High** -- transforms cryptographic check from presence-check to actual authentication

**4b. DB-backed reputation** -- Query `M2MTask` and `AgentVerification` tables for the agent's actual history with The Last Bastion, instead of relying on self-reported history.
- Effort: **Small** (1-2 hours)
- Impact: **Medium** -- reputation check becomes meaningful

### Priority 5: OCR Pipeline (LARGE)

**5a. Image text extraction** -- Wire pytesseract/DocTR to extract text from image attachments. Feed extracted text back into the structured data pipeline for domain logic checks.
- Effort: **Large** (6-8 hours)
- Impact: **Medium** -- enables cross-verification of image content against structured claims

**5b. PDF text extraction** -- Wire PyMuPDF text extraction into the verification pipeline. Compare PDF text against submitted structured data.
- Effort: **Medium** (3-4 hours)
- Impact: **Medium** -- enables PDF content verification beyond structure checks

### Priority 6: Anti-Replay Persistence (SMALL)

**6a. Persist seen provenance hashes** -- The `AttestationVerifier._seen_hashes` set is in-memory and lost on restart. Move to Redis or DB.
- Effort: **Small** (1 hour)
- Impact: **Low** (only matters for attestation submissions, which are rare currently)

### Priority 7: Statistical Anomaly Detection (MEDIUM)

**7a. Automatic distribution learning** -- After accumulating 100+ verified data points for a field, compute mean/std and feed into `ConsistencyAnalyzer._check_statistical_anomalies()`.
- Effort: **Medium** (3-4 hours)
- Impact: **Medium** -- enables statistical anomaly detection to function

### Priority 8: LLM-Assisted Verification (LARGE)

**8a. LLM reasonableness check** -- Use the pilot LLM to evaluate whether a payload "makes sense" in context. Feed the data + domain context to the LLM and get a plausibility assessment. This would catch issues that rule-based systems miss.
- Effort: **Large** (6-8 hours)
- Impact: **High** -- dramatically improves verification quality for novel data types
- Risk: LLM latency and cost. Should be optional and only used when rule-based checks are inconclusive.

### Priority 9: Federated Passport Authority (ARCHITECTURAL)

> **NOTE:** The current system has a fundamental architectural limitation: a single passport authority. If the issuing service's Ed25519 signing key is compromised, every passport it ever issued becomes untrustworthy. This is a single point of failure that must be addressed before production deployment.
>
> The target architecture is **M-of-N federated issuance**: multiple independent organizations each operate a passport authority with their own signing keys. A passport requires cross-signatures from at least M of N authorities (e.g., 2 of 3) to be considered valid. When one authority is compromised, its key is revoked, passports signed only by that authority are invalidated, and agents must re-authenticate with the remaining healthy authorities. Passports cross-signed by uncompromised authorities remain valid — the system degrades gracefully instead of collapsing.
>
> The wire protocol already supports this (passport_hash is content-addressed, not issuer-addressed). No protocol changes required — only the passport structure, verification logic, and authority discovery need to evolve.
>
> See `BASTION_PROTOCOL_SPEC.md` Section 7.13 for full technical design.

- Effort: **Very Large** (weeks, requires multi-party coordination)
- Impact: **Critical** -- transforms from prototype trust to production trust infrastructure

---

## Summary

The verification stack is architecturally sound -- the layered design with gates, pillars, evidence chains, and adversarial challenge is well-structured. The core problem is that **most of the layers have nothing to work with** for the most common submission type (JSON via API). The forensic pillar is excellent for images but irrelevant for JSON. The triangulation pillar has good logic but empty stores. The schema gatekeeper works but is never called.

The highest-ROI fixes are in Priority 1 (schema registry + corroboration score fix + weight adjustment). These are small code changes that would immediately move clean JSON submissions from REJECTED (0.10-0.35) to QUARANTINE or VERIFIED (0.50-0.80) territory, making the system actually usable for its primary use case.
