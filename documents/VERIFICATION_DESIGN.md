# Verification Stack v2 — Multi-Modal Forensic Triangulation
**Version**: 2.0 | **Date**: 2026-03-04 | **Status**: DRAFT — REVIEW REQUIRED

---

## The Paradigm Shift

v1 asked: "Can we find this data on a website to confirm it?"
**v2 asks three different questions:**

1. **"Is this document an unaltered original?"** (Forensic Integrity)
2. **"Is the data inside it consistent with reality?"** (Logic Triangulation)
3. **"Can we prove this physical artifact existed?"** (Human-Attested Proof)

If the answer to #1 is YES, #2 is YES, and we have #3 — that data is **verified truth** without needing any online database.

---

## The Three Pillars

```
                        ┌───────────────────┐
                        │   VERDICT ENGINE   │
                        │  (Composite Score) │
                        └─────────┬─────────┘
                                  │
           ┌──────────────────────┼──────────────────────┐
           │                      │                      │
   ┌───────┴────────┐   ┌────────┴────────┐   ┌────────┴────────┐
   │   PILLAR 1     │   │   PILLAR 2      │   │   PILLAR 3      │
   │   FORENSIC     │   │   LOGIC         │   │   ATTESTATION   │
   │   INTEGRITY    │   │   TRIANGULATION │   │   PROOF         │
   │                │   │                 │   │                 │
   │ "Is document   │   │ "Does the data  │   │ "Did this       │
   │  authentic?"   │   │  match reality?"│   │  artifact       │
   │                │   │                 │   │  exist?"         │
   └────────────────┘   └─────────────────┘   └─────────────────┘
    Pixel analysis       Cross-domain logic    GPS + time + depth
    Metadata forensics   Engineering history   Blockchain hash
    Tampering detect     Statistical norms     Provenance chain
```

---

## Pillar 1: Forensic Document Integrity (The Digital Microscope)

**Purpose**: Prove the document itself is authentic — not fabricated, not altered, not deepfaked.

### Module: `core/verification/forensic_integrity.py`

```python
class ForensicIntegrityAnalyzer:
    """
    Analyzes the physical properties of a digital document
    to determine if it's an unaltered original.
    """

    async def analyze(self, file_bytes: bytes, file_type: str,
                      metadata: dict) -> PillarResult:
        """
        Runs all forensic checks and returns composite integrity score.
        """

    # --- Sub-analyzers ---

    def check_pixel_consistency(self, image: ndarray) -> ForensicEvidence:
        """
        Error Level Analysis (ELA):
        Re-compresses the image at known quality and compares
        pixel-level differences. Edited regions show up as
        bright spots because they were saved at different
        compression levels than the rest.

        Detects: Photoshop edits, pasted text, replaced numbers
        """

    def check_font_forensics(self, image: ndarray) -> ForensicEvidence:
        """
        Font Consistency Analysis:
        - Extracts all text regions via OCR with bounding boxes
        - Measures font metrics: size, weight, kerning, baseline
        - Flags regions where font properties DON'T match surrounding text
        - A real document has consistent font rendering
        - An edited document has "flattened" fonts (rasterized at different DPI)

        Detects: Number replacement, added text, forged signatures
        """

    def check_lighting_consistency(self, image: ndarray) -> ForensicEvidence:
        """
        For photographed documents (not digital PDFs):
        - Analyzes shadow direction and intensity across the image
        - Real photo: consistent light source, natural paper curvature
        - Composite: inconsistent shadows, sharp edges between regions
        - Checks if text sharpness matches paper texture sharpness

        Detects: Composited photos, digitally overlaid text on real paper
        """

    def check_metadata_forensics(self, file_bytes: bytes,
                                  file_type: str) -> ForensicEvidence:
        """
        EXIF/PDF Metadata Analysis:
        - Creation date, modification dates, software used
        - PDF: producer, creator, modification history, font embedding
        - Image: camera model, GPS, focal length, color profile
        - Flags: modification date != creation date (edited after creation)
        - Flags: metadata stripped (common fraud tactic)
        - Flags: software="Adobe Photoshop" on a supposedly "scanned" document

        Detects: Post-creation edits, metadata stripping, tool mismatch
        """

    def check_noise_pattern(self, image: ndarray) -> ForensicEvidence:
        """
        Sensor Noise Analysis:
        - Every camera/scanner has a unique noise fingerprint
        - Consistent noise = single capture device (authentic)
        - Inconsistent noise across regions = composite from multiple sources
        - Also checks JPEG quantization tables for re-save detection

        Detects: Documents assembled from multiple scans, re-saved JPEGs
        """

    def check_copy_move_detection(self, image: ndarray) -> ForensicEvidence:
        """
        Duplicate Region Detection:
        - Uses DCT (Discrete Cosine Transform) block matching
        - Finds regions that are pixel-identical to other regions
        - Real documents don't have duplicated pixel patterns
        - Copy-move forgery: someone copied a "good" section over a "bad" one

        Detects: Copy-paste forgery within a document
        """
```

**Dependencies**: `Pillow`, `opencv-python`, `numpy`, `python-doctr` or `pytesseract`

**Test Scenarios**:
| Input | Expected | Why |
|---|---|---|
| Clean scan of real invoice | Integrity: HIGH (0.9+) | Consistent noise, fonts, lighting |
| Same invoice with one number edited in Photoshop | Integrity: LOW (0.2) | ELA shows bright region at edit point |
| Photo of real paper document | Integrity: HIGH (0.85) | Consistent lighting and shadows |
| Digitally generated text overlaid on paper photo | Integrity: LOW (0.15) | Text sharpness doesn't match paper texture |
| PDF with stripped metadata | Integrity: MEDIUM (0.5) | Suspicious but not conclusive |

---

## Pillar 2: Cross-Domain Logic Triangulation

**Purpose**: Even if the specific data isn't online, its LOGIC can be verified against reality.

### Module: `core/verification/logic_triangulation.py`

```python
class LogicTriangulationEngine:
    """
    Verifies data by checking if its claims are consistent
    with the known physical, economic, and historical world.
    Doesn't need the exact data online — needs RELATED data.
    """

    async def triangulate(self, claims: list[DataClaim],
                          domain: str,
                          playbook: dict) -> PillarResult:
        """
        For each claim, finds the BEST verification strategy
        and hunts for evidence.
        """

    # --- Strategy: Direct API Verification ---
    async def verify_via_api(self, claim: DataClaim) -> Evidence:
        """
        If an authoritative API exists for this data type,
        query it directly.

        Examples:
        - Company registration → NZ Companies Office API
        - GST number → IRD Validation
        - Address → Geocoding API
        - Stock price → Market data API
        """

    # --- Strategy: Web Corroboration ---
    async def verify_via_web(self, claim: DataClaim) -> Evidence:
        """
        Use browser agent to find corroborating data on official sites.
        NOT scraping for the sake of data — scraping to VERIFY a claim.

        Example: Submitted data says "Mercury Energy $0.28/kWh"
        → Agent loads Mercury's pricing page → extracts current price
        → Confirms or contradicts the claim
        """

    # --- Strategy: Cross-Reference (Internal) ---
    async def verify_via_cross_reference(self, claim: DataClaim) -> Evidence:
        """
        Check our OWN verified data store.
        If 3 other independent sources already submitted the same claim,
        that's strong corroboration.
        """

    # --- Strategy: Engineering/Domain Logic ---
    async def verify_via_domain_logic(self, claim: DataClaim,
                                       context: dict) -> Evidence:
        """
        THE KEY DIFFERENTIATOR — cross-domain logic verification.

        Example: 1990s parts manual says "Part X uses M10 bolt"
        → Agent searches for other machines from same manufacturer, same era
        → Finds they ALL use M8 bolts
        → Flags: "Logic Conflict — manufacturer used M8 across all
                  1990s models. M10 claim is suspicious."

        Example: Invoice says "100 units × $50 = $4,500"
        → 100 × 50 = 5,000, not 4,500
        → Flags: "Arithmetic Conflict"

        Example: Electricity price claimed at $2.80/kWh in NZ
        → NZ average is $0.28/kWh
        → Could be decimal error or fraud
        → Flags: "Magnitude Anomaly — 10x expected value"

        Uses LLM for reasoning about domain-specific logic:
        "Given what you know about [domain], is this claim plausible?
         What would you expect the value to be? Why?"
        """

    # --- Strategy: Temporal Consistency ---
    async def verify_via_temporal(self, claim: DataClaim,
                                   domain: str) -> Evidence:
        """
        Compare against historical patterns in EpisodicMemory.
        - Price 5% different from last month → Normal
        - Price 500% different → Suspicious
        - First ever submission for this domain → Neutral (no history)
        - Seasonal pattern match → Boosts confidence
        """

    # --- Strategy: Authority Registry ---
    async def verify_via_authority(self, claim: DataClaim) -> Evidence:
        """
        Query authoritative registries and databases.
        - Company exists? → Companies Office
        - GST number valid? → IRD
        - Address real? → Geocoding
        - Product exists? → Manufacturer database
        - Standard exists? → ISO/NZ Standards
        """
```

**Triangulation Scoring**:
```
0 strategies found evidence         → 0.00 (UNVERIFIABLE)
1 source confirms, 0 contradict     → 0.40 (WEAK)
2 sources confirm, 0 contradict     → 0.75 (STRONG)
3+ sources confirm, 0 contradict    → 0.90 (VERY STRONG)
Any active contradiction found      → 0.00 (DISPROVED — veto)
Contradiction + confirmations       → 0.20 (CONTESTED — quarantine)
```

---

## Pillar 3: Human-Attested Provenance Seeding

**Purpose**: Prove that a physical artifact EXISTED at a specific place and time — even if you can't prove the DATA inside it is "fair."

### Module: `core/verification/attestation.py`

```python
class AttestationVerifier:
    """
    Handles human-attested document submissions where the physical
    provenance of the artifact can be cryptographically proven.
    """

    def verify_attestation_bundle(self, bundle: AttestationBundle
                                   ) -> PillarResult:
        """
        An AttestationBundle contains:
        - file_bytes: the document image/video
        - gps_location: (lat, lon, accuracy_meters)
        - timestamp: device-reported time
        - depth_map: 3D depth data (proves it's a real object, not a screen)
        - device_fingerprint: unique device identifier
        - video_frames: multiple angles of the document (optional)

        Checks:
        1. GPS Plausibility — is the location a real address?
        2. Temporal Plausibility — timestamp within reasonable window
        3. Depth Verification — depth map shows paper geometry (not flat screen)
        4. Device Consistency — same device fingerprint across submissions
        5. Video Continuity — if video provided, frames are temporally consistent
        6. Anti-Replay — haven't we seen this exact bundle before?

        Returns: PillarResult with attestation_score and provenance_chain
        """

    def generate_provenance_hash(self, bundle: AttestationBundle
                                  ) -> str:
        """
        Creates the blockchain-ready hash:

        hash = SHA-256(
            file_hash +
            gps_lat + gps_lon +
            timestamp_unix +
            depth_map_hash +
            device_fingerprint
        )

        This hash proves:
        "This specific document was captured by this device,
         at this location, at this time, and it was a real
         physical object (not a screen capture)."
        """

    def check_depth_authenticity(self, depth_map: ndarray) -> bool:
        """
        Key anti-fraud check:
        - Real paper has Z-depth variation (curves, folds, thickness)
        - A photo of a screen is FLAT (uniform Z-depth)
        - A printed fake has different paper texture than originals

        This is what separates "someone held up a real 1985 manual"
        from "someone displayed a PDF on their iPad"
        """
```

**The Value Proposition**:
> "I can't prove the price in this 1920s ledger is 'fair,' but I can prove with 100% certainty that this specific piece of paper existed in this warehouse on March 4, 2026."

---

## Composite Verdict Engine

### Module: `core/verification/verdict_engine.py`

```python
class VerdictEngine:
    """
    Combines all three pillars into a single verdict.
    """

    PILLAR_WEIGHTS = {
        "forensic_integrity":     0.30,   # Is the document real?
        "logic_triangulation":    0.45,   # Is the data correct?
        "attestation_proof":      0.25,   # Can we prove provenance?
    }

    def render_verdict(self, pillar_results: dict) -> Verdict:
        """
        Rules:
        1. If forensic integrity < 0.3 → REJECT
           (document is tampered — nothing else matters)
        2. If triangulation finds ACTIVE CONTRADICTION → REJECT
           (data is provably wrong)
        3. If no attestation bundle exists → attestation weight
           redistributed to other pillars
        4. Otherwise → weighted average

        Verdicts:
        - REJECTED:    score < 0.40 OR veto triggered
        - QUARANTINE:  0.40 ≤ score < 0.70
        - VERIFIED:    0.70 ≤ score < 0.90
        - GOLD:        score ≥ 0.90

        GOLD requires:
        - Forensic integrity ≥ 0.8
        - At least 2 independent triangulation confirmations
        - Either attestation bundle OR 3+ cross-reference matches
        """
```

**Attestation is Optional**: Not every submission will have a 3D video scan. When attestation is absent, its weight is redistributed to forensic integrity (0.40) and triangulation (0.60). **Gold verification becomes harder without attestation** — you need more triangulation evidence.

---

## Progressive Build — 10 Steps

| Step | What | Module | Test Gate |
|---|---|---|---|
| **1** | Schema Gatekeeper | `schema_gatekeeper.py` | 10 test cases (valid/invalid/injection) |
| **2** | Internal Consistency | `consistency.py` | 10 test cases (math/anomaly/range) |
| **3** | Forensic: ELA + Noise | `forensic_integrity.py` | Real vs edited document pairs |
| **4** | Forensic: Font + Lighting | `forensic_integrity.py` | Photo vs composite detection |
| **5** | Triangulation: API + Web | `logic_triangulation.py` | Real API calls + web verification |
| **6** | Triangulation: Domain Logic | `logic_triangulation.py` | LLM reasoning against known data |
| **7** | Temporal + Cross-Reference | `logic_triangulation.py` | Historical pattern matching |
| **8** | Attestation Verifier | `attestation.py` | Depth map + GPS + hash generation |
| **9** | Adversarial Challenge | `adversarial.py` | LLM tries to disprove known-good/bad |
| **10** | Verdict Engine | `verdict_engine.py` | End-to-end: good→GOLD, bad→REJECT, ambiguous→QUARANTINE |

---

## File Structure

```
core/
├── verification_stack.py              # Orchestrates all pillars
├── verification/
│   ├── __init__.py
│   ├── schema_gatekeeper.py           # Step 1
│   ├── consistency.py                 # Step 2
│   ├── forensic_integrity.py          # Steps 3-4 (Pillar 1)
│   ├── logic_triangulation.py         # Steps 5-7 (Pillar 2)
│   ├── attestation.py                 # Step 8 (Pillar 3)
│   ├── adversarial.py                 # Step 9
│   ├── verdict_engine.py              # Step 10
│   └── models.py                      # DataClaim, Evidence, PillarResult, Verdict
```

> [!CAUTION]
> Pillar 1 (Forensic Integrity) is the first line of defense. If the document itself is fake, nothing else matters. This is the "kill switch" — a forged document gets REJECTED before we even read the data inside it.

> [!IMPORTANT]
> Pillar 2 (Logic Triangulation) is where we prove data is TRUE even when no online source exists. We don't verify "is this number on a website." We verify "is this number consistent with the laws of physics, engineering, economics, and history."
