# The Last Bastion

**Agent security infrastructure for a world where AI agents operate autonomously.**

Nobody is verifying the agents. The Last Bastion does.

---

## The Problem

AI agents are being deployed into production with nothing more than an API key and a system prompt. They call tools, sign transactions, exchange data, and make decisions — but there is no standardised way to verify that an agent is who it claims to be, or that the data it carries hasn't been tampered with.

Current authentication (OAuth, JWT, API keys) was built for humans clicking buttons. It assumes a person is in the loop. Agents don't have that. They operate autonomously, across systems, across organisations, 24/7.

This isn't theoretical:
- **NIST** identified agent identity and trust as critical unsolved gaps in AI security ([NIST AI 600-17](https://csrc.nist.gov/pubs/ai/600/17/final))
- **CSA** published guidance on agentic AI threats including identity spoofing and data poisoning
- The market for AI agent security is projected to hit $236B by 2030 (WEF)

Nobody has built the infrastructure to solve this. Until now.

---

## What This Solves

### Agent Trust Verification

A 10-check security pipeline that answers: *"Should I trust this agent?"*

```
Agent arrives → Identity Check → Cryptographic Challenge (Ed25519)
  → Behavioral Analysis → Anti-Sybil Detection → Capability Audit
  → Payload Integrity → Network Reputation → History Analysis
  → Anomaly Detection → Trust Score (0.0 - 1.0)
  → Verdict: TRUSTED / SUSPICIOUS / MALICIOUS
  → Signed Passport (JWT) + Blockchain Stamp
```

Agents receive a **cryptographic passport** — a signed JWT containing their trust score, verification results, and anti-cloning protections. Other systems can verify this passport offline, without calling The Last Bastion.

### Payload Integrity Verification

A 5-layer pipeline that answers: *"Should I trust this data?"*

```
Data arrives → Schema Gatekeeper (injection detection, type checking)
  → Consistency Analyzer (arithmetic, cross-field logic, anomalies)
  → Forensic Integrity (ELA, noise analysis, copy-move, metadata, PDF forensics)
  → Logic Triangulation (cross-reference, temporal, domain logic)
  → Adversarial Challenge (devil's advocate)
  → Verdict: REJECTED / QUARANTINE / VERIFIED / GOLD
  → Proof Hash → Merkle Chain → Blockchain Anchor
```

Every verification produces a tamper-evident proof record. These chain together in a Merkle chain — modify any record and all subsequent hashes break. Optionally anchored on-chain for independent verification.

### Open Sandbox

Send your agent to be tested. The sandbox runs real attacks against it:
- Prompt injection
- Identity spoofing
- Sybil flooding
- Data exfiltration attempts
- Payload poisoning
- Replay attacks

Your agent gets a trust score based on what it survives.

---

## Architecture

```
                         ┌─────────────────────────────────┐
                         │       THE LAST BASTION           │
                         │                                  │
  Agent arrives ────────►│  M2M Protocol (Ed25519 + Nonce)  │
                         │         │                        │
                         │    ┌────▼────┐                   │
                         │    │  Agent   │  10-check trust   │
                         │    │ Verifier │  pipeline          │
                         │    └────┬────┘                   │
                         │         │                        │
                         │    ┌────▼────┐                   │
                         │    │ Passport │  Ed25519-signed   │
                         │    │ Issuer   │  JWT + blockchain  │
                         │    └────┬────┘                   │
                         │         │                        │
  Data arrives ─────────►│  ┌──────▼──────┐                 │
                         │  │  5-Layer     │                 │
                         │  │ Verification │                 │
                         │  │  Pipeline    │                 │
                         │  └──────┬──────┘                 │
                         │         │                        │
                         │    ┌────▼────┐                   │
                         │    │  Proof   │  Merkle chain     │
                         │    │  Ledger  │  + blockchain     │
                         │    └─────────┘                   │
                         │                                  │
                         │    ┌─────────┐                   │
  Sandbox test ─────────►│   │ Attack   │  6 attack types   │
                         │    │Simulator│  real execution   │
                         │    └─────────┘                   │
                         └─────────────────────────────────┘
```

---

## What's Built

This isn't a whitepaper. Everything listed below is implemented and working.

### Security Infrastructure
- **10-check agent verification pipeline** — identity, crypto challenge, behavioral, anti-Sybil, payload, network, history, anomaly
- **Ed25519 challenge-response authentication** — agents prove key ownership, not just key possession
- **Cryptographic passports** — signed JWTs with anti-cloning protection (runtime fingerprint, IP allowlist hash)
- **M2M protocol** — message freshness (300s window), nonce anti-replay, rate limiting, RBAC
- **6-attack sandbox** — prompt injection, identity spoofing, Sybil flood, exfiltration, payload poisoning, replay

### Verification Stack
- **Schema Gatekeeper** — structural validation, SQL/XSS/code injection detection
- **Consistency Analyzer** — arithmetic cross-checks, statistical anomaly detection
- **7 forensic analyzers** — Error Level Analysis, noise patterns, copy-move detection, lighting analysis, metadata forensics, file structure, PDF forensics
- **Logic Triangulation** — cross-reference, temporal, domain-specific logic checks
- **Adversarial Challenge** — 5 strategies: contradiction hunting, boundary testing, source skepticism, pattern injection, confidence calibration

### Audit & Blockchain
- **Merkle-chain proof ledger** — append-only, tamper-evident, every record chains to the previous
- **Proof-of-Task** — SHA-256 non-repudiation (proves which agent produced what data, when)
- **Smart contracts on Polygon Amoy:**
  - `SwarmProofRegistry` — on-chain proof anchoring ([0x110a...e946](https://amoy.polygonscan.com/address/0x110affBAC98FCC6b86Da499550B1fC0aCA22e946))
  - `SwarmAgentRegistry` — agent identity, reputation, service marketplace ([0xc917...0D7D](https://amoy.polygonscan.com/address/0xc9177baBF86FF16794AABd1a2169f898986a0D7D))

### Agent Network
- **A2A Protocol** (Linux Foundation standard) — real agent-to-agent communication
- **4 demo agents** — Producer, Compliance, Logistics, Buyer — running a supply chain verification workflow
- **Agent Cards** — standardised discovery (/.well-known/agent.json)

### Platform
- **FastAPI backend** with full API docs at `/docs`
- **React dashboard** — real-time monitoring, protocol feed, sandbox controls
- **Python SDK** — client, gateway middleware, MCP tools
- **Docker orchestration** — 4 services, one command to start

---

## Quick Start

**Requirements:** Docker + free Groq API key. That's it.

```bash
# 1. Clone
git clone https://github.com/YOUR_USERNAME/the-last-bastion.git
cd the-last-bastion

# 2. Configure
cp .env.example .env
# Edit .env — add your Groq key from https://console.groq.com

# 3. Launch (builds everything, no installs on your system)
docker-compose up --build
```

| Service | URL |
|---------|-----|
| **Dashboard** | [http://localhost:5173](http://localhost:5173) |
| **API** | [http://localhost:8000](http://localhost:8000) |
| **API Docs** | [http://localhost:8000/docs](http://localhost:8000/docs) |

Full setup guide with troubleshooting: **[SETUP.md](SETUP.md)**

---

## Tech Stack

| Layer | Technology |
|-------|-----------|
| **API** | FastAPI, Uvicorn, SQLAlchemy |
| **Database** | PostgreSQL (persistent), Redis (queuing + pub/sub) |
| **Frontend** | React, Vite, Axios |
| **Cryptography** | Ed25519 (PyNaCl), SHA-256, HMAC, JWT |
| **Blockchain** | Solidity, Hardhat, Web3.py, Polygon Amoy |
| **LLM** | Groq (Llama 3.3 70B), Ollama (local, optional) |
| **Agent Protocol** | A2A (Linux Foundation), MCP |
| **Containerisation** | Docker, Docker Compose |
| **Forensics** | PIL/Pillow, NumPy (ELA, noise, copy-move, lighting) |

---

## Smart Contracts

Both contracts are deployed and verified on Polygon Amoy testnet.

### SwarmProofRegistry

Stores verification proof hashes on-chain. Any modification to the source data invalidates the proof. Lookups are free (no gas).

- **Address:** [`0x110affBAC98FCC6b86Da499550B1fC0aCA22e946`](https://amoy.polygonscan.com/address/0x110affBAC98FCC6b86Da499550B1fC0aCA22e946)
- **Functions:** `anchorProof()`, `anchorBatch()`, `verifyProof()` (free)

### SwarmAgentRegistry

On-chain agent identity, reputation scores (0-100), service listings, and task receipts. All lookups free.

- **Address:** [`0xc9177baBF86FF16794AABd1a2169f898986a0D7D`](https://amoy.polygonscan.com/address/0xc9177baBF86FF16794AABd1a2169f898986a0D7D)
- **Functions:** `registerAgent()`, `updateReputation()`, `registerService()`, `recordTaskReceipt()`

---

## SDK

The Python SDK lets any agent interact with The Last Bastion — register, get verified, submit data, protect endpoints.

```python
from lastbastion import LastBastionClient

async with LastBastionClient(base_url="http://localhost:8000") as client:
    # Generate Ed25519 keypair
    public_key, private_key = client.generate_keypair()

    # Register → verify → get passport (one call)
    passport = await client.register_and_verify(
        agent_id="my-agent",
        public_key=public_key,
        private_key=private_key,
    )
    # passport contains: trust_score, jwt_token, verification_checks

    # Submit data for verification
    result = await client.submit_payload({"invoice": {"total": 1500}})
    # result = {"verdict": "VERIFIED", "score": 0.82, "proof_hash": "abc123..."}
```

Full SDK documentation: **[sdk/README.md](sdk/README.md)**

---

## Why This Matters

The agent economy is being built without security infrastructure. Every major framework (LangChain, CrewAI, AutoGen) lets you build agents — none of them verify the agents they interact with.

**What exists today:**
- API keys (shared secrets, no identity verification)
- OAuth (requires human in the loop)
- JWT (no standard for agent-to-agent trust)
- Zero forensic verification of agent-produced data

**What's needed:**
- Cryptographic proof of agent identity (not just "has a valid key")
- Behavioural verification (is this agent acting normally?)
- Data integrity verification (is this data real or fabricated?)
- Tamper-evident audit trails (can we prove what happened?)
- Cross-platform trust (works across any agent framework)

This is what NIST, CSA, and WEF have identified as critical gaps. The Last Bastion is a working implementation that addresses them.

---

## Research & References

The security model is grounded in real research:

- [NIST AI 600-17](https://csrc.nist.gov/pubs/ai/600/17/final) — AI agent identity and authorisation gaps
- [CSA AI Safety Initiative](https://cloudsecurityalliance.org/) — Agentic AI threat modelling
- [A2A Protocol](https://github.com/google/A2A) — Linux Foundation agent-to-agent standard
- [MCP Protocol](https://modelcontextprotocol.io/) — Tool integration standard

Architecture documents in [`/documents`](documents/):
- `BASTION_PROTOCOL_SPEC.md` — Protocol specification
- `SANDBOX_BLUEPRINT.md` — Sandbox architecture
- `NIST_RESEARCH.md` — NIST gap analysis
- `SYSTEM_ARCHITECTURE.md` — Full system design

---

## License

Apache 2.0 — see [LICENSE](LICENSE) and [NOTICE](NOTICE).

If you use, fork, or build on this code — attribution is required.

---

## Contact

**Daniel Hodgetts** — DK Studios NZ

Email: [dkstudiosnz@gmail.com](mailto:dkstudiosnz@gmail.com)

---

*i am solo dev Solving security problems the rest of the industry hasn't noticed yet.*
