# The Last Bastion

**Agent security infrastructure for a world where AI agents operate autonomously.**

[![License: Apache 2.0](https://img.shields.io/badge/license-Apache%202.0-blue.svg)](LICENSE)
[![Python 3.11+](https://img.shields.io/badge/python-3.11%2B-blue.svg)](https://www.python.org/)
[![Status: Prototype](https://img.shields.io/badge/status-prototype-orange.svg)](#whats-built)
[![Protocol: Ed25519](https://img.shields.io/badge/crypto-Ed25519%20%2F%20X25519-informational.svg)](sdk/lastbastion/protocol/)

Nobody is verifying the agents. The Last Bastion does.

---

## The Problem

AI agents are being deployed into production with nothing more than an API key and a system prompt. They call tools, sign transactions, exchange data, and make decisions — but there is no standardised way to verify that an agent is who it claims to be, or that the data it carries hasn't been tampered with.

Current authentication (OAuth, JWT, API keys) was built for humans clicking buttons. It assumes a person is in the loop. Agents don't have that. They operate autonomously, across systems, across organisations, 24/7.

This isn't theoretical:
- **NIST** identified agent identity and trust as critical unsolved gaps in AI security ([NIST AI 600-17](https://csrc.nist.gov/pubs/ai/600/17/final))
- **CSA** published guidance on agentic AI threats including identity spoofing and data poisoning
- The market for AI agent security is projected to hit $236B by 2030 (WEF)

Nobody has built the infrastructure to solve this. The Last Bastion is a prototype working toward it.

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

### Bastion Protocol — the fast lane for agent-to-agent traffic

Most agent frameworks talk JSON-RPC over HTTP. That's the right choice for *discovery* — it's an open standard, and it's how an agent you've never met (built on someone else's stack) can find and talk to you at all. But once two agents both support this protocol, JSON-RPC is pure overhead: text serialization, no session encryption by default, a full connection setup on every call.

Bastion Protocol is a binary wire protocol for that second case — MessagePack framing, Ed25519 identity, X25519 ephemeral Diffie-Hellman handshakes (forward secrecy), NaCl SecretBox-encrypted sessions, and TLS-1.3-style session resumption so a reconnect doesn't pay the full handshake cost again. Two authentication modes, chosen per deployment, not per protocol:

- **PASSPORT mode** — an issuer-signed passport, pinned to a known trust authority. Use this when a verification authority (like The Last Bastion) is in the loop.
- **DIRECT mode** — no issuer required. Two agents that already hold their own Ed25519 keys authenticate each other via key pinning (the same trust-on-first-use model SSH uses for host keys) — for the common real-world case where no third-party authority exists yet, but you still want a fast, encrypted, mutually authenticated channel.

A2A stays the front door for the open ecosystem. Bastion Protocol is what agents that have already met each other switch to.

### Sandbox

A multi-tenant test environment: register an organization, get a sandbox API key, start a session for your agent, submit payloads through the same verification pipeline described above, and track trust score history over time.

---

## Prove it yourself

We don't ask you to take performance claims on faith — we ship the tool that measures them.

```bash
# Terminal 1 — the receiving agent
python scripts/bastion_bench.py serve --port 9100

# Terminal 2 — the sending agent (same machine, or point --host at a different one entirely)
python scripts/bastion_bench.py bench --host 127.0.0.1 --port 9100
```

This spins up two real agents that perform a real handshake and exchange real encrypted frames over a real TCP connection — no mocks, no simulated numbers. It reports, from that run:

- Fresh handshake latency vs. resumed handshake latency (session resumption skips the full key exchange)
- Throughput (messages/sec, MB/sec) and round-trip latency percentiles
- CPU/memory usage during the run
- A side-by-side comparison against plain JSON-over-TCP on the same machine, same payload, same run

The tool needs zero external infrastructure — no Postgres, no Redis, no Docker. Just this repo's SDK.

We're not going to print a number here and ask you to trust it. Run it, on your own hardware, on your own network. If the numbers don't hold up, that's useful information for us too — [see the open items below](#whats-built).

---

## Architecture

```
                         ┌───────────────────────────────────┐
                         │         THE LAST BASTION           │
                         │                                    │
  Agent arrives ────────►│  M2M / REST API (Ed25519 + Nonce)  │
                         │            │                       │
                         │       ┌────▼─────┐                 │
                         │       │  Agent   │  10-check trust  │
                         │       │ Verifier │  pipeline        │
                         │       └────┬─────┘                 │
                         │            │                       │
                         │       ┌────▼─────┐                 │
                         │       │ Passport │  Ed25519-signed  │
                         │       │ Issuer   │  JWT + blockchain│
                         │       └────┬─────┘                 │
                         │            │                       │
  Data arrives ─────────►│      ┌─────▼──────┐                │
                         │      │  5-Layer   │                │
                         │      │Verification│                │
                         │      │  Pipeline  │                │
                         │      └─────┬──────┘                │
                         │            │                       │
                         │       ┌────▼─────┐                 │
                         │       │  Proof   │  Merkle chain    │
                         │       │  Ledger  │  + blockchain    │
                         │       └──────────┘                 │
                         └───────────────────────────────────┘
                                       ▲
                                       │  binary, encrypted, resumable
                         ┌─────────────┴─────────────┐
                         │      Bastion Protocol       │
                         │  PASSPORT mode / DIRECT mode│
                         └─────────────────────────────┘
                            ▲                       ▲
                    Agent A (your stack)     Agent B (their stack)
```

---

## What's Built

Everything listed below is implemented and covered by an automated test suite. Nothing here is marketing copy for a roadmap item — if it's listed as built, `pytest` proves it on every change.

### Security Infrastructure
- **10-check agent verification pipeline** — identity, crypto challenge, behavioral, anti-Sybil, payload, network, history, anomaly
- **Ed25519 challenge-response authentication** — agents prove key ownership, not just key possession
- **Cryptographic passports** — signed JWTs with anti-cloning protection (runtime fingerprint, IP allowlist hash)
- **M2M protocol** — message freshness (300s window), nonce anti-replay, rate limiting, RBAC
- **Bastion Protocol** — binary agent-to-agent wire protocol; PASSPORT mode (issuer-verified) and DIRECT mode (key-pinned, no issuer needed); session resumption with single-use rotating tickets and forward secrecy

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
- **A2A Protocol** (Linux Foundation standard) — the outward-facing discovery layer, for agents outside this ecosystem
- **Bastion Protocol** — the fast inner lane once both sides can speak it (see above)
- **4 demo agents** — Producer, Compliance, Logistics, Buyer — demonstrating a supply chain verification workflow
- **Agent Cards** — standardised discovery (`/.well-known/agent-card.json`)

### Platform
- **FastAPI backend** with full API docs at `/docs`
- **React dashboard** — monitoring, protocol feed, sandbox controls
- **Python SDK** — client, gateway middleware, protocol library, MCP tools
- **Docker orchestration** — one command to start

### Known open items
We'd rather list what's still rough than have you find out the hard way:
- Bastion Protocol's DATA-frame throughput is currently *not yet* faster than plain JSON-over-TCP for small, high-frequency messages on the same machine — session resumption shows a real, measured speedup, but raw throughput has more optimization ahead. Run the bench tool above for current numbers.
- Most of `core/database.py`'s query layer is still synchronous, which can block the event loop under concurrent load on a handful of older endpoints — being worked through incrementally.
- DIRECT mode + session resumption are implemented and tested at the protocol layer but not yet wired into the high-level `AgentSocket` convenience API — usable today via `DirectAgentSocket` directly.

---

## Quick Start

**Requirements:** Docker + free Groq API key. That's it.

```bash
# 1. Clone
git clone https://github.com/xDarkzx/TheLastBastion.git
cd TheLastBastion

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

Just want to see two agents talk to each other, no Docker required? See [Prove it yourself](#prove-it-yourself) above.

Full setup guide with troubleshooting: **[SETUP.md](SETUP.md)**

---

## Tech Stack

| Layer | Technology |
|-------|-----------|
| **API** | FastAPI, Uvicorn, SQLAlchemy |
| **Database** | PostgreSQL (persistent), Redis (queuing + pub/sub) |
| **Frontend** | React, Vite, Axios |
| **Cryptography** | Ed25519, X25519 (PyNaCl / libsodium), SHA-256, HMAC, JWT |
| **Serialization** | MessagePack (Bastion Protocol), JSON (REST/A2A) |
| **Blockchain** | Solidity, Hardhat, Web3.py, Polygon Amoy |
| **LLM** | Groq (Llama 3.3 70B), Ollama (local, optional) |
| **Agent Protocol** | A2A (Linux Foundation), Bastion Protocol (this repo), MCP |
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

The Python SDK lets any agent interact with The Last Bastion — register, get verified, submit data, protect endpoints, or speak Bastion Protocol directly.

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

Talking directly to another agent over Bastion Protocol, no verification authority required:

```python
from lastbastion.crypto import generate_keypair
from lastbastion.protocol import DirectAgentSocket, PeerTrustStore

pub, priv = generate_keypair()
trust_store = PeerTrustStore(".my_agent_trust.json")

conn, ticket, secret = await DirectAgentSocket.connect(
    "peer-host:9100", agent_id="my-agent", public_key=pub,
    signing_key=priv, trust_store=trust_store,
)
await conn.send({"task": "verify", "payload": {...}})
result = await conn.recv()
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

These are the gaps NIST, CSA, and WEF have identified as critical. The Last Bastion is a prototype implementation working toward addressing them.

---

## Research & References

The security model is grounded in real research:

- [NIST AI 600-17](https://csrc.nist.gov/pubs/ai/600/17/final) — AI agent identity and authorisation gaps
- [CSA AI Safety Initiative](https://cloudsecurityalliance.org/) — Agentic AI threat modelling
- [A2A Protocol](https://github.com/google/A2A) — Linux Foundation agent-to-agent standard
- [MCP Protocol](https://modelcontextprotocol.io/) — Tool integration standard

Architecture documents in [`/documents`](documents/):
- `BASTION_PROTOCOL_SPEC.md` — Bastion Protocol specification
- `SYSTEM_ARCHITECTURE.md` — Full system design
- `SANDBOX_BLUEPRINT.md` — Sandbox architecture
- `NIST_RESEARCH.md` — NIST gap analysis
- `M2M_SIMULATION_BLUEPRINT.md` — M2M simulation ecosystem design

---

## License

Apache 2.0 — see [LICENSE](LICENSE) and [NOTICE](NOTICE).

If you use, fork, or build on this code — attribution is required.

---

## Contact

**Daniel Hodgetts** — DK Studios NZ

Email: [dkstudiosnz@gmail.com](mailto:dkstudiosnz@gmail.com)

---

*Solo developer. Building the security layer the rest of the agent ecosystem hasn't gotten to yet — one verified commit at a time.*
