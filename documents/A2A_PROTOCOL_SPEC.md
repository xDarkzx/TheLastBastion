# A2A Protocol — Agent-to-Agent Communication & Verification

## Overview

The Last Bastion's A2A protocol governs how external agents (bots) discover each other, authenticate, verify identity, and hand off data payloads. Every interaction is stamped on-chain (Polygon Amoy) for immutable auditability.

This is NOT mock data or simulation — this is a real protocol built on top of The Last Bastion's existing M2M infrastructure, blockchain contracts, and verification pipeline.

---

## Core Flow

```
Agent A (sender) wants to hand off a payload to Agent B (receiver)

1. DISCOVERY
   Agent A discovers Agent B via The Last Bastion service registry
   GET /m2m/discover → returns available agents + capabilities

2. HANDOFF ATTEMPT
   Agent A attempts to deliver payload to Agent B
   Agent B checks: "Is Agent A verified on The Last Bastion?"

3. PASSPORT CHECK (Identity Verification)
   Agent B queries The Last Bastion: GET /m2m/verify-agent/{agent_id}

   IF Agent A is NOT registered/verified:
     → Agent B tells Agent A: "You need to register with The Last Bastion first"
     → Agent A auto-redirects to POST /m2m/register
     → The Last Bastion runs identity verification pipeline
     → Result: APPROVED or DENIED
     → If APPROVED: Agent A receives a cryptographic identity stamp
     → If DENIED: Agent A is flagged, cannot participate

   IF Agent A IS verified:
     → Continue to payload verification

4. PAYLOAD VERIFICATION
   Agent B submits Agent A's payload to The Last Bastion for verification
   POST /refinery/submit → 5-layer verification pipeline
   → Schema Gatekeeper → Consistency → Forensic → Triangulation → Adversarial
   → Result: REJECTED / QUARANTINE / VERIFIED / GOLD

5. HANDOFF COMPLETION
   IF payload verdict >= VERIFIED:
     → Agent B accepts the payload
     → Transaction stamped on-chain via SwarmProofRegistry
     → Both agents' reputation scores updated on SwarmAgentRegistry

   IF payload verdict < VERIFIED:
     → Agent B rejects the handoff
     → Agent A's reputation score decremented
     → Rejection event logged on-chain

6. ON-CHAIN STAMP
   Every completed handoff produces:
   - Proof hash (SHA-256 of payload + agents + timestamp)
   - Transaction on Polygon Amoy via SwarmProofRegistry (0x110aff...e946)
   - Agent reputation update on SwarmAgentRegistry (0xc9177b...0D7D)
```

---

## Agent Lifecycle

```
UNREGISTERED → REGISTERED → VERIFICATION_PENDING → APPROVED / DENIED
                                                      ↓
                                              ACTIVE (can transact)
                                                      ↓
                                              REPUTATION TRACKING
                                              (0-100 score, on-chain)
```

### Registration
```
POST /m2m/register
{
  "agent_id": "agent_<uuid>",
  "role": "DATA_PROVIDER | DATA_CONSUMER | VERIFIER | BROKER",
  "capabilities": ["energy-data", "insurance-quotes", ...],
  "public_key": "<Ed25519 public key>"
}
→ Returns: API key, 50 starter credits, identity hash
```

### Identity Verification
- Ed25519 signature verification on every message
- Nonce-based anti-replay protection (300s freshness window)
- Rate limiting (60 req/min default, sliding window)
- 6-step auth pipeline: version → freshness → nonce → identity → rate limit → signature

### Reputation
- Starts at 50/100
- Successful verified handoffs: +2
- Gold verdicts: +5
- Rejected payloads: -10
- Quarantined payloads: -3
- Reputation stored on-chain via SwarmAgentRegistry.updateReputation()
- Any agent can query another's reputation (free read, no gas)

---

## Protocol Messages

Every A2A message follows the ProtocolMessage format:

```json
{
  "message_id": "<uuid>",
  "sender_id": "agent_<uuid>",
  "receiver_id": "agent_<uuid>",
  "message_type": "HANDOFF_REQUEST | HANDOFF_ACCEPT | HANDOFF_REJECT | VERIFY_REQUEST | VERIFY_RESPONSE",
  "payload_hash": "<sha256>",
  "timestamp": "<ISO8601>",
  "nonce": "<unique>",
  "signature": "<Ed25519 signature of message body>"
}
```

### Message Types

| Type | Direction | Purpose |
|---|---|---|
| `HANDOFF_REQUEST` | A → B | "I want to give you this payload" |
| `VERIFY_REQUEST` | B → Last Bastion | "Is this agent legit? Check this payload" |
| `VERIFY_RESPONSE` | Last Bastion → B | "Agent status: X, Payload verdict: Y" |
| `HANDOFF_ACCEPT` | B → A | "Payload accepted, here's the proof hash" |
| `HANDOFF_REJECT` | B → A | "Payload rejected, reason: Z" |
| `REGISTER_REDIRECT` | B → A | "You're not verified, go register at The Last Bastion" |

---

## Smart Contracts

### SwarmProofRegistry (0x110affBAC98FCC6b86Da499550B1fC0aCA22e946)
- `anchorProof(bytes32 blockHash, bytes32 previousHash)` — stamp a verified handoff
- `anchorBatch(bytes32[] blockHashes, bytes32 previousHash)` — batch stamp
- `verifyProof(bytes32 blockHash)` → free read, returns bool + timestamp
- Deployed on Polygon Amoy

### SwarmAgentRegistry (0xc9177baBF86FF16794AABd1a2169f898986a0D7D)
- `registerAgent(address agent, string role)` — on-chain identity
- `updateReputation(address agent, uint8 newScore)` — reputation update
- `registerService(address agent, string serviceId)` — service listing
- `recordTaskReceipt(address agent, bytes32 taskHash)` — task completion proof
- All lookups are free (no gas)
- Deployed on Polygon Amoy

---

## What Needs To Be Built

### Phase 1: Agent Verification Endpoint
- [ ] `POST /m2m/verify-agent/{agent_id}` — check if agent is registered + verified on The Last Bastion
- [ ] `AgentVerificationResult` model in database.py
- [ ] Agent analysis pipeline (check identity, history, reputation)
- [ ] Verdict: TRUSTED / SUSPICIOUS / MALICIOUS

### Phase 2: A2A Handoff Protocol
- [ ] `POST /m2m/handoff/request` — Agent A initiates handoff to Agent B
- [ ] `POST /m2m/handoff/accept` — Agent B accepts after verification
- [ ] `POST /m2m/handoff/reject` — Agent B rejects with reason
- [ ] Handoff transaction model in database
- [ ] Auto-redirect unregistered agents to registration

### Phase 3: Demo Agents
- [ ] Create 4 ecosystem agents (Financial, Insurance, Energy, IoT)
- [ ] Each agent can discover, authenticate, and communicate
- [ ] Implement the full handoff flow with real verification
- [ ] All handoffs go through the 5-layer pipeline
- [ ] All results stamped on-chain

### Phase 4: SwarmAgentRegistry Web3 Integration
- [ ] `blockchain_anchor.py` functions for SwarmAgentRegistry calls
- [ ] `register_agent_on_chain(agent_id, role)`
- [ ] `update_reputation_on_chain(agent_id, score)`
- [ ] `record_task_receipt_on_chain(agent_id, task_hash)`
- [ ] Free lookups: `get_agent_reputation(agent_id)`

### Phase 5: Frontend Visualization
- [ ] Real-time visualization of actual A2A handoffs (not animated mock)
- [ ] Show real agent verification status from the chain
- [ ] Display actual handoff transactions with proof hashes
- [ ] Live reputation scores from SwarmAgentRegistry

---

## Key Principles

1. **ZERO MOCK DATA** — Every data point shown on the dashboard comes from the database or blockchain. If there's no data, show "No data yet" — never fake it.

2. **ZERO TRUST** — Every agent must prove identity before every transaction. No cached trust. Verify every time.

3. **ON-CHAIN IMMUTABILITY** — Every handoff, verification, and reputation change is stamped on Polygon. Tamper-evident.

4. **AUTOMATIC ONBOARDING** — Unverified agents are automatically directed to register. No manual intervention needed.

5. **REPUTATION IS EARNED** — Agents start at 50/100. Every action moves the score. Bad actors are isolated automatically.
