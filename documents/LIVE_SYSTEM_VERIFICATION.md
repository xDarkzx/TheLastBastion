# Live System Verification — Captured Evidence

This document is not a claim, it's a record. Every value below was pulled
directly from a running instance of this system via `curl`/`docker logs` on
2026-07-19, not written from memory or intention. Where a JSON response or a
log line is shown, it is pasted verbatim, unedited except for truncation
noted as `...`. Anyone can reproduce every step below against a clean
checkout.

## Reproduction

```bash
git clone <this repo>
cd TheLastBastion
docker compose up --build -d
# wait ~60s for all 4 containers healthy + agent network boot
curl http://localhost:8000/health
curl http://localhost:8000/m2m/dashboard/stats
curl "http://localhost:8000/m2m/dashboard/activity?limit=20"
curl "http://localhost:8000/refinery/ledger?limit=10"
```

No Ollama, no GROQ key, no blockchain RPC, and no manual configuration
required for any of what follows — this is the default `docker-compose up`
experience.

## 1. The stack actually boots and stays healthy

```
$ docker ps --format "table {{.Names}}\t{{.Status}}"
NAMES                STATUS
aiagent-frontend-1   Up (healthy)
aiagent-api-1        Up (healthy)
aiagent-db-1         Up (healthy)
aiagent-redis-1      Up (healthy)

$ curl http://localhost:8000/health
{"status":"healthy","database":"connected","redis":"connected",
 "agent_network":"running","timestamp":"2026-07-19T00:00:11Z"}
```

## 2. Four independent agent processes actually boot, register, and are discovered

Each of `producer`, `compliance`, `logistics`, `buyer` is a real HTTP server
(A2A protocol) plus a real Bastion Protocol TCP listener, spawned as
embedded `uvicorn` instances inside the `api` container. Real HTTP requests
are made between them — no mocked responses.

```
$ curl "http://localhost:8000/m2m/dashboard/stats"
{"active_agents":4,"total_tasks":0,"total_extractions":15,
 "total_proofs_generated":4,"proofs_anchored_on_chain":0,
 "blockchain_connected":false}
```

`blockchain_connected: false` and `proofs_anchored_on_chain: 0` are
themselves evidence of honesty in this report: `web3` is not installed in
this image, so on-chain anchoring is disabled and this system says so
plainly rather than faking a transaction hash. See section 6.

Agent Card discovery (real HTTP GET against each agent's own
`/.well-known/agent-card.json`, not a static config file):

```
GET http://localhost:9001/.well-known/agent-card.json -> 200
GET http://localhost:9002/.well-known/agent-card.json -> 200
GET http://localhost:9003/.well-known/agent-card.json -> 200
GET http://localhost:9004/.well-known/agent-card.json -> 200
```

## 3. M2M registration is a real two-step Ed25519 challenge-response, not a static API key

`POST /m2m/register` returns a nonce, not a key:

```json
{"challenge_id":"reg-5b9c436e3ca6ab86",
 "nonce":"5af0f278eac45f85c41993def6d530647b653e8f132779a6f1128bf28e93d4ab",
 "status":"PENDING",
 "message":"Sign this nonce with your Ed25519 private key and POST to /m2m/register/verify",
 "expires_in_seconds":600}
```

The agent signs that nonce with its own Ed25519 private key and posts the
signature to `/m2m/register/verify`. The server verifies the signature
against the public key submitted in step 1 before issuing credentials — an
attacker who doesn't hold the matching private key cannot complete
registration, even if they know the target agent's public key and ID.

```
$ docker logs aiagent-api-1 | grep "M2M REGISTER VERIFIED"
M2M REGISTER VERIFIED: compliance-regional-001 -> sandbox key issued, trust=0.42
M2M REGISTER VERIFIED: logistics-maersk-001 -> sandbox key issued, trust=0.42
M2M REGISTER VERIFIED: buyer-sg-001 -> sandbox key issued, trust=0.42
```

## 4. A real Bastion Protocol trade — DIRECT mode, trusted transport

Actual log output from a real `DirectAgentSocket` connection between two of
the four agent processes, over a real TCP socket on localhost:

```
BASTION: producer -> compliance via DIRECT trusted transport (2ms handshake)
BASTION: compliance -> logistics via DIRECT trusted transport (2ms handshake)
BASTION: logistics -> buyer via DIRECT trusted transport (2ms handshake)
```

What "DIRECT mode, trusted transport" means concretely, and what it does
NOT mean:

- Identity **is** cryptographically proven at handshake time: X25519 ECDH
  key exchange + TOFU (trust-on-first-use) key pinning against a persisted
  trust store. An impersonation attempt (wrong private key for a known
  agent_id) is rejected — this is covered by an automated pytest test
  (`test_direct_mode_impersonation_rejected` in
  `tests/test_bastion_direct_and_resumption.py`).
- Post-handshake DATA frames are **not** encrypted and carry **no**
  per-frame signature. This is a deliberate choice, not an oversight: these
  four agents run inside one process/ecosystem this deployment controls
  end-to-end, so there is no hostile network between them for encryption to
  defend against. The dashboard activity feed says "DIRECT mode,
  authenticated" for these events — not "encrypted" — because that's what
  actually happens. An earlier version of this same code claimed
  "encrypted binary protocol" here after the switch to trusted transport;
  that was caught and corrected (see git history) precisely because it
  would have been a false claim.
- Crossing into a genuinely external/untrusted agent uses a different code
  path (`AgentSocket`, PASSPORT mode) that keeps full Ed25519 signing and
  NaCl encryption unconditionally. This demo does not exercise that path
  because there is no external ecosystem to cross into here.

## 5. The verification pipeline runs for real and produces a real, non-trivial verdict

This is a complete, unedited log capture of one actual submission going
through all five layers of `core/verification/verification_stack.py`:

```
VERIFICATION STACK: Processing payload
  Fields: 10
  Attachments: 0
  Context: {'document_type': 'buyer_verification', 'protocol': 'a2a',
            'submission_id': 'sub-f385646ca4248e0b',
            'data_hash': '3919132a40aba9d26fc7c215a65246f4e0996d47e148f643dda464e1befb8d03'}
  Gate 1 (Schema): skipped — no schema provided
  Gate 2 (Consistency): score=0.50
  Pillar 1 (Forensic): skipped — no attachments
  DOMAIN: 1 confirmed, 0 contradicted, score=1.00
  TEMPORAL: No history for domain 'unknown' — neutral
  TRIANGULATION: 3 confirmations, 0 contradictions, score=0.81
  Pillar 2 (Triangulation): score=0.81
  Pillar 3 (Attestation): no bundle provided
  ADVERSARIAL: 1 challenges, total_penalty=0.05, score=0.95
  Adversarial: score=0.95, challenges=1
  VERDICT: QUARANTINE (score=0.6340)
PROOF #4: QUARANTINE (score=0.6340), block=5ee50b8c9fb630fd..., chain_length=4
DATABASE: VerificationResult saved — QUARANTINE (score=0.6340, proof=5ee50b8c9fb630fd...)
DATABASE: DataQuarantine entry created for hash=3919132a40aba9d2...
DATABASE: BlockchainStamp saved — tx=pending...
```

**Why QUARANTINE and not VERIFIED, and why that's honest, not a bug:** the
demo's synthetic supply-chain data has no attachments (Pillar 1 skipped),
no schema (Gate 1 skipped), and no attestation bundle (Pillar 3 skipped) —
those three checks sit out entirely rather than being faked as passing.
With three of five layers neutral, the composite score is dominated by
Triangulation (0.81) and Consistency (0.50), landing at 0.634 — inside the
documented 0.40–0.70 QUARANTINE band (see `CLAUDE.md`'s verdict table).
This is the verification stack doing its job on thin synthetic data, not
a rubber stamp. A submission with real attachments and a real schema would
exercise the other two layers and score differently — that's not
demonstrated here because the demo doesn't generate that kind of data.

One real bug was found and fixed during this verification pass:
`_check_date_validity()` in `core/verification/triangulation/domain_logic.py`
was flagging every `expiry_date` field as "in the future" (a contradiction)
even though expiry dates are supposed to be in the future — this alone was
capping every producer batch's score low enough to halt the demo chain at
step 1. Fixed and covered by a manual regression check documented in the
commit that fixed it.

## 6. Tamper-evident proof chain — independently verifiable

Each verification produces a block whose hash chains to the previous one,
starting from a genesis hash of all zeros:

```json
{
  "proof_chain": [
    {"record_id": 1, "block_hash": "8d775922eed2c4d6e19eae2e4f8188fd081e6e41a96f1fc090380469f82f9927",
     "previous_hash": "0000000000000000000000000000000000000000000000000000000000000000",
     "verdict": "QUARANTINE", "score": 0.634},
    {"record_id": 2, "block_hash": "d3c452479bea2053b95bfefebc8a00b267217e9f640f681b7ff4c9e6feec0e31",
     "previous_hash": "8d775922eed2c4d6e19eae2e4f8188fd081e6e41a96f1fc090380469f82f9927",
     "verdict": "QUARANTINE", "score": 0.634},
    {"record_id": 3, "block_hash": "6bdf8dfb4cfd65f249dc2a8811a1902cfd6d999e0fed4b02324703354ad12ab0",
     "previous_hash": "d3c452479bea2053b95bfefebc8a00b267217e9f640f681b7ff4c9e6feec0e31",
     "verdict": "QUARANTINE", "score": 0.634}
  ]
}
```

Note record 2's `previous_hash` exactly equals record 1's `block_hash`, and
record 3's `previous_hash` exactly equals record 2's `block_hash` — a real
hash chain, not three independent records with a `verdict` field in common.
Any single edited byte in a past record breaks every hash after it.

Any record can be independently looked up and verified without trusting
the dashboard UI:

```
$ curl http://localhost:8000/m2m/verify/8d775922eed2c4d6e19eae2e4f8188fd081e6e41a96f1fc090380469f82f9927
{"verified":true,"proof_hash":"8d775922eed2c4d6e19eae2e4f8188fd081e6e41a96f1fc090380469f82f9927",
 "verdict":"QUARANTINE","score":0.634,"timestamp":"2026-07-19T00:00:32.563531",
 "chain_position":1,"source":"local_ledger"}
```

## 7. What's honestly NOT demonstrated here

- **On-chain anchoring**: `web3` is not installed in this image, so
  `BlockchainStamp.tx_hash` is `null` for every record above (`"tx=pending"`
  in the logs is the honest label for "never sent," not a real pending
  transaction). The Solidity contracts (`SwarmProofRegistry`,
  `SwarmAgentRegistry`) are deployed and documented in `CLAUDE.md` with real
  addresses on Polygon Amoy, but this Docker demo does not exercise that
  path.
- **Cross-ecosystem PASSPORT mode**: this demo only shows DIRECT mode
  (agents inside one ecosystem). PASSPORT mode (full Ed25519 signing +
  NaCl encryption, for crossing into an unfamiliar ecosystem) exists and is
  exercised by a standalone integration script,
  `tests/test_bastion_protocol_integration.py` (run directly with
  `python tests/test_bastion_protocol_integration.py`, not pytest) —
  but has no external party to demonstrate against in this Docker demo.
- **LLM-driven reasoning**: `Ollama`/`GROQ_API_KEY` are not configured in
  this environment, so LLM-dependent features (the "Think Tank" research
  loop) fail with `OLLAMA_ERROR: 404` and degrade gracefully rather than
  block anything else, per the graceful-degradation pattern documented
  throughout `CLAUDE.md`. This is visible directly in the container logs,
  not hidden.
- **Speed**: see `documents/BENCHMARK_METHODOLOGY.md` — Bastion Protocol is
  measured slower than plain JSON on both platforms tested, in both
  round-trip and pipelined patterns. That finding stands; nothing in this
  document changes it.
