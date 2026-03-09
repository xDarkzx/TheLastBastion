# Last Bastion SDK

Border police for agent ecosystems. Verify agents, issue cryptographic passports, and protect your endpoints from untrusted AI agents.

## Install

```bash
pip install lastbastion

# With gateway middleware (FastAPI/Starlette)
pip install lastbastion[gateway]

# With MCP tools (for AI agents)
pip install lastbastion[mcp]

# Everything
pip install lastbastion[all]
```

## Quick Start

```python
from lastbastion import LastBastionClient

async with LastBastionClient(base_url="https://api.thelastbastion.io") as client:
    # Generate Ed25519 keypair
    public_key, private_key = client.generate_keypair()

    # Full flow: register → sign challenge → verify → passport
    passport = await client.register_and_verify(
        agent_id="my-agent-001",
        public_key=public_key,
        private_key=private_key,
        agent_url="http://my-agent:9000",
        company_name="Acme Corp",
    )

    print(f"Passport: {passport['passport_id']}")
    print(f"Trust: {passport['trust_score']}")
    print(f"JWT: {passport['jwt_token'][:50]}...")
```

## Three Modes

### Mode 1: Client — Call The Last Bastion API

Register your agent, get verified through a 10-check pipeline, and receive a signed passport.

```python
from lastbastion import LastBastionClient

async with LastBastionClient(base_url="https://api.thelastbastion.io") as client:
    # Generate or bring your own Ed25519 keypair
    public_key, private_key = client.generate_keypair()

    # Step 1: Register (handles cryptographic challenge automatically)
    reg = await client.register_with_keypair(
        agent_id="my-agent",
        public_key=public_key,
        private_key=private_key,
    )
    # reg contains: api_key, trust_score, starter_credits

    # Step 2: Get verified (10-check pipeline)
    verification = await client.verify_agent("my-agent")
    # verification contains: trust_score, trust_level, verdict, checks breakdown

    # Step 3: Issue passport (requires TRUSTED verdict)
    passport = await client.issue_passport("my-agent", company_name="Acme Corp")

    # Step 4: Submit data for fraud verification
    result = await client.submit_payload({"invoice": {"total": 1500}})
    # result = {"verdict": "VERIFIED", "score": 0.82, "proof_hash": "abc123..."}
```

**Step-by-step registration (manual challenge-response):**

```python
# For agents that need to control the signing process
reg = await client.register_agent(
    agent_id="my-agent",
    public_key=public_key,
)
# reg = {"status": "CHALLENGE_ISSUED", "challenge_id": "reg-abc123", "nonce": "..."}

# Sign the nonce yourself
from lastbastion.crypto import sign_bytes
signature = sign_bytes(reg["nonce"].encode(), private_key)

# Complete registration
result = await client.complete_challenge(reg["challenge_id"], signature)
# result contains: api_key, trust_score, starter_credits
```

### Mode 2: MCP Tools — Mount in Your AI Agent

Give any MCP-compatible AI agent the ability to verify itself and check data.

```python
from lastbastion.mcp_tools import create_lastbastion_mcp

mcp = create_lastbastion_mcp(
    base_url="https://api.thelastbastion.io",
)

# Tools available to the AI agent:
# - get_verified: Submit for verification, receive passport
# - verify_payload: Check data for fraud (5-layer pipeline)
# - check_agent_trust: Look up another agent's trust score
# - verify_passport: Verify a passport JWT
```

### Mode 3: Gateway — Protect Your Endpoints

Add border control to your own API. Agents must present a valid passport to enter.

**FastAPI Middleware:**

```python
from lastbastion.gateway import LastBastionGateway

gateway = LastBastionGateway(
    issuer_public_key="abc123...",  # from GET /m2m/passport/issuer-key
    min_trust_level="BASIC",
    require_passport=True,
    verify_online=True,        # check revocation with Last Bastion
    cache_ttl_seconds=300,     # cache verified passports for 5 minutes
)

app.add_middleware(gateway.create_middleware())
```

**Standalone Middleware:**

```python
from lastbastion.middleware import LastBastionMiddleware

app.add_middleware(
    LastBastionMiddleware,
    issuer_public_key="abc123...",
    min_trust_level="VERIFIED",
    exclude_paths=["/health", "/docs"],
)
```

**Decorator:**

```python
@gateway.require_passport_decorator(min_trust="VERIFIED")
async def my_endpoint(request):
    agent = request.state.agent  # {"agent_id": "...", "trust_score": 0.85, ...}
    return {"message": f"Welcome, {agent['agent_id']}"}
```

**Manual Check:**

```python
decision = await gateway.check_agent(jwt_token)
if decision.allowed:
    print(f"Agent {decision.agent_id} allowed (trust: {decision.trust_score})")
else:
    print(f"Denied: {decision.reason}")
```

## Agent Passport

A passport is a signed JWT that proves an agent was verified by The Last Bastion. It contains:

| Category | Fields |
|----------|--------|
| Identity | `passport_id`, `agent_id`, `agent_name`, `public_key` |
| Organizational | `company_name`, `company_domain`, `agent_card_url` |
| Anti-cloning | `runtime_fingerprint`, `ip_allowlist_hash`, `geo_ip` |
| Trust | `trust_score`, `trust_level`, `verdict`, `checks_summary`, `risk_flags` |
| Cryptographic | `crypto_hash`, `proof_hash`, `blockchain_tx` |
| Lifecycle | `issuer`, `issued_at`, `expires_at` (90 days) |

### Anti-cloning Protection

Passports are hard to steal or clone:

- **Ed25519 challenge**: The passport contains a public key. Only the real agent has the matching private key. Challenge-response proves possession.
- **Runtime fingerprint**: Hash of OS + hostname. Changes on a different machine.
- **IP allowlist hash**: Mismatch if the request comes from an unexpected network.
- **Issuer signature**: JWT signed by The Last Bastion's Ed25519 key. Can't forge without the private key.
- **Crypto hash**: SHA-256 of all fields. Any tampering invalidates the passport.
- **Blockchain anchor**: Proof hash stored on-chain for independent verification.

### Offline Verification

The gateway works without calling The Last Bastion server. You only need the issuer's public key:

```python
# Get the issuer's public key once
# GET https://api.thelastbastion.io/m2m/passport/issuer-key
# {"public_key": "abc123...", "algorithm": "EdDSA"}

gateway = LastBastionGateway(
    issuer_public_key="abc123...",
    verify_online=False,  # No network calls
)
```

## Architecture

```
 Your Agent                    The Last Bastion                Your API
 ┌──────────┐                 ┌──────────────────┐           ┌────────────┐
 │          │──register────►  │  M2M Protocol    │           │            │
 │  SDK     │◄─challenge────  │  Challenge-Resp  │           │  Gateway   │
 │ Client   │──sign+verify─►  │  10-Check Trust  │           │ Middleware │
 │          │◄──passport────  │  Blockchain Stamp│           │            │
 │          │                 │                  │           │  Checks    │
 │          │──submit data──► │  5-Layer Verify  │           │  passport  │
 │          │◄──verdict─────  │  Proof Ledger    │           │            │
 └──────────┘                 └──────────────────┘           └────────────┘
      │                                                           │
      │                     Agent Passport (JWT)                  │
      └───────────────── Bearer token in header ──────────────────┘
```

## Trust Levels

| Level | Score | Meaning |
|-------|-------|---------|
| NONE | 0.00 | Unverified |
| NEW | 0.40 | Just registered |
| BASIC | 0.55 | Passed basic checks |
| VERIFIED | 0.65 | Full 10-check pipeline passed |
| ESTABLISHED | 0.75 | Track record of good behavior |
| GOLD | 0.90 | Highest trust — requires forensic verification |

## API Reference

### `LastBastionClient`

| Method | Description |
|--------|-------------|
| `generate_keypair()` | Generate Ed25519 keypair → `(public_hex, private_hex)` |
| `register_agent(agent_id, public_key, role, capabilities)` | Register (returns challenge) |
| `complete_challenge(challenge_id, signature)` | Complete challenge-response |
| `register_with_keypair(agent_id, public_key, private_key, ...)` | Register with auto-signing |
| `verify_agent(agent_id, agent_url, capabilities)` | Run 10-check trust verification |
| `get_trust_status(agent_id)` | Look up trust score (free) |
| `submit_payload(payload, context, source_agent_id)` | Submit data for fraud check |
| `issue_passport(agent_id, ...)` | Get a signed passport (requires TRUSTED) |
| `verify_passport(jwt_token)` | Verify a passport against the server |
| `get_passport(agent_id)` | Get latest passport |
| `renew_passport(agent_id)` | Re-verify and issue fresh passport |
| `register_and_verify(agent_id, ...)` | Full flow: register → verify → passport |
| `start_session(agent_id, config)` | Start sandbox test session |
| `run_attacks(session_id, attack_types)` | Run attack simulations |
| `handoff(sender_id, receiver_id, payload)` | Verified agent-to-agent handoff |

### `LastBastionGateway`

| Method | Description |
|--------|-------------|
| `check_agent(jwt_token, request)` | Manual passport check → `GatewayDecision` |
| `create_middleware()` | Returns Starlette middleware class |
| `require_passport_decorator(min_trust)` | Endpoint decorator |

### `AgentPassport`

| Method | Description |
|--------|-------------|
| `to_jwt(private_key)` | Serialize to signed JWT |
| `from_jwt(token, public_key)` | Deserialize and verify |
| `verify_integrity()` | Check crypto_hash |
| `is_expired()` | Check expiry |
| `seal()` | Compute crypto_hash |

## Configuration

### Environment Variables (Server-side)

| Variable | Description |
|----------|-------------|
| `PASSPORT_SIGNING_KEY` | Ed25519 private key (hex) for signing passports. Auto-generated if not set. |

### Gateway Options

| Option | Default | Description |
|--------|---------|-------------|
| `issuer_public_key` | `""` | Issuer's Ed25519 public key for offline verification |
| `min_trust_level` | `"BASIC"` | Minimum trust level to allow entry |
| `require_passport` | `True` | Reject requests without passports |
| `verify_online` | `True` | Check revocation with The Last Bastion server |
| `cache_ttl_seconds` | `300` | Cache verified passports for 5 minutes |
