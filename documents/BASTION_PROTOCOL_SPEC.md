# Bastion Protocol v0.2 -- Agent-to-Agent Wire Protocol

**Status:** Draft
**Date:** 2026-03-08
**Author:** Daniel Hodgetts
---

## 1. Overview

Bastion Protocol is a binary agent-to-agent communication protocol that runs on top of TCP (via WebSocket tunnel for firewall traversal). It is NOT HTTP. It has no URLs, no headers, no status codes, no content types.

**Design principles:**
- Security is the protocol, not a bolt-on
- Binary-native -- no human-readable overhead
- Passport-based identity built into the handshake
- Every frame is signed and encrypted -- no exceptions
- Hard dependencies only (PyNaCl, msgpack) -- no silent fallbacks
- Simple enough to fit in one document

**What it replaces:** HTTP/REST/JSON for agent-to-agent communication.
**What it does NOT replace:** Agent discovery (Agent Cards stay on HTTP -- they're public, indexable). Discovery is the one place HTTP makes sense.

**Hard dependencies:**
- `pynacl` -- Ed25519 signing, X25519 DH, NaCl SecretBox encryption
- `msgpack` -- Binary serialization (no JSON fallback -- ensures cross-language interop)

---

## 2. Transport

### 2.1 WebSocket Tunnel

To traverse corporate firewalls and NAT, connections start as a standard WebSocket upgrade on port 443:

```
Agent A connects to wss://agent-b.example.com:443/bastion
HTTP upgrade handshake completes (one time)
WebSocket established
From this point: pure binary Bastion Protocol frames
No more HTTP. Ever.
```

The WebSocket is a dumb pipe. It carries binary frames. The Bastion Protocol operates entirely inside WebSocket binary messages.

### 2.2 Direct TCP (Optional)

In environments where firewall traversal is not needed (internal networks, Docker, same-host), agents MAY connect via raw TCP on a configurable port (default 9100). The protocol is identical -- only the transport wrapper differs.

---

## 3. Wire Format

### 3.1 Frame Structure

Every message is a single binary frame:

```
+----------+----------+-----------+----------+---------+--------------+-----------+
| Version  | Msg Type | Passport  | Sequence | Payload |   Payload    | Signature |
| 1 byte   | 1 byte   |  Hash     |  Number  | Length  |  (encrypted) | (Ed25519) |
|          |          |  16 bytes |  4 bytes | 4 bytes |  N bytes     | 64 bytes  |
+----------+----------+-----------+----------+---------+--------------+-----------+

Fixed overhead: 90 bytes per frame.
```

| Field | Size | Description |
|---|---|---|
| `version` | 1 byte | Protocol version. Current: `0x01` |
| `msg_type` | 1 byte | Message type (see 3.2) |
| `passport_hash` | 16 bytes | First 16 bytes of sender's passport SHA-256. Must match handshake. |
| `sequence` | 4 bytes | Monotonically increasing counter (big-endian unsigned). Starts at 0. Max: 2^32-1. |
| `payload_length` | 4 bytes | Length of encrypted payload in bytes (big-endian unsigned). Max: 16,777,216 (16MB). |
| `payload` | N bytes | Encrypted with session key (NaCl SecretBox). |
| `signature` | 64 bytes | Ed25519 signature over all preceding bytes (version through payload). |

### 3.2 Message Types

```
0x01  HELLO          Initiate connection -- carries passport JWT + nonce + timestamp
0x02  HELLO_ACK      Accept connection -- carries responder's passport JWT + nonce echo
0x03  DATA           Normal message payload
0x04  DATA_ACK       Acknowledgement of received DATA
0x05  STREAM_START   Begin large payload transfer
0x06  STREAM_CHUNK   Chunk of large payload
0x07  STREAM_END     Complete large payload transfer
0x08  PING           Keepalive probe
0x09  PONG           Keepalive response
0x0A  ERROR          Error notification (always unencrypted -- enables crypto failure reporting)
0x0B  CLOSE          Clean disconnect (bidirectional)
```

### 3.3 Unencrypted Frame Types

HELLO, HELLO_ACK, and ERROR frames are NOT encrypted:
- HELLO/HELLO_ACK: No session key exists yet
- ERROR: Must be sendable when crypto fails (e.g., decryption error, key mismatch)

All three ARE signed with the sender's Ed25519 key.

### 3.4 Serialization

Payloads are serialized with **MessagePack** (binary, cross-language). No JSON fallback -- this ensures binary interoperability across Python, Go, Rust, JS, etc.

### 3.5 Strict Frame Parsing

- Frames shorter than 90 bytes (header + signature) are rejected
- Frames with trailing data beyond the declared payload + signature are rejected
- Payload length > MAX_FRAME_SIZE is rejected without allocating memory
- Unknown message types are rejected
- Unsupported protocol versions are rejected

---

## 4. Connection Lifecycle

### 4.1 Handshake

```
Agent A (initiator)                    Agent B (responder)
       |                                      |
       |--- HELLO -------------------------------->|
       |    payload: {                         |
       |      passport_jwt: "eyJ...",          |
       |      ephemeral_pub: <32 bytes>,       |
       |      supported_versions: [1],         |
       |      nonce: <32 bytes>,               |
       |      timestamp: 1741456000.0,         |
       |    }                                  |
       |    signed with Agent A's Ed25519 key  |
       |                                      |
       |                          Verify passport JWT
       |                          Check trust score
       |                          Validate timestamp (< 30s)
       |                          If unacceptable:
       |                            send ERROR, close
       |                                      |
       |<-- HELLO_ACK ----------------------------|
       |    payload: {                         |
       |      passport_jwt: "eyJ...",          |
       |      ephemeral_pub: <32 bytes>,       |
       |      chosen_version: 1,               |
       |      nonce: <32 bytes>,               |
       |      peer_nonce: <Agent A's nonce>,   |
       |      timestamp: 1741456000.5,         |
       |    }                                  |
       |    signed with Agent B's Ed25519 key  |
       |                                      |
       |  Verify passport JWT                  |
       |  Verify peer_nonce matches            |
       |  Validate timestamp (< 30s)           |
       |  Derive session key:                  |
       |    session_key = DH(eph_A, eph_B)     |
       |  Both sides now share session_key     |
       |                                      |
       |--- DATA (encrypted) ------------------>|
       |<-- DATA_ACK (encrypted) ---------------|
       |         ... communication ...         |
```

### 4.2 Handshake Security

- **Nonce**: Each side includes a 32-byte random nonce. HELLO_ACK echoes the initiator's nonce to prove it's responding to THIS handshake (prevents replay).
- **Timestamp**: Both HELLO and HELLO_ACK include a timestamp. Frames older than 30 seconds are rejected (prevents recorded-and-replayed handshakes).
- **Mutual verification**: Both sides MUST verify the peer's passport JWT with a known public key. Empty/missing verify keys are not allowed.

### 4.3 Session Key Derivation

1. Each side generates an ephemeral X25519 key pair for this session only
2. Ephemeral public keys are exchanged in HELLO/HELLO_ACK (signed by passport Ed25519 key)
3. Session key = X25519 Diffie-Hellman shared secret
4. Encryption: NaCl SecretBox (XSalsa20 + Poly1305)
5. Ephemeral private keys are destroyed when the connection closes
6. This provides **forward secrecy** -- compromising passport keys cannot decrypt past sessions

### 4.4 Keepalive

- Either side MAY send PING at any time
- Receiver MUST respond with PONG within 5 seconds
- If no PONG received: connection is dead, close immediately
- Recommended PING interval: 30 seconds

### 4.5 Clean Shutdown (Bidirectional)

1. Initiating side sends CLOSE frame
2. Receiving side sends CLOSE frame back
3. Both sides tear down connection
4. Session key is destroyed
5. Timeout: 2 seconds for peer's CLOSE response

### 4.6 Sequence Overflow

- Sequence numbers are 4 bytes unsigned (max 2^32-1 = 4,294,967,295)
- When sequence reaches max, the encoder raises OverflowError
- Agent must reconnect (new handshake, new session key, sequence resets to 0)
- At 1000 frames/second, overflow takes ~49 days

---

## 5. Streaming (Large Payloads)

For payloads exceeding MAX_FRAME_SIZE or for continuous data transfer:

```
STREAM_START  ->  payload: { stream_id: <4 bytes>, total_size: <8 bytes>,
                             chunk_count: <4 bytes>, content_hash: <32 bytes> }
STREAM_CHUNK  ->  payload: { stream_id: <4 bytes>, chunk_index: <4 bytes>,
                             data: <bytes> }
STREAM_CHUNK  ->  ...
STREAM_END    ->  payload: { stream_id: <4 bytes>, final_hash: <32 bytes> }
```

- Each chunk is individually encrypted and signed
- Receiver verifies `final_hash` matches SHA-256 of reassembled data
- If hash mismatch: entire stream is discarded, ERROR sent
- Max chunk size: MAX_FRAME_SIZE (16MB default)
- **Stream size cap**: Configurable per-connection (default 256MB). Streams declaring `total_size` above the cap are rejected at STREAM_START.

---

## 6. Error Handling

ERROR frames carry a MessagePack payload:

```msgpack
{
  "code": <uint16>,
  "message": <string>
}
```

ERROR frames are **always unencrypted** so they can report crypto failures (decryption errors, key mismatches) even when the session is broken.

Error codes:

| Code | Meaning | Fatal |
|---|---|---|
| 1000 | Generic error | No |
| 1001 | Invalid frame format | No |
| 1002 | Passport verification failed | Yes |
| 1003 | Trust score insufficient | Yes |
| 1004 | Sequence number violation | Yes |
| 1005 | Frame too large | Yes |
| 1006 | Incomplete frame timeout | Yes |
| 1007 | Version not supported | Yes |
| 1008 | Signature verification failed | Yes |
| 1009 | Decryption failed | Yes |
| 1010 | Stream hash mismatch | No |
| 1011 | Ping timeout | No |
| 1012 | Budget exhausted | No |
| 1013 | Agent locked out (MALICIOUS verdict) | Yes |

After sending/receiving a fatal error, the connection MUST be closed.

---

## 7. Security Properties (Structural)

These are enforced by the protocol itself. They cannot be violated without breaking the parser. There are no configuration options to disable them.

### 7.1 No Unsigned Messages

Every frame includes a 64-byte Ed25519 signature over all preceding bytes. The parser rejects frames with invalid signatures before processing the payload. There is no unsigned mode.

### 7.2 Mandatory Mutual Authentication

Both sides MUST present a passport in the HELLO/HELLO_ACK exchange. There is no server-only authentication. There is no anonymous mode. Both sides MUST verify the peer's passport JWT with a known public key.

### 7.3 Mandatory Encryption

After the handshake, all payloads are encrypted with the session key (NaCl SecretBox -- XSalsa20 + Poly1305). There is no plaintext mode. The only unencrypted frames are HELLO, HELLO_ACK, and ERROR.

### 7.4 Replay Protection

- **Sequence numbers**: Monotonically increasing, starting at 0. Any gap, regression, or duplicate causes immediate connection termination.
- **Handshake nonce**: 32-byte random nonce in HELLO, echoed in HELLO_ACK. Prevents replayed handshakes.
- **Handshake timestamp**: Frames older than 30 seconds are rejected. Prevents recorded-and-replayed handshakes.

### 7.5 Identity Binding

The `passport_hash` field (first 16 bytes of passport SHA-256) is present in EVERY frame and must match the passport presented during handshake. An attacker cannot inject frames pretending to be the authenticated agent without knowing the passport hash and possessing the signing key.

### 7.6 Max Frame Size

Frames declaring `payload_length > MAX_FRAME_SIZE` (default 16MB) are rejected immediately without allocating memory. This prevents memory exhaustion attacks. The parser reads the 4-byte length, checks the limit, and kills the connection if exceeded.

### 7.7 Incomplete Frame Timeout

If a complete frame is not received within 5 seconds of the first byte, the connection is terminated. This prevents slowloris-style attacks where an attacker sends partial frames to tie up resources.

### 7.8 Signed Version Negotiation

The HELLO frame contains `supported_versions` and the HELLO_ACK contains `chosen_version`. Both are inside signed frames. An attacker cannot modify version selection via MITM without breaking the signature. This prevents protocol downgrade attacks.

### 7.9 Forward Secrecy

Session keys are derived from ephemeral X25519 key exchange. Ephemeral keys are generated per-connection and destroyed on disconnect. Even if an agent's long-term Ed25519 passport key is later compromised, past recorded sessions cannot be decrypted.

### 7.10 No Silent Crypto Degradation

Hard dependencies on PyNaCl and msgpack. There are no HMAC fallbacks, no XOR "encryption" fallbacks, no JSON serialization fallbacks. If PyNaCl is not installed, the module refuses to load. This prevents accidental deployment with broken security.

### 7.11 No Selective Enforcement

There is no configuration to disable signing, disable encryption, allow anonymous connections, or skip passport verification. These properties are structural -- the frame format does not have optional security fields.

### 7.12 Concurrency Safety

Send and receive operations are protected by asyncio.Lock to prevent interleaved frames from concurrent coroutines. Sequence numbers remain monotonic regardless of concurrency.

### 7.13 Architectural Limitation: Single Passport Authority

> **NOTE:** In its current form, the Bastion Protocol relies on a single passport authority (the issuing service) to sign and validate agent passports. This is a known single point of failure. If the passport authority's signing key is compromised, every passport it issued becomes untrustworthy, and the entire trust chain collapses.
>
> For the protocol to be effective in production at scale, **federated passport issuance is required**. The target architecture:
>
> 1. **Multiple independent passport authorities** operated by different organizations. No single entity controls trust issuance.
> 2. **M-of-N cross-signing** -- a passport is only valid if signed by at least M of N authorities (e.g., 2 of 3). No single authority can unilaterally issue a trusted passport.
> 3. **Revocation cascade** -- when one authority is compromised:
>    - Remaining authorities detect the breach (anomalous signing patterns, key leak disclosure, peer challenge failure)
>    - Compromised authority's signing key is revoked across all peers
>    - Passports signed **only** by the compromised authority are invalidated immediately
>    - Passports cross-signed by healthy authorities remain valid (graceful degradation)
>    - Agents holding invalidated passports must re-authenticate with the remaining authorities
> 4. **Key rotation schedule** -- authorities rotate signing keys on a fixed cadence. Old keys expire after a grace period. This bounds the blast radius of any undiscovered compromise.
> 5. **Authority discovery** -- passport authorities publish their current public keys via signed Agent Cards (HTTP, same as agent discovery). Agents and relying parties can independently verify which authorities are active and fetch their current keys.
>
> The wire format already supports this: the `passport_hash` field in every frame is a hash of the passport contents, not a reference to a specific issuer. Multiple issuers can sign the same passport fields. The handshake carries the full passport JWT, which can contain multiple issuer signatures. No protocol changes are required -- only the passport structure and verification logic need to evolve.
>
> This is not built yet. The current implementation uses a single issuer key pair. Federated issuance is the path from prototype to production trust infrastructure.

---

## 8. Observability

### 8.1 Protocol Metrics

Every connection tracks:
- `frames_sent` / `frames_received` -- frame counters
- `bytes_sent` / `bytes_received` -- wire bytes
- `errors` -- error frame count
- `pings_sent` / `pongs_received` -- keepalive health

### 8.2 Hooks

Optional callbacks on AgentSocket:
- `on_frame_sent(frame)` -- fires after every frame write
- `on_frame_received(frame)` -- fires after every frame read

Use for logging, metrics export, debugging, or integration with monitoring systems.

---

## 9. What the Protocol Does NOT Do

The protocol is deliberately thin. These concerns belong to the SDK and service layer:

| Concern | Where it lives | Why not in the protocol |
|---|---|---|
| Trust score evaluation | SDK / Last Bastion service | Trust algorithms evolve constantly |
| Escalation tiers | SDK / Last Bastion service | Policy changes shouldn't require protocol updates |
| Budget tracking | SDK / Last Bastion service | Business logic, not wire format |
| Behavioral analysis | Last Bastion service | Requires historical data the protocol doesn't carry |
| Appeal system | Last Bastion service | Human-in-the-loop process |
| Sandbox testing | Last Bastion service | Complex multi-step process |
| Agent discovery | HTTP (Agent Cards) | Discovery is public and indexable |
| Blockchain anchoring | Last Bastion service | Optional feature, not transport concern |

The protocol guarantees the physics: identity, integrity, confidentiality, freshness.
The SDK and service provide the judgement: trust, policy, escalation, reputation.

---

## 10. Comparison with HTTP/REST

| Aspect | HTTP/REST | Bastion Protocol |
|---|---|---|
| Overhead per message | 500-2000 bytes (headers) | 90 bytes (fixed frame header) |
| Serialization | JSON (text, slow to parse) | MessagePack (binary, 2-5x faster) |
| Authentication | Optional (headers, can be forgotten) | Mandatory (handshake, structural) |
| Encryption | Optional (TLS, can be misconfigured) | Mandatory (NaCl, no plaintext mode) |
| Signing | Rare (custom implementation) | Every frame (structural) |
| Large payloads | Multipart + base64 (33% bloat) | Native streaming (zero bloat) |
| Connection model | Request/response (stateless) | Persistent (authenticated session) |
| Replay protection | None (must implement yourself) | Monotonic sequences + nonce + timestamp |
| Attack surface | Entire OWASP Top 10 | Zero -- tools don't speak this protocol |
| Forward secrecy | Depends on TLS config | Mandatory (ephemeral DH) |
| Crypto fallbacks | TLS allows weak ciphers | None -- PyNaCl or nothing |

---

## 11. SDK Interface

The SDK abstracts the protocol completely. Developers never touch binary frames.

### 11.1 Server (Receiving Agent)

```python
from lastbastion.protocol import AgentSocket

async def handle_agent(conn):
    # conn.peer -- verified agent identity
    print(f"Connected: {conn.peer.agent_id} (trust: {conn.peer.trust_score})")

    msg = await conn.recv()              # auto decrypt + verify
    await conn.send({"status": "ok"})    # auto encrypt + sign

    # Large payload -- same API, auto-chunked
    await conn.send_stream(large_data)

    # Metrics
    print(f"Frames: {conn.metrics.frames_sent} sent, {conn.metrics.frames_received} recv")

server = AgentSocket.listen(
    port=9100,
    passport=my_passport,
    signing_key=my_private_key,
    verify_key=issuer_public_key,  # REQUIRED
)
server.on_connect(handle_agent)
await server.start()
```

### 11.2 Client (Connecting Agent)

```python
from lastbastion.protocol import AgentSocket

conn = await AgentSocket.connect(
    "agent-b.example.com:443",
    passport=my_passport,
    signing_key=my_private_key,
    verify_key=issuer_public_key,  # REQUIRED
)
await conn.send({"task": "verify", "data": payload})
result = await conn.recv()
await conn.close()
```

### 11.3 What the SDK Handles Automatically

- HELLO/HELLO_ACK exchange with passport, nonce, timestamp
- Ephemeral key generation and session key derivation (X25519)
- Frame construction, signing (Ed25519), encryption (NaCl SecretBox)
- Frame parsing, signature verification, decryption
- Sequence number tracking and enforcement (with overflow detection)
- PING/PONG keepalive with timeout
- Stream chunking for large payloads (with size cap)
- Bidirectional CLOSE shutdown
- Incomplete frame timeout enforcement
- Max frame size enforcement
- Concurrency safety (asyncio.Lock)
- Observability metrics and hooks

---

## 12. Implementation Roadmap

### Phase 1: Frame Layer (DONE)
- Binary frame encoder/decoder with 16-byte passport hash
- Message type enum (11 types)
- Ed25519 signature generation and verification (PyNaCl, no fallback)
- Max frame size enforcement
- Sequence number tracking with overflow detection
- Trailing data rejection
- MessagePack serialization (no JSON fallback)

### Phase 2: Handshake (DONE)
- HELLO/HELLO_ACK with nonce + timestamp
- Passport exchange and JWT verification (verify_key mandatory)
- Ephemeral X25519 key generation
- Diffie-Hellman session key derivation
- Version negotiation
- Timestamp freshness validation (30s window)
- Nonce echo for replay prevention

### Phase 3: AgentSocket (DONE)
- Direct TCP transport (via asyncio)
- Connection lifecycle (connect, handshake, communicate, close)
- send/recv with automatic encrypt/sign + concurrency locks
- PING/PONG keepalive with timeout enforcement
- Bidirectional CLOSE
- Stream size cap (default 256MB)
- Connection cleanup on server
- Observability metrics + hooks
- Incomplete frame timeout

### Phase 4: WebSocket Transport (PLANNED)
- WebSocket tunnel via `websockets` library
- WSS on port 443 for firewall traversal
- Transparent to application layer (same AgentConnection API)

### Phase 5: Integration (PLANNED)
- Wire into Last Bastion trust pipeline
- AgentSocket as alternative to HTTP endpoints
- HTTP bridge endpoint for gradual migration
- Multi-language SDK (Go, Rust, JS)
