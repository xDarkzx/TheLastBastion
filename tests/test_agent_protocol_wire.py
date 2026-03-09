"""
Tests for the Bastion Protocol v2 -- binary agent-to-agent wire format.

Covers:
1. Frame encoding/decoding (v2: flags + full hash + timestamp)
2. Message types
3. Sequence number enforcement (monotonic, replay, gap, overflow)
4. Max frame size rejection
5. Passport hash validation (32 bytes, full SHA-256)
6. Serialization (MessagePack)
7. Handshake (HELLO/HELLO_ACK) with nonce + timestamp
8. Session key derivation (X25519 DH)
9. Encrypt/decrypt round-trip (NaCl SecretBox)
10. Full connection lifecycle (server + client over TCP)
11. Streaming large payloads with size cap
12. Trailing data rejection
13. Corrupted/tampered frame detection
14. Observability metrics
15. Bidirectional CLOSE
16. Frame flags (COMPRESSED, FRAGMENTED, PRIORITY, FRESHNESS_STRICT)
17. Per-frame timestamp freshness enforcement
18. Reserved flags rejection
19. Nonce anti-replay registry (cross-session duplicate rejection + purge)
"""

import sys
import os
import asyncio
import time
import struct

# Add SDK to path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "sdk"))


# ---------------------------------------------------------------------------
# Frame tests
# ---------------------------------------------------------------------------

def test_frame_encode_decode():
    """Frame should survive encode/decode round-trip."""
    from lastbastion.protocol.frames import BastionFrame, FrameType, FrameFlags, PROTOCOL_VERSION, PASSPORT_HASH_SIZE

    test_hash = bytes(range(32))  # 32-byte passport hash (full SHA-256)
    test_timestamp = 1709900000_000000  # Fixed timestamp in microseconds

    frame = BastionFrame(
        version=PROTOCOL_VERSION,
        msg_type=FrameType.DATA,
        flags=FrameFlags.NONE,
        passport_hash=test_hash,
        sequence=42,
        timestamp_us=test_timestamp,
        payload=b"hello world",
        signature=b"\xaa" * 64,
    )

    raw = frame.to_bytes()
    restored = BastionFrame.from_bytes(raw)

    assert restored.version == PROTOCOL_VERSION
    assert restored.msg_type == FrameType.DATA
    assert restored.flags == FrameFlags.NONE
    assert restored.passport_hash == test_hash
    assert restored.sequence == 42
    assert restored.timestamp_us == test_timestamp
    assert restored.payload == b"hello world"
    assert restored.signature == b"\xaa" * 64
    print("  PASS: Frame v2 encode/decode round-trip")


def test_frame_all_message_types():
    """All message types should encode/decode correctly."""
    from lastbastion.protocol.frames import BastionFrame, FrameType, PASSPORT_HASH_SIZE

    for ftype in FrameType:
        frame = BastionFrame(
            msg_type=ftype,
            passport_hash=b"\x00" * PASSPORT_HASH_SIZE,
            sequence=0,
            payload=b"",
            signature=b"\x00" * 64,
        )
        raw = frame.to_bytes()
        restored = BastionFrame.from_bytes(raw)
        assert restored.msg_type == ftype, f"Failed for {ftype.name}"
    print(f"  PASS: All {len(FrameType)} message types encode/decode correctly")


def test_frame_too_short():
    """Frame shorter than minimum should raise ValueError."""
    from lastbastion.protocol.frames import BastionFrame
    try:
        BastionFrame.from_bytes(b"\x00" * 10)
        assert False, "Should have raised ValueError"
    except ValueError as e:
        assert "too short" in str(e).lower()
    print("  PASS: Short frame rejected")


def test_frame_invalid_version():
    """Frame with wrong version should raise ValueError."""
    from lastbastion.protocol.frames import BastionFrame, FrameType, PASSPORT_HASH_SIZE, FRAME_HEADER_SIZE

    # Build a v2 frame with version 0xFF
    header = struct.pack(">BBH32sIQI", 0xFF, FrameType.DATA, 0, b"\x00" * PASSPORT_HASH_SIZE, 0, 0, 0)
    raw = header + b"\x00" * 64  # signature
    try:
        BastionFrame.from_bytes(raw)
        assert False, "Should have raised ValueError"
    except ValueError as e:
        assert "version" in str(e).lower()
    print("  PASS: Invalid version rejected")


def test_frame_unknown_type():
    """Frame with unknown message type should raise ValueError."""
    from lastbastion.protocol.frames import BastionFrame, PASSPORT_HASH_SIZE, PROTOCOL_VERSION

    header = struct.pack(">BBH32sIQI", PROTOCOL_VERSION, 0xFF, 0, b"\x00" * PASSPORT_HASH_SIZE, 0, 0, 0)
    raw = header + b"\x00" * 64
    try:
        BastionFrame.from_bytes(raw)
        assert False, "Should have raised ValueError"
    except ValueError as e:
        assert "unknown" in str(e).lower()
    print("  PASS: Unknown message type rejected")


def test_frame_max_size_enforcement():
    """Payload declaring size > MAX_FRAME_SIZE should be rejected."""
    from lastbastion.protocol.frames import BastionFrame, MAX_FRAME_SIZE, PASSPORT_HASH_SIZE, PROTOCOL_VERSION

    too_large = MAX_FRAME_SIZE + 1
    header = struct.pack(">BBH32sIQI", PROTOCOL_VERSION, 0x03, 0, b"\x00" * PASSPORT_HASH_SIZE, 0, 0, too_large)
    raw = header + b"\x00" * (too_large + 64)
    try:
        BastionFrame.from_bytes(raw)
        assert False, "Should have raised ValueError"
    except ValueError as e:
        assert "too large" in str(e).lower()
    print(f"  PASS: Frame > {MAX_FRAME_SIZE} bytes rejected")


def test_frame_encoder_max_size():
    """Encoder should reject payloads exceeding MAX_FRAME_SIZE."""
    from lastbastion.protocol.frames import FrameEncoder, FrameType, MAX_FRAME_SIZE, PASSPORT_HASH_SIZE

    encoder = FrameEncoder(b"\x00" * PASSPORT_HASH_SIZE)
    try:
        encoder.encode(FrameType.DATA, b"\x00" * (MAX_FRAME_SIZE + 1))
        assert False, "Should have raised ValueError"
    except ValueError as e:
        assert "MAX_FRAME_SIZE" in str(e)
    print("  PASS: Encoder rejects oversized payloads")


def test_frame_trailing_data_rejected():
    """Frame with trailing data after signature should be rejected."""
    from lastbastion.protocol.frames import BastionFrame, FrameType, PASSPORT_HASH_SIZE

    frame = BastionFrame(
        msg_type=FrameType.DATA,
        passport_hash=b"\x00" * PASSPORT_HASH_SIZE,
        sequence=0,
        payload=b"test",
        signature=b"\x00" * 64,
    )
    raw = frame.to_bytes() + b"\xDE\xAD"  # Trailing garbage
    try:
        BastionFrame.from_bytes(raw)
        assert False, "Should have raised ValueError"
    except ValueError as e:
        assert "trailing" in str(e).lower()
    print("  PASS: Trailing data rejected")


def test_frame_tampered_payload():
    """Frame with tampered payload should fail signature verification."""
    from lastbastion.protocol.frames import FrameEncoder, FrameDecoder, FrameType, PASSPORT_HASH_SIZE
    from lastbastion.crypto import generate_keypair

    pub, priv = generate_keypair()
    encoder = FrameEncoder(b"\x00" * PASSPORT_HASH_SIZE, signing_key=priv)
    frame = encoder.encode(FrameType.DATA, b"original payload")

    # Tamper with the payload bytes in the raw frame
    raw = bytearray(frame.to_bytes())
    # Flip a byte in the payload area (after header)
    from lastbastion.protocol.frames import FRAME_HEADER_SIZE
    raw[FRAME_HEADER_SIZE] ^= 0xFF
    raw = bytes(raw)

    decoder = FrameDecoder(verify_key=pub)
    try:
        decoder.decode(raw)
        assert False, "Should have raised ValueError for tampered frame"
    except ValueError as e:
        assert "signature" in str(e).lower() or "verification" in str(e).lower()
    print("  PASS: Tampered payload detected via signature")


def test_frame_wrong_passport_hash():
    """Decoder should reject frames with wrong passport hash."""
    from lastbastion.protocol.frames import FrameEncoder, FrameDecoder, FrameType, PASSPORT_HASH_SIZE

    encoder = FrameEncoder(b"\x11" * PASSPORT_HASH_SIZE)
    frame = encoder.encode(FrameType.DATA, b"test")

    # Decoder expects a different hash
    decoder = FrameDecoder(expected_passport_hash=b"\x22" * PASSPORT_HASH_SIZE)
    try:
        decoder.decode(frame.to_bytes())
        assert False, "Should have raised ValueError for passport hash mismatch"
    except ValueError as e:
        assert "passport hash mismatch" in str(e).lower()
    print("  PASS: Wrong passport hash rejected")


# ---------------------------------------------------------------------------
# Serialization tests
# ---------------------------------------------------------------------------

def test_payload_serialization():
    """Dict payload should survive serialize/deserialize."""
    from lastbastion.protocol.frames import serialize_payload, deserialize_payload

    data = {
        "agent_id": "test-001",
        "score": 0.85,
        "flags": ["none"],
        "nested": {"key": "value"},
    }
    raw = serialize_payload(data)
    restored = deserialize_payload(raw)

    assert restored["agent_id"] == "test-001"
    assert restored["score"] == 0.85
    assert restored["flags"] == ["none"]
    assert restored["nested"]["key"] == "value"
    print(f"  PASS: Payload serialization round-trip ({len(raw)} bytes)")


def test_passport_hash():
    """Passport hash should be deterministic 32 bytes (full SHA-256)."""
    from lastbastion.protocol.frames import compute_passport_hash, PASSPORT_HASH_SIZE

    h1 = compute_passport_hash("pp-abc123")
    h2 = compute_passport_hash("pp-abc123")
    h3 = compute_passport_hash("pp-xyz789")

    assert h1 == h2, "Same passport should produce same hash"
    assert h1 != h3, "Different passports should produce different hashes"
    assert len(h1) == PASSPORT_HASH_SIZE, f"Hash should be {PASSPORT_HASH_SIZE} bytes, got {len(h1)}"
    assert PASSPORT_HASH_SIZE == 32, "v2 uses full SHA-256 (32 bytes)"
    print(f"  PASS: Passport hash is deterministic {PASSPORT_HASH_SIZE} bytes (full SHA-256)")


# ---------------------------------------------------------------------------
# Sequence enforcement tests
# ---------------------------------------------------------------------------

def test_sequence_monotonic():
    """Encoder should produce monotonically increasing sequences."""
    from lastbastion.protocol.frames import FrameEncoder, FrameType, PASSPORT_HASH_SIZE

    encoder = FrameEncoder(b"\x00" * PASSPORT_HASH_SIZE)
    f1 = encoder.encode(FrameType.DATA, b"a")
    f2 = encoder.encode(FrameType.DATA, b"b")
    f3 = encoder.encode(FrameType.DATA, b"c")

    assert f1.sequence == 0
    assert f2.sequence == 1
    assert f3.sequence == 2
    print("  PASS: Encoder produces monotonic sequences")


def test_decoder_sequence_violation():
    """Decoder should reject out-of-order sequences."""
    from lastbastion.protocol.frames import (
        FrameEncoder, FrameDecoder, FrameType, BastionFrame, PASSPORT_HASH_SIZE
    )

    encoder = FrameEncoder(b"\x00" * PASSPORT_HASH_SIZE)
    decoder = FrameDecoder()

    # First frame (seq 0) -- should pass
    f0 = encoder.encode(FrameType.DATA, b"first")
    decoder.decode(f0.to_bytes())

    # Second frame (seq 1) -- should pass
    f1 = encoder.encode(FrameType.DATA, b"second")
    decoder.decode(f1.to_bytes())

    # Now create a frame with seq 0 again (replay)
    replay = BastionFrame(
        msg_type=FrameType.DATA,
        passport_hash=b"\x00" * PASSPORT_HASH_SIZE,
        sequence=0,  # Already seen!
        payload=b"replay",
        signature=b"\x00" * 64,
    )
    try:
        decoder.decode(replay.to_bytes())
        assert False, "Should have raised ValueError for sequence violation"
    except ValueError as e:
        assert "sequence" in str(e).lower()
    print("  PASS: Decoder rejects sequence violations (replay protection)")


def test_decoder_sequence_gap():
    """Decoder should reject gaps in sequence numbers."""
    from lastbastion.protocol.frames import FrameEncoder, FrameDecoder, FrameType, BastionFrame, PASSPORT_HASH_SIZE

    decoder = FrameDecoder()
    encoder = FrameEncoder(b"\x00" * PASSPORT_HASH_SIZE)

    # seq 0 -- OK
    f0 = encoder.encode(FrameType.DATA, b"")
    decoder.decode(f0.to_bytes())

    # Skip seq 1, send seq 2 -- should fail
    gap_frame = BastionFrame(
        msg_type=FrameType.DATA,
        passport_hash=b"\x00" * PASSPORT_HASH_SIZE,
        sequence=2,  # Skipped 1!
        payload=b"",
        signature=b"\x00" * 64,
    )
    try:
        decoder.decode(gap_frame.to_bytes())
        assert False, "Should have raised ValueError for sequence gap"
    except ValueError as e:
        assert "sequence" in str(e).lower()
    print("  PASS: Decoder rejects sequence gaps")


def test_sequence_overflow():
    """Encoder should raise OverflowError when sequence exceeds 2^32-1."""
    from lastbastion.protocol.frames import FrameEncoder, FrameType, MAX_SEQUENCE, PASSPORT_HASH_SIZE

    encoder = FrameEncoder(b"\x00" * PASSPORT_HASH_SIZE)
    # Artificially set sequence near overflow
    encoder._sequence = MAX_SEQUENCE
    # This should work (last valid sequence)
    frame = encoder.encode(FrameType.DATA, b"last")
    assert frame.sequence == MAX_SEQUENCE

    # Next should overflow
    try:
        encoder.encode(FrameType.DATA, b"overflow")
        assert False, "Should have raised OverflowError"
    except OverflowError as e:
        assert "overflow" in str(e).lower()
    print(f"  PASS: Sequence overflow at {MAX_SEQUENCE} detected")


# ---------------------------------------------------------------------------
# Encoder signing tests
# ---------------------------------------------------------------------------

def test_encoder_signing():
    """Encoder should produce signed frames."""
    from lastbastion.protocol.frames import FrameEncoder, FrameType, PASSPORT_HASH_SIZE
    from lastbastion.crypto import generate_keypair

    pub, priv = generate_keypair()
    encoder = FrameEncoder(b"\x00" * PASSPORT_HASH_SIZE, signing_key=priv)
    frame = encoder.encode(FrameType.DATA, b"test payload")

    assert frame.signature != b"\x00" * 64, "Signature should not be all zeros"
    print("  PASS: Encoder produces signed frames")


def test_encoder_convenience_methods():
    """Encoder convenience methods should produce correct message types."""
    from lastbastion.protocol.frames import FrameEncoder, FrameType, PASSPORT_HASH_SIZE

    encoder = FrameEncoder(b"\x00" * PASSPORT_HASH_SIZE)

    data_frame = encoder.encode_data({"key": "value"})
    assert data_frame.msg_type == FrameType.DATA

    ping_frame = encoder.encode_ping()
    assert ping_frame.msg_type == FrameType.PING

    pong_frame = encoder.encode_pong()
    assert pong_frame.msg_type == FrameType.PONG

    close_frame = encoder.encode_close()
    assert close_frame.msg_type == FrameType.CLOSE

    from lastbastion.protocol.frames import ErrorCode
    err_frame = encoder.encode_error(ErrorCode.GENERIC, "test error")
    assert err_frame.msg_type == FrameType.ERROR

    print("  PASS: Convenience methods produce correct frame types")


def test_error_frame_unencrypted():
    """ERROR frames should not be encrypted (for crypto failure reporting)."""
    from lastbastion.protocol.frames import FrameEncoder, FrameType, ErrorCode, UNENCRYPTED_TYPES, PASSPORT_HASH_SIZE

    assert FrameType.ERROR in UNENCRYPTED_TYPES, "ERROR should be in UNENCRYPTED_TYPES"

    encoder = FrameEncoder(b"\x00" * PASSPORT_HASH_SIZE)
    encrypt_called = []

    def mock_encrypt(data):
        encrypt_called.append(True)
        return data

    # ERROR frame should NOT call encrypt even if encrypt_func is passed
    err = encoder.encode_error(ErrorCode.DECRYPTION_FAILED, "bad decrypt", mock_encrypt)
    assert len(encrypt_called) == 0, "ERROR frame should not be encrypted"
    print("  PASS: ERROR frames are unencrypted (crypto failure reporting works)")


# ---------------------------------------------------------------------------
# Handshake tests
# ---------------------------------------------------------------------------

def test_handshake_hello_build_parse():
    """HELLO frame should build and parse correctly with nonce + timestamp."""
    from lastbastion.passport import AgentPassport
    from lastbastion.crypto import generate_keypair
    from lastbastion.protocol.handshake import build_hello, parse_hello

    pub, priv = generate_keypair()
    passport = AgentPassport(
        agent_id="hello-test",
        trust_score=0.80,
        trust_level="VERIFIED",
        verdict="TRUSTED",
    )

    frame = build_hello(passport, priv, b"\x99" * 32)
    data = parse_hello(frame)

    assert "passport_jwt" in data
    assert data["ephemeral_pub"] == b"\x99" * 32
    from lastbastion.protocol.frames import PROTOCOL_VERSION as PV
    assert PV in data["supported_versions"]
    assert len(data["nonce"]) == 32, "Nonce should be 32 bytes"
    assert abs(data["timestamp"] - time.time()) < 5, "Timestamp should be recent"
    print("  PASS: HELLO build/parse round-trip with nonce + timestamp")


def test_handshake_full():
    """Full initiator/responder handshake should produce matching session keys."""
    from lastbastion.passport import AgentPassport
    from lastbastion.crypto import generate_keypair
    from lastbastion.protocol.handshake import HandshakeInitiator, HandshakeResponder

    pub_a, priv_a = generate_keypair()
    pub_b, priv_b = generate_keypair()

    passport_a = AgentPassport(
        agent_id="agent-alice",
        trust_score=0.85,
        trust_level="VERIFIED",
        verdict="TRUSTED",
    )
    passport_b = AgentPassport(
        agent_id="agent-bob",
        trust_score=0.90,
        trust_level="ESTABLISHED",
        verdict="TRUSTED",
    )

    # Alice initiates
    initiator = HandshakeInitiator(passport_a, priv_a, verify_key=pub_b)
    hello = initiator.build_hello()

    # Bob responds
    responder = HandshakeResponder(passport_b, priv_b, verify_key=pub_a)
    ack, bob_result = responder.process_hello(hello)

    # Alice completes
    alice_result = initiator.complete(ack)

    # Both should have the same session key
    assert alice_result.session_keys.shared_key == bob_result.session_keys.shared_key
    assert alice_result.peer_passport.agent_id == "agent-bob"
    assert bob_result.peer_passport.agent_id == "agent-alice"

    # Cleanup
    alice_result.finalize()
    bob_result.finalize()
    print("  PASS: Full handshake produces matching session keys")


def test_handshake_malicious_rejected():
    """Handshake should reject agents with MALICIOUS verdict."""
    from lastbastion.passport import AgentPassport
    from lastbastion.crypto import generate_keypair
    from lastbastion.protocol.handshake import HandshakeInitiator, HandshakeResponder

    pub_a, priv_a = generate_keypair()
    pub_b, priv_b = generate_keypair()

    evil_passport = AgentPassport(
        agent_id="evil-agent",
        trust_score=0.0,
        trust_level="NONE",
        verdict="MALICIOUS",
    )
    good_passport = AgentPassport(
        agent_id="good-agent",
        trust_score=0.90,
        trust_level="ESTABLISHED",
        verdict="TRUSTED",
    )

    initiator = HandshakeInitiator(evil_passport, priv_a, verify_key=pub_b)
    hello = initiator.build_hello()

    responder = HandshakeResponder(good_passport, priv_b, verify_key=pub_a)
    try:
        responder.process_hello(hello)
        assert False, "Should have rejected MALICIOUS agent"
    except ValueError as e:
        assert "MALICIOUS" in str(e)
    print("  PASS: Handshake rejects MALICIOUS agents")


def test_handshake_low_trust_rejected():
    """Handshake should reject agents below minimum trust score."""
    from lastbastion.passport import AgentPassport
    from lastbastion.crypto import generate_keypair
    from lastbastion.protocol.handshake import HandshakeInitiator, HandshakeResponder

    pub_a, priv_a = generate_keypair()
    pub_b, priv_b = generate_keypair()

    low_trust = AgentPassport(
        agent_id="low-trust",
        trust_score=0.20,
        trust_level="NEW",
        verdict="TRUSTED",
    )
    server_passport = AgentPassport(
        agent_id="server",
        trust_score=0.90,
        trust_level="ESTABLISHED",
        verdict="TRUSTED",
    )

    initiator = HandshakeInitiator(low_trust, priv_a, verify_key=pub_b)
    hello = initiator.build_hello()

    responder = HandshakeResponder(
        server_passport, priv_b, verify_key=pub_a, min_trust_score=0.50
    )
    try:
        responder.process_hello(hello)
        assert False, "Should have rejected low trust agent"
    except ValueError as e:
        assert "trust score" in str(e).lower()
    print("  PASS: Handshake rejects low trust agents")


def test_handshake_stale_hello_rejected():
    """HELLO frame with old timestamp should be rejected."""
    from lastbastion.passport import AgentPassport
    from lastbastion.crypto import generate_keypair
    from lastbastion.protocol.frames import (
        BastionFrame, FrameType, FrameEncoder, PASSPORT_HASH_SIZE,
        serialize_payload, compute_passport_hash,
    )
    from lastbastion.protocol.handshake import parse_hello, HANDSHAKE_FRESHNESS_SECONDS
    import os

    pub, priv = generate_keypair()
    passport = AgentPassport(
        agent_id="stale-test",
        trust_score=0.80,
        trust_level="VERIFIED",
        verdict="TRUSTED",
    )

    passport_hash = compute_passport_hash(passport.passport_id)
    passport_signed = passport.to_signed_bytes(priv)

    # Build a HELLO with an old timestamp
    from lastbastion.protocol.frames import PROTOCOL_VERSION as PV2
    payload_data = {
        "passport_signed": passport_signed,
        "ephemeral_pub": os.urandom(32),
        "supported_versions": [PV2],
        "nonce": os.urandom(32),
        "timestamp": time.time() - HANDSHAKE_FRESHNESS_SECONDS - 10,  # Too old
    }
    payload = serialize_payload(payload_data)
    encoder = FrameEncoder(passport_hash, priv)
    frame = encoder.encode(FrameType.HELLO, payload)

    try:
        parse_hello(frame)
        assert False, "Should have rejected stale HELLO"
    except ValueError as e:
        assert "too old" in str(e).lower()
    print(f"  PASS: Stale HELLO rejected (>{HANDSHAKE_FRESHNESS_SECONDS}s)")


# ---------------------------------------------------------------------------
# Session encryption tests
# ---------------------------------------------------------------------------

def test_session_encrypt_decrypt():
    """Session keys should encrypt and decrypt correctly."""
    from lastbastion.protocol.handshake import SessionKeys
    import os

    key = os.urandom(32)
    session = SessionKeys(shared_key=key)

    plaintext = b"sensitive agent data that must be encrypted"
    ciphertext = session.encrypt(plaintext)
    assert ciphertext != plaintext, "Ciphertext should differ from plaintext"

    decrypted = session.decrypt(ciphertext)
    assert decrypted == plaintext, "Decrypted should match original plaintext"

    session.destroy()
    try:
        session.encrypt(b"should fail")
        assert False, "Should have raised RuntimeError after destroy"
    except RuntimeError:
        pass
    print("  PASS: Session encrypt/decrypt round-trip + destroy")


# ---------------------------------------------------------------------------
# Full connection lifecycle tests
# ---------------------------------------------------------------------------

def test_full_connection_lifecycle():
    """Full TCP connection: server + client, handshake, send/recv, close."""
    from lastbastion.passport import AgentPassport
    from lastbastion.crypto import generate_keypair
    from lastbastion.protocol.socket import AgentSocket

    pub_s, priv_s = generate_keypair()
    pub_c, priv_c = generate_keypair()

    server_passport = AgentPassport(
        agent_id="server-agent",
        trust_score=0.95,
        trust_level="GOLD",
        verdict="TRUSTED",
    )
    client_passport = AgentPassport(
        agent_id="client-agent",
        trust_score=0.80,
        trust_level="VERIFIED",
        verdict="TRUSTED",
    )

    received_messages = []

    async def handler(conn):
        msg = await conn.recv()
        received_messages.append(msg)
        await conn.send({"echo": msg.get("text", ""), "from": "server"})

    async def _test():
        server = AgentSocket.listen(
            passport=server_passport,
            signing_key=priv_s,
            verify_key=pub_c,
            port=19100,
        )
        server.on_connect(handler)
        await server.start_background()

        # Give server a moment to bind
        await asyncio.sleep(0.1)

        # Client connects
        conn = await AgentSocket.connect(
            "127.0.0.1:19100",
            passport=client_passport,
            signing_key=priv_c,
            verify_key=pub_s,
        )

        # Verify peer info
        assert conn.peer.agent_id == "server-agent"
        assert conn.peer.trust_score == 0.95

        # Send and receive
        await conn.send({"text": "hello from client"})
        response = await conn.recv()
        assert response["echo"] == "hello from client"
        assert response["from"] == "server"

        # Check metrics
        assert conn.metrics.frames_sent > 0
        assert conn.metrics.frames_received > 0
        assert conn.metrics.bytes_sent > 0

        await conn.close()
        await server.stop()

    asyncio.run(_test())
    assert len(received_messages) == 1
    assert received_messages[0]["text"] == "hello from client"
    print("  PASS: Full connection lifecycle (handshake + send + recv + close + metrics)")


def test_streaming():
    """Large payload streaming should work with hash verification."""
    from lastbastion.passport import AgentPassport
    from lastbastion.crypto import generate_keypair
    from lastbastion.protocol.socket import AgentSocket

    pub_s, priv_s = generate_keypair()
    pub_c, priv_c = generate_keypair()

    server_passport = AgentPassport(
        agent_id="stream-server",
        trust_score=0.90,
        trust_level="ESTABLISHED",
        verdict="TRUSTED",
    )
    client_passport = AgentPassport(
        agent_id="stream-client",
        trust_score=0.80,
        trust_level="VERIFIED",
        verdict="TRUSTED",
    )

    received_data = []

    async def handler(conn):
        data = await conn.recv_stream()
        received_data.append(data)
        await conn.send({"received_bytes": len(data)})

    async def _test():
        server = AgentSocket.listen(
            passport=server_passport,
            signing_key=priv_s,
            verify_key=pub_c,
            port=19101,
        )
        server.on_connect(handler)
        await server.start_background()
        await asyncio.sleep(0.1)

        conn = await AgentSocket.connect(
            "127.0.0.1:19101",
            passport=client_passport,
            signing_key=priv_c,
            verify_key=pub_s,
        )

        # Send 100KB of data as a stream
        test_data = os.urandom(100 * 1024)
        await conn.send_stream(test_data, chunk_size=32 * 1024)

        # Get confirmation
        response = await conn.recv()
        assert response["received_bytes"] == len(test_data)

        await conn.close()
        await server.stop()

    asyncio.run(_test())
    assert len(received_data) == 1
    print(f"  PASS: Streaming {len(received_data[0])} bytes with hash verification")


def test_observability_hooks():
    """Observability hooks should fire on frame send/receive."""
    from lastbastion.passport import AgentPassport
    from lastbastion.crypto import generate_keypair
    from lastbastion.protocol.socket import AgentSocket

    pub_s, priv_s = generate_keypair()
    pub_c, priv_c = generate_keypair()

    server_passport = AgentPassport(
        agent_id="obs-server", trust_score=0.90, trust_level="ESTABLISHED", verdict="TRUSTED",
    )
    client_passport = AgentPassport(
        agent_id="obs-client", trust_score=0.80, trust_level="VERIFIED", verdict="TRUSTED",
    )

    sent_types = []
    recv_types = []

    def on_sent(frame):
        sent_types.append(frame.msg_type)

    def on_recv(frame):
        recv_types.append(frame.msg_type)

    async def handler(conn):
        msg = await conn.recv()
        await conn.send({"ok": True})

    async def _test():
        server = AgentSocket.listen(
            passport=server_passport, signing_key=priv_s, verify_key=pub_c, port=19102,
        )
        server.on_connect(handler)
        await server.start_background()
        await asyncio.sleep(0.1)

        conn = await AgentSocket.connect(
            "127.0.0.1:19102", passport=client_passport, signing_key=priv_c, verify_key=pub_s,
            on_frame_sent=on_sent, on_frame_received=on_recv,
        )

        await conn.send({"test": True})
        await conn.recv()

        await conn.close()
        await server.stop()

    asyncio.run(_test())
    assert len(sent_types) > 0, "Should have sent frames"
    assert len(recv_types) > 0, "Should have received frames"
    print(f"  PASS: Observability hooks fired ({len(sent_types)} sent, {len(recv_types)} recv)")


# ---------------------------------------------------------------------------
# Protocol constants tests
# ---------------------------------------------------------------------------

def test_protocol_constants():
    """Protocol constants should have expected values."""
    from lastbastion.protocol.frames import (
        PROTOCOL_VERSION, MAX_FRAME_SIZE, FRAME_HEADER_SIZE,
        SIGNATURE_SIZE, FRAME_TIMEOUT_SECONDS, PING_INTERVAL_SECONDS,
        PASSPORT_HASH_SIZE, MAX_SEQUENCE, PING_TIMEOUT_SECONDS,
        FRAME_FLAGS_SIZE, FRAME_TIMESTAMP_SIZE, FRAME_FRESHNESS_SECONDS,
    )

    assert PROTOCOL_VERSION == 0x02
    assert MAX_FRAME_SIZE == 16 * 1024 * 1024  # 16MB
    assert FRAME_HEADER_SIZE == 52  # v2: 1+1+2+32+4+8+4
    assert SIGNATURE_SIZE == 64
    assert PASSPORT_HASH_SIZE == 32  # v2: full SHA-256 (was 16 in v1)
    assert FRAME_FLAGS_SIZE == 2
    assert FRAME_TIMESTAMP_SIZE == 8
    assert FRAME_FRESHNESS_SECONDS == 60
    assert FRAME_TIMEOUT_SECONDS == 5
    assert PING_INTERVAL_SECONDS == 30
    assert PING_TIMEOUT_SECONDS == 5
    assert MAX_SEQUENCE == 0xFFFFFFFF
    print(f"  PASS: Protocol v2 constants correct (v{PROTOCOL_VERSION}, hash={PASSPORT_HASH_SIZE}B, header={FRAME_HEADER_SIZE}B)")


def test_error_codes():
    """Error codes should be defined."""
    from lastbastion.protocol.frames import ErrorCode, FATAL_ERROR_CODES

    assert ErrorCode.GENERIC == 1000
    assert ErrorCode.AGENT_LOCKED_OUT == 1013
    assert ErrorCode.PASSPORT_FAILED in FATAL_ERROR_CODES
    assert ErrorCode.SEQUENCE_VIOLATION in FATAL_ERROR_CODES
    assert ErrorCode.GENERIC not in FATAL_ERROR_CODES
    print(f"  PASS: {len(ErrorCode)} error codes defined, {len(FATAL_ERROR_CODES)} are fatal")


# ---------------------------------------------------------------------------
# v2 Feature Tests: Flags, Timestamps, Reserved Bits
# ---------------------------------------------------------------------------

def test_frame_flags():
    """Frame flags should encode/decode correctly."""
    from lastbastion.protocol.frames import (
        BastionFrame, FrameType, FrameFlags, PASSPORT_HASH_SIZE, PROTOCOL_VERSION,
    )

    for flag_combo in [
        FrameFlags.NONE,
        FrameFlags.COMPRESSED,
        FrameFlags.PRIORITY,
        FrameFlags.COMPRESSED | FrameFlags.PRIORITY,
        FrameFlags.FRESHNESS_STRICT,
        FrameFlags.COMPRESSED | FrameFlags.FRAGMENTED | FrameFlags.PRIORITY | FrameFlags.FRESHNESS_STRICT,
    ]:
        frame = BastionFrame(
            version=PROTOCOL_VERSION,
            msg_type=FrameType.DATA,
            flags=flag_combo,
            passport_hash=b"\x00" * PASSPORT_HASH_SIZE,
            sequence=0,
            timestamp_us=1000000,
            payload=b"test",
            signature=b"\x00" * 64,
        )
        raw = frame.to_bytes()
        restored = BastionFrame.from_bytes(raw)
        assert restored.flags == flag_combo, f"Flags mismatch for {flag_combo}"
    print(f"  PASS: All flag combinations encode/decode correctly")


def test_frame_reserved_flags_rejected():
    """Reserved flag bits (4-15) should cause rejection."""
    from lastbastion.protocol.frames import BastionFrame, PASSPORT_HASH_SIZE, PROTOCOL_VERSION

    # Set bit 4 (reserved)
    header = struct.pack(">BBH32sIQI", PROTOCOL_VERSION, 0x03, 0x0010, b"\x00" * PASSPORT_HASH_SIZE, 0, 0, 0)
    raw = header + b"\x00" * 64
    try:
        BastionFrame.from_bytes(raw)
        assert False, "Should have raised ValueError for reserved flags"
    except ValueError as e:
        assert "reserved" in str(e).lower()
    print("  PASS: Reserved flags rejected")


def test_frame_timestamp():
    """Frame timestamp should survive encode/decode."""
    from lastbastion.protocol.frames import FrameEncoder, FrameType, PASSPORT_HASH_SIZE
    import time as _time

    encoder = FrameEncoder(b"\x00" * PASSPORT_HASH_SIZE)
    before_us = int(_time.time() * 1_000_000)
    frame = encoder.encode(FrameType.DATA, b"timestamped")
    after_us = int(_time.time() * 1_000_000)

    assert frame.timestamp_us >= before_us, "Timestamp should be >= encode start"
    assert frame.timestamp_us <= after_us, "Timestamp should be <= encode end"
    assert frame.timestamp_seconds > 0, "Timestamp seconds should be positive"
    print(f"  PASS: Frame timestamp set ({frame.timestamp_us} us)")


def test_frame_freshness_enforcement():
    """Decoder should reject stale frames when freshness is enforced."""
    from lastbastion.protocol.frames import (
        BastionFrame, FrameType, FrameFlags, FrameDecoder,
        PASSPORT_HASH_SIZE, PROTOCOL_VERSION, FRAME_FRESHNESS_SECONDS,
    )

    # Build a frame with a stale timestamp (2 minutes old)
    stale_us = int((time.time() - 120) * 1_000_000)
    stale_frame = BastionFrame(
        version=PROTOCOL_VERSION,
        msg_type=FrameType.DATA,
        flags=FrameFlags.FRESHNESS_STRICT,
        passport_hash=b"\x00" * PASSPORT_HASH_SIZE,
        sequence=0,
        timestamp_us=stale_us,
        payload=b"stale",
        signature=b"\x00" * 64,
    )

    decoder = FrameDecoder()
    try:
        decoder.decode(stale_frame.to_bytes())
        assert False, "Should have rejected stale frame"
    except ValueError as e:
        assert "stale" in str(e).lower()
    print(f"  PASS: Stale frame rejected (>{FRAME_FRESHNESS_SECONDS}s)")


def test_frame_freshness_decoder_flag():
    """Decoder-level enforce_freshness should reject stale frames."""
    from lastbastion.protocol.frames import (
        BastionFrame, FrameType, FrameFlags, FrameDecoder,
        PASSPORT_HASH_SIZE, PROTOCOL_VERSION,
    )

    stale_us = int((time.time() - 120) * 1_000_000)
    frame = BastionFrame(
        version=PROTOCOL_VERSION,
        msg_type=FrameType.DATA,
        flags=FrameFlags.NONE,  # No FRESHNESS_STRICT flag on frame
        passport_hash=b"\x00" * PASSPORT_HASH_SIZE,
        sequence=0,
        timestamp_us=stale_us,
        payload=b"stale",
        signature=b"\x00" * 64,
    )

    # Decoder with enforce_freshness=True should still reject
    decoder = FrameDecoder(enforce_freshness=True)
    try:
        decoder.decode(frame.to_bytes())
        assert False, "Should have rejected stale frame"
    except ValueError as e:
        assert "stale" in str(e).lower()
    print("  PASS: Decoder-level freshness enforcement works")


def test_v2_header_size():
    """v2 header should be exactly 52 bytes."""
    from lastbastion.protocol.frames import (
        BastionFrame, FrameType, FrameFlags, PASSPORT_HASH_SIZE,
        FRAME_HEADER_SIZE, SIGNATURE_SIZE, PROTOCOL_VERSION,
    )

    frame = BastionFrame(
        version=PROTOCOL_VERSION,
        msg_type=FrameType.DATA,
        flags=FrameFlags.NONE,
        passport_hash=b"\x00" * PASSPORT_HASH_SIZE,
        sequence=0,
        timestamp_us=0,
        payload=b"",
        signature=b"\x00" * SIGNATURE_SIZE,
    )

    header = frame.header_bytes
    assert len(header) == 52, f"v2 header should be 52 bytes, got {len(header)}"
    assert len(header) == FRAME_HEADER_SIZE, f"FRAME_HEADER_SIZE mismatch"

    total = frame.to_bytes()
    assert len(total) == 52 + 64, f"Empty frame should be 116 bytes, got {len(total)}"
    print(f"  PASS: v2 header={len(header)}B, total overhead={len(total)}B (was 90B in v1)")


def test_nonce_replay_rejected():
    """Replayed HELLO nonce should be rejected by HandshakeResponder."""
    from lastbastion.passport import AgentPassport
    from lastbastion.crypto import generate_keypair
    from lastbastion.protocol.handshake import (
        HandshakeInitiator, HandshakeResponder, NonceRegistry,
    )

    pub_a, priv_a = generate_keypair()
    pub_b, priv_b = generate_keypair()

    passport_a = AgentPassport(
        agent_id="replay-alice",
        trust_score=0.85, trust_level="VERIFIED", verdict="TRUSTED",
    )
    passport_b = AgentPassport(
        agent_id="replay-bob",
        trust_score=0.90, trust_level="ESTABLISHED", verdict="TRUSTED",
    )

    # Shared nonce registry for this test
    registry = NonceRegistry()

    # First handshake succeeds
    init1 = HandshakeInitiator(passport_a, priv_a, verify_key=pub_b)
    hello1 = init1.build_hello()
    resp1 = HandshakeResponder(passport_b, priv_b, verify_key=pub_a, nonce_registry=registry)
    _ack1, _result1 = resp1.process_hello(hello1)

    # Replay the SAME hello frame — should be rejected
    resp2 = HandshakeResponder(passport_b, priv_b, verify_key=pub_a, nonce_registry=registry)
    try:
        resp2.process_hello(hello1)
        raise AssertionError("Should have rejected replayed nonce")
    except ValueError as e:
        assert "replay" in str(e).lower(), f"Expected replay error, got: {e}"

    # Fresh handshake should still work
    init3 = HandshakeInitiator(passport_a, priv_a, verify_key=pub_b)
    hello3 = init3.build_hello()
    resp3 = HandshakeResponder(passport_b, priv_b, verify_key=pub_a, nonce_registry=registry)
    _ack3, _result3 = resp3.process_hello(hello3)

    print(f"  PASS: Nonce replay rejected, fresh nonce accepted (registry size: {len(registry)})")


def test_nonce_registry_purge():
    """NonceRegistry should purge expired nonces."""
    from lastbastion.protocol.handshake import NonceRegistry, HANDSHAKE_FRESHNESS_SECONDS

    registry = NonceRegistry()

    # Insert a nonce with fake old timestamp
    old_nonce = b"\xaa" * 32
    registry._seen[old_nonce] = time.time() - HANDSHAKE_FRESHNESS_SECONDS - 1

    # Insert a fresh nonce
    fresh_nonce = b"\xbb" * 32
    assert registry.check_and_record(fresh_nonce) == True  # triggers purge

    # Old nonce should have been purged, so re-using it should succeed
    assert registry.check_and_record(old_nonce) == True
    # But fresh nonce should be rejected (still in registry)
    assert registry.check_and_record(fresh_nonce) == False

    print(f"  PASS: Nonce registry purges expired entries, rejects live duplicates")


# ---------------------------------------------------------------------------
# Run all tests
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    tests = [
        ("Frame: Encode/decode", test_frame_encode_decode),
        ("Frame: All message types", test_frame_all_message_types),
        ("Frame: Too short", test_frame_too_short),
        ("Frame: Invalid version", test_frame_invalid_version),
        ("Frame: Unknown type", test_frame_unknown_type),
        ("Frame: Max size enforcement", test_frame_max_size_enforcement),
        ("Frame: Encoder max size", test_frame_encoder_max_size),
        ("Frame: Trailing data rejected", test_frame_trailing_data_rejected),
        ("Frame: Tampered payload detected", test_frame_tampered_payload),
        ("Frame: Wrong passport hash", test_frame_wrong_passport_hash),
        ("Serialization: Payload round-trip", test_payload_serialization),
        ("Serialization: Passport hash (32 bytes)", test_passport_hash),
        ("Sequence: Monotonic", test_sequence_monotonic),
        ("Sequence: Replay rejected", test_decoder_sequence_violation),
        ("Sequence: Gap rejected", test_decoder_sequence_gap),
        ("Sequence: Overflow detected", test_sequence_overflow),
        ("Encoder: Signing", test_encoder_signing),
        ("Encoder: Convenience methods", test_encoder_convenience_methods),
        ("Encoder: ERROR frames unencrypted", test_error_frame_unencrypted),
        ("Handshake: HELLO with nonce+timestamp", test_handshake_hello_build_parse),
        ("Handshake: Full exchange", test_handshake_full),
        ("Handshake: MALICIOUS rejected", test_handshake_malicious_rejected),
        ("Handshake: Low trust rejected", test_handshake_low_trust_rejected),
        ("Handshake: Stale HELLO rejected", test_handshake_stale_hello_rejected),
        ("Session: Encrypt/decrypt (NaCl)", test_session_encrypt_decrypt),
        ("Connection: Full lifecycle", test_full_connection_lifecycle),
        ("Connection: Streaming", test_streaming),
        ("Connection: Observability hooks", test_observability_hooks),
        ("Constants: Protocol v2 values", test_protocol_constants),
        ("Constants: Error codes", test_error_codes),
        ("v2: Frame flags", test_frame_flags),
        ("v2: Reserved flags rejected", test_frame_reserved_flags_rejected),
        ("v2: Frame timestamp", test_frame_timestamp),
        ("v2: Freshness enforcement (frame flag)", test_frame_freshness_enforcement),
        ("v2: Freshness enforcement (decoder flag)", test_frame_freshness_decoder_flag),
        ("v2: Header size (52B)", test_v2_header_size),
        ("Nonce: Replay rejected", test_nonce_replay_rejected),
        ("Nonce: Registry purge", test_nonce_registry_purge),
    ]

    print("=" * 60)
    print("BASTION PROTOCOL -- WIRE FORMAT TEST SUITE")
    print("=" * 60)

    passed = 0
    failed = 0
    for name, fn in tests:
        try:
            print(f"\n[TEST] {name}")
            fn()
            passed += 1
        except Exception as e:
            print(f"  FAIL: {e}")
            import traceback
            traceback.print_exc()
            failed += 1

    print("\n" + "=" * 60)
    print(f"RESULTS: {passed} passed, {failed} failed, {len(tests)} total")
    print("=" * 60)

    if failed > 0:
        sys.exit(1)
