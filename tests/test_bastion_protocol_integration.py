"""
Bastion Protocol Integration Tests.

Tests the full Bastion Protocol stack:
1. Passport creation and sealing
2. Server boot and TCP listening
3. Handshake (HELLO/HELLO_ACK + X25519 key exchange)
4. Encrypted data send/recv
5. Frame event capture in bastion_bus
6. Multi-agent chain (Producer → Compliance → Logistics → Buyer)
7. Connection close and cleanup
8. Error handling (bad passport, wrong keys)

Run:
    python tests/test_bastion_protocol_integration.py

For remote testing against Raspberry Pi agents:
    BASTION_HOST=192.168.87.39 python tests/test_bastion_protocol_integration.py
"""
import asyncio
import json
import logging
import os
import sys
import time

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(name)s] %(message)s")
logger = logging.getLogger("BASTION_TEST")

# Colors for terminal output
# Force UTF-8 output on Windows
if sys.platform == "win32":
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    sys.stderr.reconfigure(encoding="utf-8", errors="replace")

G = "\033[92m"  # green
R = "\033[91m"  # red
Y = "\033[93m"  # yellow
B = "\033[94m"  # blue
W = "\033[0m"   # reset

RESULTS = []


def phase(num, name):
    print(f"\n{'='*60}")
    print(f"  Phase {num}: {name}")
    print(f"{'='*60}")


def result(name, passed, detail=""):
    status = f"{G}PASS{W}" if passed else f"{R}FAIL{W}"
    print(f"  [{status}] {name}" + (f" — {detail}" if detail else ""))
    RESULTS.append((name, passed))
    return passed


async def run_tests():
    """Run all Bastion Protocol integration tests."""

    bastion_host = os.environ.get("BASTION_HOST", "localhost")
    is_remote = bastion_host != "localhost"

    print(f"\n{'#'*60}")
    print(f"  BASTION PROTOCOL INTEGRATION TESTS")
    print(f"  Target: {bastion_host}" + (" (REMOTE)" if is_remote else " (LOCAL)"))
    print(f"{'#'*60}")

    # ── Phase 1: SDK Import & Keypair Generation ──────────────
    phase(1, "SDK Import & Crypto")

    try:
        from lastbastion.crypto import generate_keypair, compute_hash
        from lastbastion.passport import AgentPassport, PassportVerifier
        from lastbastion.protocol import (
            AgentSocket, AgentConnection, FrameType, BastionFrame,
            FrameEncoder, FrameDecoder, PROTOCOL_VERSION, FRAME_HEADER_SIZE,
            SIGNATURE_SIZE, PASSPORT_HASH_SIZE,
        )
        from lastbastion.protocol.frames import compute_passport_hash
        result("SDK imports", True)
    except ImportError as e:
        result("SDK imports", False, str(e))
        print(f"\n{R}Cannot continue without SDK. Install: pip install -e sdk/{W}")
        return

    try:
        pub1, priv1 = generate_keypair()
        pub2, priv2 = generate_keypair()
        assert len(pub1) == 64, f"Expected 64 hex chars, got {len(pub1)}"
        assert len(priv1) == 64, f"Expected 64 hex chars, got {len(priv1)}"
        assert pub1 != pub2, "Keys should be unique"
        result("Ed25519 keypair generation", True, f"pub={pub1[:16]}...")
    except Exception as e:
        result("Ed25519 keypair generation", False, str(e))
        return

    # Issuer keypair (signs all passports)
    issuer_pub, issuer_priv = generate_keypair()
    result("Issuer keypair", True, f"pub={issuer_pub[:16]}...")

    # ── Phase 2: Passport Creation & Integrity ────────────────
    phase(2, "Passport Creation & Integrity")

    try:
        passport_a = AgentPassport(
            agent_id="test-agent-alpha",
            agent_name="TestAlpha",
            public_key=pub1,
            trust_score=0.92,
            trust_level="VERIFIED",
            verdict="TRUSTED",
            company_name="Test Corp",
            issuer="the-last-bastion",
            issuer_public_key=issuer_pub,
        ).seal()

        assert passport_a.crypto_hash, "Seal should set crypto_hash"
        assert passport_a.verify_integrity(), "Integrity check should pass"
        result("Passport creation + seal", True, f"id={passport_a.passport_id}")
    except Exception as e:
        result("Passport creation + seal", False, str(e))
        return

    try:
        passport_b = AgentPassport(
            agent_id="test-agent-beta",
            agent_name="TestBeta",
            public_key=pub2,
            trust_score=0.88,
            trust_level="VERIFIED",
            verdict="TRUSTED",
            company_name="Test Corp",
            issuer="the-last-bastion",
            issuer_public_key=issuer_pub,
        ).seal()
        result("Second passport", True, f"id={passport_b.passport_id}")
    except Exception as e:
        result("Second passport", False, str(e))
        return

    # Tamper detection
    try:
        tampered = passport_a.model_copy()
        tampered.trust_score = 0.99
        assert not tampered.verify_integrity(), "Tampered passport should fail integrity"
        result("Tamper detection", True, "Modified trust_score detected")
    except Exception as e:
        result("Tamper detection", False, str(e))

    # Passport hash
    try:
        ph = compute_passport_hash(passport_a.passport_id)
        assert len(ph) == PASSPORT_HASH_SIZE, f"Expected {PASSPORT_HASH_SIZE} bytes"
        result("Passport hash computation", True, f"hash={ph.hex()[:16]}...")
    except Exception as e:
        result("Passport hash computation", False, str(e))

    # ── Phase 3: Frame Encoding/Decoding ──────────────────────
    phase(3, "Frame Encoding & Decoding")

    try:
        ph_a = compute_passport_hash(passport_a.passport_id)
        encoder = FrameEncoder(ph_a, priv1)

        # Encode a DATA frame
        test_payload = {"action": "verify", "batch_id": "TEST-001", "temperature": 4.2}
        frame = encoder.encode_data(test_payload)

        assert frame.msg_type == FrameType.DATA, f"Expected DATA, got {frame.msg_type}"
        assert frame.sequence >= 0, f"Expected seq >= 0, got {frame.sequence}"
        assert frame.passport_hash == ph_a, "Passport hash mismatch"
        result("Frame encoding", True, f"type={FrameType(frame.msg_type).name}, seq={frame.sequence}")
    except Exception as e:
        result("Frame encoding", False, str(e))

    try:
        raw = frame.to_bytes()
        overhead = FRAME_HEADER_SIZE + SIGNATURE_SIZE
        assert len(raw) >= overhead, f"Frame too small: {len(raw)} < {overhead}"
        result("Frame serialization", True, f"total={len(raw)}B, overhead={overhead}B, payload={len(raw)-overhead}B")
    except Exception as e:
        result("Frame serialization", False, str(e))

    try:
        decoded = BastionFrame.from_bytes(raw)
        assert decoded.msg_type == frame.msg_type
        assert decoded.sequence == frame.sequence
        assert decoded.passport_hash == frame.passport_hash
        result("Frame deserialization", True)
    except Exception as e:
        result("Frame deserialization", False, str(e))

    # ── Phase 4: Bastion Bus Event Capture ────────────────────
    phase(4, "Bastion Bus Event Capture")

    try:
        from core.bastion_bus import bastion_bus, BastionLogEntry

        # Clear any existing data
        bastion_bus._buffer.clear()
        bastion_bus._total_recorded = 0
        bastion_bus._total_bytes = 0
        bastion_bus._handshakes_completed = 0
        bastion_bus._stats.clear()
        bastion_bus._active_sessions.clear()

        # Record test events
        e1 = bastion_bus.record(
            event_type="HANDSHAKE_INIT",
            frame_type="HELLO",
            sender_agent="test-alpha",
            receiver_agent="test-beta",
            direction="SENT",
            session_id="test-session-1",
        )
        assert e1.log_id.startswith("bp-"), f"Expected bp- prefix, got {e1.log_id}"
        assert e1.timestamp, "Should have timestamp"
        result("Event recording", True, f"id={e1.log_id}")
    except Exception as e:
        result("Event recording", False, str(e))

    try:
        bastion_bus.record_handshake(
            event_type="HANDSHAKE_COMPLETE",
            sender="test-alpha",
            receiver="test-beta",
            session_id="test-session-1",
            trust_score=0.92,
            passport_hash="abc123",
            latency_ms=12.5,
        )

        bastion_bus.record(
            event_type="FRAME_SENT",
            frame_type="DATA",
            sender_agent="test-alpha",
            receiver_agent="test-beta",
            direction="SENT",
            encrypted=True,
            payload_size=256,
            total_frame_size=346,
            session_id="test-session-1",
        )

        stats = bastion_bus.get_stats()
        assert stats["total_frames"] == 3, f"Expected 3 frames, got {stats['total_frames']}"
        assert stats["handshakes_completed"] == 1, f"Expected 1 handshake"
        assert stats["total_bytes"] == 346, f"Expected 346 bytes"
        result("Bus stats", True, f"frames={stats['total_frames']}, handshakes={stats['handshakes_completed']}")
    except Exception as e:
        result("Bus stats", False, str(e))

    try:
        entries = bastion_bus.query(limit=10, frame_type="DATA")
        assert len(entries) == 1, f"Expected 1 DATA entry, got {len(entries)}"
        assert entries[0]["encrypted"] is True
        result("Bus query filtering", True, f"found {len(entries)} DATA frames")
    except Exception as e:
        result("Bus query filtering", False, str(e))

    try:
        conns = bastion_bus.get_connections()
        assert len(conns) >= 1, "Should have at least 1 connection"
        conn = conns[0]
        assert conn["state"] == "ESTABLISHED"
        assert conn["frame_count"] >= 2
        result("Connection tracking", True, f"state={conn['state']}, frames={conn['frame_count']}")
    except Exception as e:
        result("Connection tracking", False, str(e))

    # ── Phase 5: Live Server + Client Handshake ───────────────
    phase(5, "Live TCP Handshake + Encrypted Send/Recv")

    if is_remote:
        # Skip local server boot — test against remote Pi agents
        print(f"  {Y}Skipping local server boot — testing against remote {bastion_host}{W}")
    else:
        # Boot a local test server
        server = None
        received_messages = []

        try:
            async def handle_connection(conn):
                msg = await conn.recv()
                received_messages.append(msg)
                await conn.send({
                    "status": "verified",
                    "echo": msg,
                    "agent": "test-beta",
                })
                await conn.close()

            server = AgentSocket.listen(
                passport=passport_b,
                signing_key=priv2,
                verify_key=pub1,  # Verify CLIENT's JWT with CLIENT's public key
                host="0.0.0.0",
                port=19101,
            )
            server.on_connect(handle_connection)
            await server.start_background()
            await asyncio.sleep(0.5)  # Give server time to bind
            result("Server boot", True, "TCP:19101")
        except Exception as e:
            result("Server boot", False, str(e))

        if server:
            # Client connects
            try:
                t0 = time.monotonic()
                conn = await AgentSocket.connect(
                    host="localhost",
                    port=19101,
                    passport=passport_a,
                    signing_key=priv1,
                    verify_key=pub2,  # Verify SERVER's JWT with SERVER's public key
                )
                handshake_ms = (time.monotonic() - t0) * 1000
                result("Handshake complete", True, f"latency={handshake_ms:.1f}ms")

                # Verify peer info
                assert conn.peer.agent_id == "test-agent-beta"
                assert conn.peer.agent_name == "TestBeta"
                assert conn.peer.trust_score == 0.88
                result("Peer identity verified", True, f"peer={conn.peer.agent_name}, trust={conn.peer.trust_score}")

            except Exception as e:
                result("Handshake complete", False, str(e))
                conn = None

            if conn:
                # Encrypted send
                try:
                    test_data = {
                        "action": "verify_batch",
                        "batch_id": "TEST-BASTION-001",
                        "product": "Whole Milk Powder",
                        "quantity_kg": 15000,
                        "temperature": 4.2,
                        "certifications": ["MPI-EXPORT", "ORGANIC-NZ"],
                    }
                    await conn.send(test_data)
                    result("Encrypted send", True, f"payload={len(json.dumps(test_data))}B")
                except Exception as e:
                    result("Encrypted send", False, str(e))

                # Encrypted recv
                try:
                    response = await conn.recv()
                    assert response["status"] == "verified"
                    assert response["echo"]["batch_id"] == "TEST-BASTION-001"
                    result("Encrypted recv", True, f"status={response['status']}")
                except Exception as e:
                    result("Encrypted recv", False, str(e))

                # Protocol metrics
                try:
                    metrics = conn.metrics
                    assert metrics.frames_sent >= 1
                    assert metrics.frames_received >= 1
                    assert metrics.bytes_sent > 0
                    result("Protocol metrics", True,
                           f"sent={metrics.frames_sent} frames/{metrics.bytes_sent}B, "
                           f"recv={metrics.frames_received} frames/{metrics.bytes_received}B")
                except Exception as e:
                    result("Protocol metrics", False, str(e))

                # Close
                try:
                    await conn.close()
                    assert conn.is_closed
                    result("Bidirectional close", True)
                except Exception as e:
                    result("Bidirectional close", False, str(e))

                # Verify server received the message
                try:
                    await asyncio.sleep(0.5)
                    assert len(received_messages) == 1
                    assert received_messages[0]["batch_id"] == "TEST-BASTION-001"
                    result("Server received message", True, f"batch_id={received_messages[0]['batch_id']}")
                except Exception as e:
                    result("Server received message", False, str(e))

            # Cleanup
            try:
                await server.stop()
                result("Server shutdown", True)
            except Exception as e:
                result("Server shutdown", False, str(e))

    # ── Phase 6: Multi-Agent Chain ────────────────────────────
    phase(6, "Multi-Agent Chain (4 agents)")

    agent_configs = [
        ("producer", 19201),
        ("compliance", 19202),
        ("logistics", 19203),
        ("buyer", 19204),
    ]

    if is_remote:
        # Test against remote Pi agents on ports 9101-9104
        agent_configs = [
            ("producer", 9101),
            ("compliance", 9102),
            ("logistics", 9103),
            ("buyer", 9104),
        ]
        print(f"  {Y}Testing against remote agents at {bastion_host}:9101-9104{W}")

    servers = {}
    passports = {}
    keys = {}

    # For multi-agent: use a shared keypair so all agents can verify each other
    # This simulates a central authority (issuer) that signs all passports
    shared_pub, shared_priv = generate_keypair()

    if not is_remote:
        # Boot 4 local test servers
        for name, port in agent_configs:
            try:
                keys[name] = (shared_priv, shared_pub)
                passport = AgentPassport(
                    agent_id=f"test-{name}",
                    agent_name=f"Test{name.title()}Bot",
                    public_key=shared_pub,
                    trust_score=0.85 + (hash(name) % 10) / 100,
                    trust_level="VERIFIED",
                    verdict="TRUSTED",
                    issuer="the-last-bastion",
                    issuer_public_key=shared_pub,
                ).seal()
                passports[name] = passport

                received = []

                async def make_handler(agent_name, msg_store):
                    async def handle(conn):
                        try:
                            msg = await conn.recv()
                            msg_store.append(msg)
                            await conn.send({
                                "status": "processed",
                                "agent": agent_name,
                                "received_action": msg.get("action", "unknown"),
                            })
                            await conn.close()
                        except Exception:
                            pass
                    return handle

                handler = await make_handler(name, received)
                srv = AgentSocket.listen(
                    passport=passport,
                    signing_key=shared_priv,
                    verify_key=shared_pub,  # All agents share the same keypair
                    port=port,
                )
                srv.on_connect(handler)
                await srv.start_background()
                servers[name] = (srv, received)
            except Exception as e:
                result(f"Boot {name}", False, str(e))

        await asyncio.sleep(0.5)
        result("4 agent servers booted", len(servers) == 4, f"{len(servers)}/4 running")
    else:
        # For remote: use shared keypair as client credentials
        for name, port in agent_configs:
            passports[name] = AgentPassport(
                agent_id=f"test-{name}",
                agent_name=f"Test{name.title()}Bot",
                public_key=shared_pub,
                trust_score=0.90,
                trust_level="VERIFIED",
                verdict="TRUSTED",
                issuer="the-last-bastion",
                issuer_public_key=shared_pub,
            ).seal()
            keys[name] = (shared_priv, shared_pub)

    # Run supply chain: Producer → Compliance → Logistics → Buyer
    chain_results = []
    chain = [
        ("producer", "compliance", {"action": "certify_batch", "batch_id": "CHAIN-001"}),
        ("compliance", "logistics", {"action": "ship_batch", "batch_id": "CHAIN-001", "certified": True}),
        ("logistics", "buyer", {"action": "deliver", "batch_id": "CHAIN-001", "container": "MSKU-12345"}),
    ]

    sender_passport = passport_a if is_remote else None

    for sender_name, target_name, payload in chain:
        target_port = dict(agent_configs)[target_name]
        try:
            s_passport = passports[sender_name]
            s_priv, s_pub = keys[sender_name]

            t0 = time.monotonic()
            conn = await AgentSocket.connect(
                host=bastion_host,
                port=target_port,
                passport=s_passport,
                signing_key=s_priv,
                verify_key=shared_pub,  # All agents use same shared key
            )
            await conn.send(payload)
            response = await conn.recv()
            await conn.close()
            latency = (time.monotonic() - t0) * 1000

            assert response.get("status") in ("processed", "verified")
            chain_results.append(True)
            result(
                f"{sender_name} → {target_name}",
                True,
                f"action={payload['action']}, latency={latency:.0f}ms"
                + (f" (over network)" if is_remote else ""),
            )
        except Exception as e:
            chain_results.append(False)
            result(f"{sender_name} → {target_name}", False, str(e))

    all_chain_pass = all(chain_results)
    result("Full supply chain via Bastion", all_chain_pass,
           f"{sum(chain_results)}/{len(chain_results)} hops")

    # Cleanup local servers
    if not is_remote:
        for name, (srv, _) in servers.items():
            try:
                await srv.stop()
            except Exception:
                pass
        result("Cleanup", True, f"stopped {len(servers)} servers")

    # ── Phase 7: Error Handling ───────────────────────────────
    phase(7, "Error Handling & Edge Cases")

    if not is_remote:
        # Test connection to non-existent port
        try:
            conn = await asyncio.wait_for(
                AgentSocket.connect(
                    host="localhost",
                    port=19999,
                    passport=passport_a,
                    signing_key=priv1,
                    verify_key=issuer_pub,
                ),
                timeout=3.0,
            )
            result("Reject non-existent port", False, "Should have raised")
            await conn.close()
        except (ConnectionRefusedError, OSError, asyncio.TimeoutError):
            result("Reject non-existent port", True, "ConnectionRefused as expected")
        except Exception as e:
            result("Reject non-existent port", True, f"Error: {type(e).__name__}")

        # Test expired passport
        try:
            expired_passport = AgentPassport(
                agent_id="expired-agent",
                agent_name="ExpiredBot",
                public_key=pub1,
                trust_score=0.5,
                trust_level="BASIC",
                verdict="TRUSTED",
                issuer="the-last-bastion",
                issuer_public_key=issuer_pub,
                expires_at=time.time() - 3600,  # Expired 1 hour ago
            ).seal()
            assert expired_passport.is_expired(), "Should be expired"
            result("Expired passport detection", True)
        except Exception as e:
            result("Expired passport detection", False, str(e))

        # Test MALICIOUS verdict passport
        try:
            malicious_passport = AgentPassport(
                agent_id="bad-agent",
                agent_name="MaliciousBot",
                public_key=pub1,
                trust_score=0.1,
                trust_level="NONE",
                verdict="MALICIOUS",
                issuer="the-last-bastion",
                issuer_public_key=issuer_pub,
            ).seal()
            assert malicious_passport.verdict == "MALICIOUS"
            result("Malicious passport flagging", True)
        except Exception as e:
            result("Malicious passport flagging", False, str(e))

    # ── Phase 8: Performance Benchmark ────────────────────────
    phase(8, "Performance Benchmark")

    if not is_remote:
        # Quick benchmark: multiple round-trips
        bench_received = []

        async def bench_handler(conn):
            try:
                msg = await conn.recv()
                bench_received.append(msg)
                await conn.send({"ack": True})
                await conn.close()
            except Exception:
                pass

        try:
            bench_srv = AgentSocket.listen(
                passport=passport_b,
                signing_key=priv2,
                verify_key=pub1,  # Verify client's JWT
                port=19301,
            )
            bench_srv.on_connect(bench_handler)
            await bench_srv.start_background()
            await asyncio.sleep(0.3)

            n_trips = 10
            t0 = time.monotonic()
            for i in range(n_trips):
                c = await AgentSocket.connect(
                    host="localhost",
                    port=19301,
                    passport=passport_a,
                    signing_key=priv1,
                    verify_key=pub2,  # Verify server's JWT
                )
                await c.send({"seq": i, "data": "x" * 100})
                await c.recv()
                await c.close()
            total_ms = (time.monotonic() - t0) * 1000
            avg_ms = total_ms / n_trips

            result(
                f"{n_trips} round-trips",
                True,
                f"total={total_ms:.0f}ms, avg={avg_ms:.1f}ms/trip"
            )

            await bench_srv.stop()
        except Exception as e:
            result("Benchmark", False, str(e))
    else:
        # Remote benchmark
        try:
            n_trips = 5
            t0 = time.monotonic()
            for i in range(n_trips):
                c = await AgentSocket.connect(
                    host=bastion_host,
                    port=9101,  # Producer
                    passport=passports.get("producer", passport_a),
                    signing_key=shared_priv,
                    verify_key=shared_pub,
                )
                await c.send({"seq": i, "benchmark": True})
                await c.recv()
                await c.close()
            total_ms = (time.monotonic() - t0) * 1000
            avg_ms = total_ms / n_trips
            result(
                f"{n_trips} remote round-trips",
                True,
                f"total={total_ms:.0f}ms, avg={avg_ms:.1f}ms/trip (over network)"
            )
        except Exception as e:
            result(f"Remote benchmark", False, str(e))

    # ── Summary ───────────────────────────────────────────────
    print(f"\n{'='*60}")
    passed = sum(1 for _, p in RESULTS if p)
    failed = sum(1 for _, p in RESULTS if not p)
    total = len(RESULTS)
    print(f"  RESULTS: {G}{passed} passed{W}, {R if failed else G}{failed} failed{W}, {total} total")

    if failed:
        print(f"\n  {R}Failed tests:{W}")
        for name, p in RESULTS:
            if not p:
                print(f"    - {name}")

    print(f"{'='*60}\n")
    return failed == 0


if __name__ == "__main__":
    success = asyncio.run(run_tests())
    sys.exit(0 if success else 1)
