"""
Tests for Bastion Protocol DIRECT mode (no passport office) and session
resumption (RESUME/RESUME_ACK).

Covers:
1. DIRECT mode: successful mutual handshake, TOFU pinning on first contact
2. DIRECT mode: reconnect with the same key succeeds via pinned match
3. DIRECT mode: impersonation (different key, same agent_id) is rejected
4. DIRECT mode: tofu=False rejects an unpinned agent_id outright
5. DIRECT mode: revoked peer is rejected
6. Resumption: ticket issue -> redeem -> matching derived session keys
7. Resumption: resumed key differs from the original session's shared key
8. Resumption: ticket is single-use (replay is rejected)
9. Resumption: rotated ticket from RESUME_ACK works for the next resumption
10. Resumption: expired ticket is rejected
11. Resumption: wrong ticket_key is rejected
12. Resumption: revocation_check callback can reject a resumed session
"""

import asyncio
import os
import sys
import tempfile

# Add SDK to path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "sdk"))

from lastbastion.crypto import generate_keypair
from lastbastion.protocol.trust_store import PeerTrustStore
from lastbastion.protocol.handshake import (
    DirectHandshakeInitiator,
    DirectHandshakeResponder,
    NonceRegistry,
    build_resume,
    ResumptionResponder,
    complete_resume,
)
from lastbastion.protocol.resumption import derive_resumption_secret, issue_ticket
from lastbastion.protocol.socket import DirectAgentSocket


def _trust_store(tmp_path_name: str) -> PeerTrustStore:
    d = tempfile.mkdtemp()
    return PeerTrustStore(os.path.join(d, tmp_path_name))


# ---------------------------------------------------------------------------
# DIRECT mode
# ---------------------------------------------------------------------------

def test_direct_mode_mutual_handshake_and_tofu():
    store_a = _trust_store("a.json")
    store_b = _trust_store("b.json")
    pub_a, priv_a = generate_keypair()
    pub_b, priv_b = generate_keypair()

    initiator = DirectHandshakeInitiator("agent-a", pub_a, priv_a, store_a)
    hello = initiator.build_hello()

    responder = DirectHandshakeResponder("agent-b", pub_b, priv_b, store_b)
    ack, resp_result = responder.process_hello(hello, tofu=True)

    init_result = initiator.complete(ack, tofu=True)

    assert init_result.session_keys.shared_key == resp_result.session_keys.shared_key
    assert init_result.peer_agent_id == "agent-b"
    assert resp_result.peer_agent_id == "agent-a"
    assert init_result.trust_pin.is_new is True
    assert resp_result.trust_pin.is_new is True


def test_direct_mode_reconnect_with_same_key_succeeds():
    store_a = _trust_store("a.json")
    store_b = _trust_store("b.json")
    pub_a, priv_a = generate_keypair()
    pub_b, priv_b = generate_keypair()

    # First contact — pins both directions
    i1 = DirectHandshakeInitiator("agent-a", pub_a, priv_a, store_a)
    h1 = i1.build_hello()
    r1 = DirectHandshakeResponder("agent-b", pub_b, priv_b, store_b)
    a1, rr1 = r1.process_hello(h1, tofu=True)
    i1.complete(a1, tofu=True)

    # Reconnect with the SAME keys — should succeed, and NOT be flagged "new"
    i2 = DirectHandshakeInitiator("agent-a", pub_a, priv_a, store_a)
    h2 = i2.build_hello()
    r2 = DirectHandshakeResponder("agent-b", pub_b, priv_b, store_b)
    a2, rr2 = r2.process_hello(h2, tofu=True)
    ir2 = i2.complete(a2, tofu=True)

    assert rr2.trust_pin.is_new is False
    assert ir2.session_keys.shared_key == rr2.session_keys.shared_key


def test_direct_mode_impersonation_rejected():
    """A different keypair claiming an already-pinned agent_id must be rejected,
    not silently accepted as a key rotation."""
    store_a = _trust_store("a.json")
    store_b = _trust_store("b.json")
    pub_a, priv_a = generate_keypair()
    pub_b, priv_b = generate_keypair()

    # Pin agent-a's real key on store_b via first contact
    i1 = DirectHandshakeInitiator("agent-a", pub_a, priv_a, store_a)
    h1 = i1.build_hello()
    r1 = DirectHandshakeResponder("agent-b", pub_b, priv_b, store_b)
    r1.process_hello(h1, tofu=True)

    # Attacker claims to be "agent-a" with a DIFFERENT keypair
    pub_evil, priv_evil = generate_keypair()
    evil = DirectHandshakeInitiator("agent-a", pub_evil, priv_evil, store_a)
    h_evil = evil.build_hello()
    r2 = DirectHandshakeResponder("agent-b", pub_b, priv_b, store_b)

    raised = False
    try:
        r2.process_hello(h_evil, tofu=True)
    except ValueError as e:
        raised = True
        assert "trust check failed" in str(e)
    assert raised, "impersonation with a different key must be rejected"


def test_direct_mode_tofu_disabled_rejects_unknown_agent():
    store_a = _trust_store("a.json")
    store_b = _trust_store("b.json")
    pub_a, priv_a = generate_keypair()
    pub_b, priv_b = generate_keypair()

    initiator = DirectHandshakeInitiator("agent-a", pub_a, priv_a, store_a)
    hello = initiator.build_hello()
    responder = DirectHandshakeResponder("agent-b", pub_b, priv_b, store_b)

    raised = False
    try:
        responder.process_hello(hello, tofu=False)
    except ValueError:
        raised = True
    assert raised, "with tofu=False, an unpinned agent_id must be rejected"


def test_direct_mode_revoked_peer_rejected():
    store_a = _trust_store("a.json")
    store_b = _trust_store("b.json")
    pub_a, priv_a = generate_keypair()
    pub_b, priv_b = generate_keypair()

    # First contact pins agent-a
    i1 = DirectHandshakeInitiator("agent-a", pub_a, priv_a, store_a)
    h1 = i1.build_hello()
    r1 = DirectHandshakeResponder("agent-b", pub_b, priv_b, store_b)
    r1.process_hello(h1, tofu=True)

    store_b.revoke("agent-a")

    i2 = DirectHandshakeInitiator("agent-a", pub_a, priv_a, store_a)
    h2 = i2.build_hello()
    r2 = DirectHandshakeResponder("agent-b", pub_b, priv_b, store_b)

    raised = False
    try:
        r2.process_hello(h2, tofu=True)
    except ValueError as e:
        raised = True
        assert "revoked" in str(e)
    assert raised, "a revoked peer must be rejected even with a correct key"


def test_trust_store_revocation_propagates_across_process_boundary():
    """
    Regression test: PeerTrustStore loaded its pins once at __init__ and
    never re-read the file, so revoke() called by one process (or one
    PeerTrustStore instance sharing the same on-disk file with another --
    a real deployment shape: multiple workers, or a server process plus a
    separate revocation-check process) was invisible to any OTHER instance
    already holding that file open until it restarted. A revoked peer
    stayed trusted indefinitely on every instance that didn't independently
    restart. Simulates two processes by constructing two separate
    PeerTrustStore objects against the SAME file path.
    """
    d = tempfile.mkdtemp()
    path = os.path.join(d, "shared.json")

    store_process_a = PeerTrustStore(path)
    store_process_b = PeerTrustStore(path)

    pub, _priv = generate_keypair()
    store_process_a.pin("agent-x", pub)

    # process_b doesn't know about the pin yet (loaded before process_a wrote
    # it) -- but a read should pick it up via the mtime-based reload.
    assert store_process_b.get_pinned("agent-x") == pub

    # process_b revokes -- process_a (a DIFFERENT in-memory instance) must
    # see the revocation on its next check, not just on-disk.
    assert store_process_b.revoke("agent-x") is True
    assert store_process_a.get_pinned("agent-x") is None, (
        "a revocation from a different process/instance sharing the same "
        "trust-store file must be visible here, not just on disk"
    )


# ---------------------------------------------------------------------------
# Session Resumption
# ---------------------------------------------------------------------------

def test_resumption_round_trip_derives_matching_keys():
    ticket_key = os.urandom(32)
    shared_key = os.urandom(32)
    rs = derive_resumption_secret(shared_key)
    ticket = issue_ticket(ticket_key, "agent-a", "pub-a-hex", rs)

    responder = ResumptionResponder(ticket_key, nonce_registry=NonceRegistry())
    client_nonce = os.urandom(32)
    resume_frame = build_resume(ticket, client_nonce)

    ack_frame, resp_result = responder.process_resume(resume_frame)
    client_keys, next_ticket = complete_resume(ack_frame, client_nonce, rs)

    assert client_keys.shared_key == resp_result.session_keys.shared_key
    assert resp_result.peer_agent_id == "agent-a"


def test_resumed_key_differs_from_original_shared_key():
    """The resumed traffic key must never equal the original session's shared
    key — a leaked ticket must not expose the original session's traffic."""
    ticket_key = os.urandom(32)
    shared_key = os.urandom(32)
    rs = derive_resumption_secret(shared_key)
    ticket = issue_ticket(ticket_key, "agent-a", "pub-a-hex", rs)

    responder = ResumptionResponder(ticket_key, nonce_registry=NonceRegistry())
    resume_frame = build_resume(ticket, os.urandom(32))
    _ack, resp_result = responder.process_resume(resume_frame)

    assert resp_result.session_keys.shared_key != shared_key


def test_resumption_ticket_is_single_use():
    ticket_key = os.urandom(32)
    rs = derive_resumption_secret(os.urandom(32))
    ticket = issue_ticket(ticket_key, "agent-a", "pub-a-hex", rs)

    registry = NonceRegistry()
    responder = ResumptionResponder(ticket_key, nonce_registry=registry)

    frame1 = build_resume(ticket, os.urandom(32))
    responder.process_resume(frame1)  # first redemption succeeds

    frame2 = build_resume(ticket, os.urandom(32))  # same ticket again
    raised = False
    try:
        responder.process_resume(frame2)
    except ValueError as e:
        raised = True
        assert "TICKET_REPLAYED" in str(e)
    assert raised, "redeeming the same ticket twice must be rejected"


def test_resumption_rotated_ticket_works_next_time():
    ticket_key = os.urandom(32)
    rs = derive_resumption_secret(os.urandom(32))
    ticket = issue_ticket(ticket_key, "agent-a", "pub-a-hex", rs)

    responder = ResumptionResponder(ticket_key, nonce_registry=NonceRegistry())
    frame1 = build_resume(ticket, os.urandom(32))
    ack1, result1 = responder.process_resume(frame1)

    assert result1.next_ticket != ticket

    frame2 = build_resume(result1.next_ticket, os.urandom(32))
    ack2, result2 = responder.process_resume(frame2)
    assert result2.peer_agent_id == "agent-a"


def test_resumption_ticket_replay_rejected_after_handshake_freshness_window():
    """
    Regression test for a real vulnerability: ResumptionResponder used to
    default to the *global* NonceRegistry, whose purge window is
    HANDSHAKE_FRESHNESS_SECONDS (30s) -- correct for handshake nonces, wrong
    for ticket IDs, which stay valid for DEFAULT_TICKET_TTL_SECONDS (1 hour).
    A captured ticket was replayable for ~59 minutes after the first 30
    seconds, no private key needed. test_resumption_ticket_is_single_use
    replays immediately and would pass either way -- it never exercised the
    window this test specifically targets.

    Builds a ResumptionResponder with NO explicit nonce_registry (so it
    builds its own default -- exactly the vulnerable path), redeems a
    ticket, fast-forwards the registry's internal clock past the old 30s
    window while staying well inside the ticket's real 1-hour lifetime, and
    asserts the replay is still rejected.
    """
    ticket_key = os.urandom(32)
    rs = derive_resumption_secret(os.urandom(32))
    ticket = issue_ticket(ticket_key, "agent-a", "pub-a-hex", rs)

    responder = ResumptionResponder(ticket_key)  # no nonce_registry -- uses the default path

    # Force the in-memory fallback path deterministically -- if Redis
    # happens to be reachable in whatever environment runs this test, the
    # registry would silently use SET NX EX instead, and the manual
    # timestamp manipulation below would be a no-op against real Redis TTLs
    # (verified this happens: this exact test initially "passed" for the
    # wrong reason when Redis was running locally, testing nothing).
    registry = responder._nonce_registry
    registry._redis = None

    frame1 = build_resume(ticket, os.urandom(32))
    responder.process_resume(frame1)  # first redemption succeeds

    # Fast-forward the registry's internal clock past the OLD 30s window
    # (the bug) while staying inside the ticket's real ~3600s lifetime.
    for nonce, ts in list(registry._seen.items()):
        registry._seen[nonce] = ts - 40  # simulate 40s elapsed

    frame2 = build_resume(ticket, os.urandom(32))  # same ticket, replayed
    raised = False
    try:
        responder.process_resume(frame2)
    except ValueError as e:
        raised = True
        assert "TICKET_REPLAYED" in str(e)
    assert raised, "a replayed ticket must still be rejected 40s later, well inside its real TTL"


def test_resumption_responder_uses_explicitly_passed_empty_registry():
    """
    Regression test for a real bug found while writing the replay-window
    test above: ResumptionResponder.__init__ used
    `self._nonce_registry = nonce_registry or NonceRegistry(...)`. Python
    falls back to `or`'s right side whenever the left side is falsy --
    and NonceRegistry defines __len__, so a FRESHLY CONSTRUCTED (therefore
    empty, therefore falsy) registry passed in explicitly was silently
    discarded and replaced by a brand-new internal one. Any caller who did
    the documented "pass a dedicated registry" pattern got ignored with no
    error. Asserts the exact registry object passed in is the one actually
    used, via identity comparison.
    """
    ticket_key = os.urandom(32)
    my_registry = NonceRegistry()  # freshly constructed -- empty, therefore falsy
    assert bool(my_registry) is False, "sanity check: an empty NonceRegistry is falsy"

    responder = ResumptionResponder(ticket_key, nonce_registry=my_registry)
    assert responder._nonce_registry is my_registry, (
        "an explicitly-passed registry must be used as-is, even when empty"
    )


def test_resumption_expired_ticket_rejected():
    ticket_key = os.urandom(32)
    rs = derive_resumption_secret(os.urandom(32))
    expired_ticket = issue_ticket(ticket_key, "agent-a", "pub-a-hex", rs, ttl_seconds=-1)

    responder = ResumptionResponder(ticket_key, nonce_registry=NonceRegistry())
    frame = build_resume(expired_ticket, os.urandom(32))

    raised = False
    try:
        responder.process_resume(frame)
    except ValueError as e:
        raised = True
        assert "TICKET_INVALID" in str(e)
    assert raised, "an expired ticket must be rejected"


def test_resumption_wrong_ticket_key_rejected():
    ticket_key = os.urandom(32)
    other_key = os.urandom(32)
    rs = derive_resumption_secret(os.urandom(32))
    ticket = issue_ticket(ticket_key, "agent-a", "pub-a-hex", rs)

    responder = ResumptionResponder(other_key, nonce_registry=NonceRegistry())
    frame = build_resume(ticket, os.urandom(32))

    raised = False
    try:
        responder.process_resume(frame)
    except ValueError as e:
        raised = True
        assert "TICKET_INVALID" in str(e)
    assert raised, "a ticket encrypted with a different key must be rejected"


def test_resumption_revocation_callback_rejects_session():
    ticket_key = os.urandom(32)
    rs = derive_resumption_secret(os.urandom(32))
    ticket = issue_ticket(ticket_key, "agent-a", "pub-a-hex", rs)

    responder = ResumptionResponder(
        ticket_key,
        nonce_registry=NonceRegistry(),
        revocation_check=lambda agent_id: agent_id == "agent-a",
    )
    frame = build_resume(ticket, os.urandom(32))

    raised = False
    try:
        responder.process_resume(frame)
    except ValueError as e:
        raised = True
        assert "PEER_REVOKED" in str(e)
    assert raised, "a revoked agent_id must be rejected even with a valid ticket"


# ---------------------------------------------------------------------------
# DirectAgentSocket -- real over-the-wire TCP tests (not just in-process crypto)
# ---------------------------------------------------------------------------

def test_socket_malformed_data_payload_raises_connection_error():
    """
    Regression test: recv() called deserialize_payload() unguarded, so a
    peer sending a structurally-valid DATA frame with a payload that isn't
    valid msgpack raised a raw msgpack exception (or bare ValueError)
    instead of ConnectionError -- every docstring in AgentConnection only
    documents catching ConnectionError, so a caller following that pattern
    would not catch this. In trusted_transport=True mode there's no
    decryption/MAC step to reject a tampered payload first, so any peer
    that completed a valid handshake can trigger this just by sending
    garbage bytes as a DATA payload.

    Directly constructs a DATA frame with a non-msgpack payload and drives
    AgentConnection.recv()'s dispatch logic via the real FrameDecoder, not
    a mock, to prove the actual code path raises the right type.
    """
    async def run():
        d = tempfile.mkdtemp()
        store_client = PeerTrustStore(os.path.join(d, "client.json"))
        store_server = PeerTrustStore(os.path.join(d, "server.json"))
        pub_c, priv_c = generate_keypair()
        pub_s, priv_s = generate_keypair()

        server_saw_error = []

        async def handle(conn):
            try:
                await conn.recv()
            except ConnectionError:
                server_saw_error.append("ConnectionError")
            except Exception as e:
                server_saw_error.append(type(e).__name__)
            await conn.close()

        server = DirectAgentSocket.listen(
            agent_id="server-agent", public_key=pub_s, signing_key=priv_s,
            trust_store=store_server, port=19317, trusted_transport=True,
        )
        server.on_connect(handle)
        await server.start_background()
        await asyncio.sleep(0.1)

        try:
            conn, _t, _s = await DirectAgentSocket.connect(
                "localhost", agent_id="client-agent", public_key=pub_c,
                signing_key=priv_c, trust_store=store_client, port=19317,
                trusted_transport=True,
            )
            # Send a structurally-valid DATA frame whose payload is NOT
            # valid msgpack -- bypasses conn.send()'s normal
            # serialize_payload() call to inject genuinely malformed bytes,
            # exactly what an adversarial peer would do.
            bad_frame = conn._encoder.encode_data(
                {"placeholder": True}, conn._encrypt_func,
            )
            bad_frame.payload = b"\xff\xff\xff not valid msgpack \x00\x01"
            async with conn._send_lock:
                await conn._write_frame_raw(bad_frame)
            await asyncio.sleep(0.3)
            await conn.close()
        finally:
            await server.stop()

        assert server_saw_error == ["ConnectionError"], (
            f"expected the server's recv() to raise ConnectionError for a "
            f"malformed payload, got: {server_saw_error}"
        )

    asyncio.run(run())


def test_socket_fresh_handshake_and_data_exchange():
    async def run():
        d = tempfile.mkdtemp()
        store_client = PeerTrustStore(os.path.join(d, "client.json"))
        store_server = PeerTrustStore(os.path.join(d, "server.json"))
        pub_c, priv_c = generate_keypair()
        pub_s, priv_s = generate_keypair()

        async def handle(conn):
            msg = await conn.recv()
            await conn.send({"echo": msg})
            await conn.close()

        server = DirectAgentSocket.listen(
            agent_id="server-agent", public_key=pub_s, signing_key=priv_s,
            trust_store=store_server, port=19311,
        )
        server.on_connect(handle)
        await server.start_background()
        await asyncio.sleep(0.1)

        try:
            conn, ticket, secret = await DirectAgentSocket.connect(
                "localhost", agent_id="client-agent", public_key=pub_c,
                signing_key=priv_c, trust_store=store_client, port=19311,
            )
            assert conn.peer.agent_id == "server-agent"
            await conn.send({"hello": "world"})
            resp = await conn.recv()
            assert resp["echo"]["hello"] == "world"
            await conn.close()
        finally:
            await server.stop()

    asyncio.run(run())


def test_socket_concurrent_streams_do_not_corrupt_each_other():
    """
    Regression test for a real bug: send_stream() used to acquire/release
    _send_lock per-frame (via _write_frame()), not for the whole stream --
    two concurrent send_stream() calls on the same connection could
    interleave their STREAM_START/CHUNK/END frames on the wire. recv_stream()
    also never checked a chunk's stream_id against the stream it was
    assembling, so an interleaved chunk from a DIFFERENT stream would be
    silently placed into the wrong reassembly buffer with no exception.

    Fires two concurrent send_stream() calls on the SAME connection with
    distinct, verifiably-different payloads, and confirms both are received
    completely intact (correct hash) via two recv_stream() calls -- if
    frames interleaved or a chunk landed in the wrong stream, either the
    hash check inside recv_stream() would fail, or this test's own
    byte-for-byte comparison would.
    """
    async def run():
        d = tempfile.mkdtemp()
        store_client = PeerTrustStore(os.path.join(d, "client.json"))
        store_server = PeerTrustStore(os.path.join(d, "server.json"))
        pub_c, priv_c = generate_keypair()
        pub_s, priv_s = generate_keypair()

        received = []

        async def handle(conn):
            # Two sequential recv_stream() calls -- each fully serialized by
            # _recv_lock, receiving whichever stream's STREAM_START arrives
            # first on the wire (order between the two concurrent senders
            # isn't guaranteed, and doesn't need to be -- correctness here
            # means neither stream's bytes end up corrupted or merged).
            received.append(await conn.recv_stream())
            received.append(await conn.recv_stream())
            await conn.close()

        server = DirectAgentSocket.listen(
            agent_id="server-agent", public_key=pub_s, signing_key=priv_s,
            trust_store=store_server, port=19315,
        )
        server.on_connect(handle)
        await server.start_background()
        await asyncio.sleep(0.1)

        try:
            conn, _t, _s = await DirectAgentSocket.connect(
                "localhost", agent_id="client-agent", public_key=pub_c,
                signing_key=priv_c, trust_store=store_client, port=19315,
            )
            # Distinct payloads with a small chunk_size relative to size --
            # many chunks means many per-frame lock acquire/release cycles
            # on the old code, maximizing the interleaving window. Verified
            # empirically against the pre-fix code (git-stashed and run
            # directly): chunk_size=4096 with 50KB payloads didn't reliably
            # trigger the race on fast localhost loopback (no real
            # backpressure = no forced yield point for asyncio to actually
            # switch tasks at), but chunk_size=64 with 500KB payloads
            # reliably did -- it crashed the old code with
            # ConnectionResetError from interleaved frames desyncing the
            # wire protocol. That's this bug manifesting as a hard failure
            # rather than silent corruption, and is exactly what these
            # sizes are chosen to reproduce reliably.
            payload_a = b"A" * 500_000 + os.urandom(8)
            payload_b = b"B" * 500_000 + os.urandom(8)

            await asyncio.gather(
                conn.send_stream(payload_a, chunk_size=64),
                conn.send_stream(payload_b, chunk_size=64),
            )

            await asyncio.sleep(1.0)  # let the server finish both recv_stream() calls (~15.6k frames total)
            await conn.close()
        finally:
            await server.stop()

        assert len(received) == 2
        assert {payload_a, payload_b} == set(received), (
            "both streams must arrive byte-for-byte intact and unmerged"
        )

    asyncio.run(run())


def test_socket_resumption_over_the_wire():
    async def run():
        d = tempfile.mkdtemp()
        store_client = PeerTrustStore(os.path.join(d, "client.json"))
        store_server = PeerTrustStore(os.path.join(d, "server.json"))
        pub_c, priv_c = generate_keypair()
        pub_s, priv_s = generate_keypair()
        ticket_key = os.urandom(32)

        async def handle(conn):
            msg = await conn.recv()
            await conn.send({"echo": msg})
            await conn.close()

        server = DirectAgentSocket.listen(
            agent_id="server-agent", public_key=pub_s, signing_key=priv_s,
            trust_store=store_server, port=19312, ticket_key=ticket_key,
        )
        server.on_connect(handle)
        await server.start_background()
        await asyncio.sleep(0.1)

        try:
            conn, ticket, secret = await DirectAgentSocket.connect(
                "localhost", agent_id="client-agent", public_key=pub_c,
                signing_key=priv_c, trust_store=store_client, port=19312,
            )
            assert ticket is not None and secret is not None
            await conn.close()
            await asyncio.sleep(0.05)

            conn2, ticket2, secret2 = await DirectAgentSocket.connect(
                "localhost", agent_id="client-agent", public_key=pub_c,
                signing_key=priv_c, trust_store=store_client, port=19312,
                resume_ticket=ticket, resumption_secret=secret,
            )
            assert conn2.peer.verdict == "RESUMED"
            await conn2.send({"resumed": True})
            resp = await conn2.recv()
            assert resp["echo"]["resumed"] is True
            await conn2.close()
        finally:
            await server.stop()

    asyncio.run(run())


def test_socket_bad_ticket_falls_back_to_fresh_handshake():
    async def run():
        d = tempfile.mkdtemp()
        store_client = PeerTrustStore(os.path.join(d, "client.json"))
        store_server = PeerTrustStore(os.path.join(d, "server.json"))
        pub_c, priv_c = generate_keypair()
        pub_s, priv_s = generate_keypair()
        ticket_key = os.urandom(32)

        async def handle(conn):
            await conn.close()

        server = DirectAgentSocket.listen(
            agent_id="server-agent", public_key=pub_s, signing_key=priv_s,
            trust_store=store_server, port=19313, ticket_key=ticket_key,
        )
        server.on_connect(handle)
        await server.start_background()
        await asyncio.sleep(0.1)

        try:
            conn, ticket, secret = await DirectAgentSocket.connect(
                "localhost", agent_id="client-agent", public_key=pub_c,
                signing_key=priv_c, trust_store=store_client, port=19313,
                resume_ticket=os.urandom(140), resumption_secret=os.urandom(32),
            )
            # A garbage ticket must not prevent a working connection —
            # it should transparently fall back to a fresh handshake
            assert conn.peer.verdict in ("DIRECT_NEW", "DIRECT_PINNED")
            await conn.close()
        finally:
            await server.stop()

    asyncio.run(run())


def test_agent_network_bastion_overlay_uses_direct_trusted_transport():
    """
    core/agent_simulator.py's AgentNetwork is the real production path (booted
    by regional_core.py's startup_event) -- this proves it actually boots 4
    real DirectAgentSocket servers and successfully trades a real message
    between two of them, end-to-end, on the DIRECT mode + trusted_transport
    path (no issuer/passport, no per-message encryption -- see the field
    comments in AgentNetwork.__init__ for why that's the correct choice for
    agents inside one ecosystem).
    """
    sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
    from core.agent_simulator import AgentNetwork

    async def run():
        net = AgentNetwork()
        try:
            ok = await net._boot_bastion_servers()
            assert ok is True
            assert net._bastion_ready is True
            assert set(net._bastion_servers.keys()) == {"producer", "compliance", "logistics", "buyer"}

            response = await net._send_bastion_message("producer", "compliance", {
                "batch_id": "TEST-0001", "product": "kiwifruit", "quantity_kg": 1200,
            })
            assert response is not None
            assert response["status"] == "verified"
            assert response["received"]["batch_id"] == "TEST-0001"
        finally:
            for server in net._bastion_servers.values():
                await server.stop()

    asyncio.run(run())
