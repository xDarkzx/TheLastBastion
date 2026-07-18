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
