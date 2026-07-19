"""
Tests for core/bastion_bus.py's BastionProtocolBus session-tracking.

Covers a memory-leak fix: a session_id that only ever records an ERROR
event (handshake rejection, timeout, transport failure -- any mid-connection
exception) previously stayed in `_active_sessions` forever, because only
CONNECTION_CLOSED was treated as terminal. Real callers (core/agent_simulator.py)
record ERROR on the exception path but do not also guarantee a follow-up
CONNECTION_CLOSED, so every failed connection attempt leaked one entry.

Also covers the defense-in-depth size caps on _active_sessions and
_agent_last_seen, in case some other future caller path fails to record any
terminal event at all.
"""
import os
import sys

sys.path.insert(0, os.path.dirname(__file__))
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from core.bastion_bus import BastionProtocolBus


def _fresh_bus() -> BastionProtocolBus:
    return BastionProtocolBus(maxlen=1000)


def test_error_event_removes_session_from_active_sessions():
    bus = _fresh_bus()
    bus.record(
        event_type="HANDSHAKE_INIT", frame_type="HELLO",
        sender_agent="alpha", receiver_agent="beta",
        direction="SENT", session_id="sess-1",
    )
    assert "sess-1" in bus._active_sessions

    bus.record(
        event_type="ERROR", frame_type="ERROR",
        sender_agent="alpha", receiver_agent="beta",
        direction="SENT", session_id="sess-1", error_message="handshake rejected",
    )
    assert "sess-1" not in bus._active_sessions, (
        "ERROR should be treated as terminal -- a session that never "
        "completes should not linger in _active_sessions forever"
    )


def test_many_failed_handshakes_do_not_accumulate():
    bus = _fresh_bus()
    for i in range(2000):
        sid = f"sess-fail-{i}"
        bus.record(
            event_type="HANDSHAKE_INIT", frame_type="HELLO",
            sender_agent="alpha", receiver_agent="beta",
            direction="SENT", session_id=sid,
        )
        bus.record(
            event_type="ERROR", frame_type="ERROR",
            sender_agent="alpha", receiver_agent="beta",
            direction="SENT", session_id=sid, error_message="boom",
        )
    assert len(bus._active_sessions) == 0


def test_connection_closed_still_removes_session():
    bus = _fresh_bus()
    bus.record(
        event_type="HANDSHAKE_INIT", frame_type="HELLO",
        sender_agent="alpha", receiver_agent="beta",
        direction="SENT", session_id="sess-2",
    )
    bus.record(
        event_type="HANDSHAKE_COMPLETE", frame_type="HELLO_ACK",
        sender_agent="alpha", receiver_agent="beta",
        direction="SENT", session_id="sess-2",
    )
    assert bus._active_sessions["sess-2"]["state"] == "ESTABLISHED"

    bus.record(
        event_type="CONNECTION_CLOSED", frame_type="CLOSE",
        sender_agent="alpha", receiver_agent="beta",
        direction="SENT", session_id="sess-2",
    )
    assert "sess-2" not in bus._active_sessions


def test_active_sessions_capped_even_without_terminal_event():
    bus = _fresh_bus()
    for i in range(bus._MAX_ACTIVE_SESSIONS + 50):
        bus.record(
            event_type="HANDSHAKE_INIT", frame_type="HELLO",
            sender_agent="alpha", receiver_agent="beta",
            direction="SENT", session_id=f"sess-cap-{i}",
        )
    assert len(bus._active_sessions) <= bus._MAX_ACTIVE_SESSIONS


def test_agent_last_seen_capped():
    bus = _fresh_bus()
    for i in range(bus._MAX_AGENT_LAST_SEEN + 50):
        bus.record(
            event_type="FRAME_SENT", frame_type="DATA",
            sender_agent=f"agent-{i}", receiver_agent="beta",
            direction="SENT",
        )
    assert len(bus._agent_last_seen) <= bus._MAX_AGENT_LAST_SEEN


if __name__ == "__main__":
    test_error_event_removes_session_from_active_sessions()
    test_many_failed_handshakes_do_not_accumulate()
    test_connection_closed_still_removes_session()
    test_active_sessions_capped_even_without_terminal_event()
    test_agent_last_seen_capped()
    print("All bastion_bus tests passed.")
