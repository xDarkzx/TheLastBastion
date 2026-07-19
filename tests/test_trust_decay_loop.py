"""
Regression test for regional_core.py's trust_decay_loop().

The decay-application line referenced `inactive_days`, a name that was never
bound anywhere in the function (the actual variable is `inactivity_days`).
Every decay, in both demo and normal mode, evaluates this f-string as part of
building apply_trust_decay()'s arguments -- so the NameError fired before
apply_trust_decay() was ever called, silently aborting that agent's decay
(and any agents after it in the same batch), caught by the loop's own broad
`except Exception` with nothing but a print() to show for it. No existing
test exercises trust_decay_loop() itself (test_phase_e_trust_decay in
test_progressive_trust.py only calls apply_trust_decay() directly with
hardcoded values), so this went uncaught.

This test avoids needing a live Postgres by monkeypatching the DB-facing
functions trust_decay_loop() calls, and forces exactly one loop iteration by
making asyncio.sleep a no-op that cancels the task after the first pass.
"""
import asyncio
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

import pytest


@pytest.mark.asyncio
async def test_trust_decay_loop_applies_decay_without_crashing(monkeypatch):
    import regional_core

    calls = []
    real_sleep = asyncio.sleep

    async def _fake_sleep(_seconds):
        # Actually yield to the event loop (just skip the real duration) --
        # a coroutine that returns without ever awaiting anything does not
        # yield control at all, which would starve both this loop and the
        # test's own retry loop below (both share the same patched asyncio).
        await real_sleep(0)

    def _fake_get_agents_for_decay(inactive_days):
        return [{
            "agent_id": "decay-victim",
            "trust_score": 0.70,
            "last_active_at": None,
        }]

    def _fake_apply_trust_decay(agent_id, new_score, reason):
        calls.append((agent_id, new_score, reason))
        return True

    def _fake_revoke_agent_live_keys(agent_id):
        return 0

    monkeypatch.setattr(regional_core.asyncio, "sleep", _fake_sleep)
    monkeypatch.setattr(regional_core, "get_agents_for_decay", _fake_get_agents_for_decay)
    monkeypatch.setattr(regional_core, "apply_trust_decay", _fake_apply_trust_decay)
    monkeypatch.setattr(regional_core, "revoke_agent_live_keys", _fake_revoke_agent_live_keys)
    monkeypatch.setenv("DEMO_DECAY_MODE", "0")

    task = asyncio.ensure_future(regional_core.trust_decay_loop())
    # Let exactly one iteration run (sleep is a no-op, so this yields enough
    # times for the first pass to complete) before tearing the task down.
    for _ in range(20):
        await real_sleep(0)
        if calls:
            break
    task.cancel()
    try:
        await task
    except asyncio.CancelledError:
        pass

    assert calls, (
        "apply_trust_decay should have been called at least once -- if this "
        "is empty, the decay line raised before reaching the call (the "
        "NameError this test guards against)"
    )
    agent_id, new_score, reason = calls[0]
    assert agent_id == "decay-victim"
    assert new_score < 0.70
    assert "days idle" in reason
