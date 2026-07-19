"""
Tests for protocols/registry.py's AgentRegistry memory bounds.

register_agent() is reachable unauthenticated via POST /m2m/register with a
client-supplied agent_id (see core/m2m_router.py). AgentRegistry.get_stale_agents()
existed but nothing ever called it, so _agents/_agent_services grew without
bound -- one leaked entry per unique agent_id ever registered, forever, with
no way to reclaim memory even for agents that went stale 24h+ ago.
"""
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from protocols.registry import AgentRegistry
from protocols.agent_protocol import AgentIdentity, AgentRole


def _identity(agent_id: str, last_seen: str = "") -> AgentIdentity:
    return AgentIdentity(
        agent_id=agent_id,
        public_key="pub-" + agent_id,
        role=AgentRole.DATA_PROVIDER,
        last_seen=last_seen,
    )


def test_stale_agent_is_evicted_on_the_next_registration():
    registry = AgentRegistry()
    registry._AGENT_EVICT_INTERVAL_SECONDS = 0  # force sweep every call

    # Fresh at registration time -- survives its own post-insert sweep.
    registry.register_agent(_identity("will-go-stale"))
    assert "will-go-stale" in registry._agents

    # Age it out from underneath, then register something else -- the sweep
    # triggered by *that* registration should reclaim the now-stale entry.
    registry._agents["will-go-stale"].last_seen = "2000-01-01T00:00:00"
    registry.register_agent(_identity("fresh-agent"))

    assert "will-go-stale" not in registry._agents, (
        "get_stale_agents() existed but was never consulted -- this "
        "confirms register_agent() now actually evicts stale entries"
    )
    assert "fresh-agent" in registry._agents


def test_agent_count_hard_capped_even_when_all_fresh():
    registry = AgentRegistry()
    registry._AGENT_EVICT_INTERVAL_SECONDS = 0
    registry._MAX_AGENTS = 100

    for i in range(150):
        registry.register_agent(_identity(f"agent-{i}"))

    assert len(registry._agents) <= registry._MAX_AGENTS


def test_evicting_agent_also_drops_its_services():
    from protocols.registry import ServiceListing
    import asyncio

    registry = AgentRegistry()
    registry._AGENT_EVICT_INTERVAL_SECONDS = 0

    registry.register_agent(_identity("stale-provider"))
    listing = ServiceListing(
        service_id="svc-stale-test", provider_id="stale-provider",
        name="test", description="test",
    )
    asyncio.run(registry.register_service("stale-provider", listing))
    assert "svc-stale-test" in registry._services

    registry._agents["stale-provider"].last_seen = "2000-01-01T00:00:00"
    registry.register_agent(_identity("trigger-sweep"))

    assert "stale-provider" not in registry._agents
    assert "svc-stale-test" not in registry._services, (
        "evicting a stale agent must also drop its orphaned service listings"
    )


if __name__ == "__main__":
    test_stale_agent_is_evicted_on_the_next_registration()
    test_agent_count_hard_capped_even_when_all_fresh()
    test_evicting_agent_also_drops_its_services()
    print("All AgentRegistry eviction tests passed.")
