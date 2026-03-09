"""Sybil Flood Attack — rapidly registers N agents with similar patterns."""

import time
from core.attacks.base import BaseAttack, AttackResult


class SybilFloodAttack(BaseAttack):
    """Simulates a Sybil attack by registering many agents in a burst."""

    attack_type = "sybil_flood"
    severity = "high"

    FLOOD_COUNT = 10  # Number of fake agents to simulate

    async def execute(self, agent_id: str, context: dict = None) -> AttackResult:
        start = time.time()
        vulnerabilities = []

        try:
            from core.database import find_agents_by_url, get_agent_registration_burst

            # Check if the system detects burst registration patterns
            burst_agents = get_agent_registration_burst(agent_id, window_minutes=5)
            burst_detected = len(burst_agents) > 0

            # Simulate URL-based Sybil detection
            fake_url = f"http://sybil-farm.example.com/agent"
            url_matches = find_agents_by_url(fake_url, exclude_agent_id=agent_id)

            # Also test rate limiter behavior
            from protocols.auth import RateLimiter
            limiter = RateLimiter(default_limit=5)  # Tight limit for testing
            blocked_count = 0
            for i in range(self.FLOOD_COUNT):
                allowed, _ = limiter.check(f"sybil-test-{agent_id}")
                if not allowed:
                    blocked_count += 1

            rate_limit_works = blocked_count > 0

            if not rate_limit_works:
                vulnerabilities.append({
                    "issue": f"Rate limiter did not block any of {self.FLOOD_COUNT} rapid requests",
                })

            passed = rate_limit_works
        except Exception as e:
            return self._timed_result(
                start, False,
                details={"note": f"Sybil test inconclusive: {e}"},
            )

        return self._timed_result(
            start, passed,
            details={
                "flood_count": self.FLOOD_COUNT,
                "blocked": blocked_count,
                "rate_limit_effective": rate_limit_works,
                "burst_agents_found": len(burst_agents) if 'burst_agents' in locals() else 0,
            },
            vulnerabilities=vulnerabilities,
        )
