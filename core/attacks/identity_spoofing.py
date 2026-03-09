"""Identity Spoofing Attack — tests anti-Sybil: same public key, different agent ID."""

import time
from core.attacks.base import BaseAttack, AttackResult


class IdentitySpoofingAttack(BaseAttack):
    """Registers an agent with the same public_key under a different ID."""

    attack_type = "identity_spoofing"
    severity = "high"

    async def execute(self, agent_id: str, context: dict = None) -> AttackResult:
        start = time.time()
        vulnerabilities = []

        try:
            from core.database import find_agents_by_public_key, get_agent_trust

            # Get the target agent's public key
            trust = get_agent_trust(agent_id)
            # Simulate: look up if anyone else shares this agent's key pattern
            spoofed_id = f"spoof-{agent_id}-clone"
            fake_pub_key = f"ed25519_pub_{agent_id}"

            # Check if the system would detect the duplicate key
            existing = find_agents_by_public_key(fake_pub_key, exclude_agent_id=agent_id)

            # Also try the agent verifier's anti-Sybil check
            from core.agent_verifier import AgentVerifier
            verifier = AgentVerifier()

            # Run the identity + anti-Sybil checks
            checks = await verifier.verify_agent(
                agent_id=spoofed_id,
                agent_url="",
                public_key=fake_pub_key,
                capabilities=["spoofed_capability"],
                agent_metadata={"note": "spoofing test"},
            )

            # Check if the verifier flagged the duplicate key
            sybil_flagged = False
            if isinstance(checks, dict):
                risk_flags = checks.get("risk_flags", [])
                checks_passed = checks.get("checks_passed", {})
                sybil_flagged = (
                    not checks_passed.get("anti_sybil", True) or
                    any("sybil" in str(f).lower() or "duplicate" in str(f).lower() for f in risk_flags)
                )

            if not sybil_flagged:
                vulnerabilities.append({
                    "issue": "Identity spoofing with duplicate public key not detected",
                    "spoofed_agent": spoofed_id,
                    "shared_key": fake_pub_key[:32] + "...",
                })

            passed = sybil_flagged
        except Exception as e:
            return self._timed_result(
                start, False,
                details={"note": f"Spoofing test inconclusive: {e}"},
            )

        return self._timed_result(
            start, passed,
            details={
                "spoofed_agent_id": spoofed_id,
                "sybil_detected": passed,
            },
            vulnerabilities=vulnerabilities,
        )
