"""
Attack Simulator — orchestrates attack scenarios against agents.

Runs the selected attack types from core/attacks/ and records results to the database.
Reuses existing verification infrastructure (SchemaGatekeeper, ConsistencyAnalyzer,
ReplayProtector, etc.) rather than reimplementing checks.
"""

import logging
import time
from typing import Dict, List

from core.attacks import ATTACK_REGISTRY
from core.database import save_sandbox_attack_result
from core.protocol_bus import protocol_bus

logger = logging.getLogger("AttackSimulator")


class AttackSimulator:
    """Orchestrates attack simulations for sandbox sessions."""

    def __init__(self):
        self._registry = ATTACK_REGISTRY

    def available_attacks(self) -> List[str]:
        """Returns list of available attack type names."""
        return list(self._registry.keys())

    async def run_attacks(
        self,
        session_id: str,
        agent_id: str,
        attack_types: List[str] = None,
    ) -> List[dict]:
        """
        Run attack simulations and persist results.

        Args:
            session_id: The sandbox session to associate results with
            agent_id: The agent being tested
            attack_types: List of attack type names. If empty, runs all.

        Returns:
            List of attack result dicts
        """
        if not attack_types:
            attack_types = list(self._registry.keys())

        results = []
        for attack_type in attack_types:
            attack_cls = self._registry.get(attack_type)
            if not attack_cls:
                logger.warning(f"Unknown attack type: {attack_type}")
                results.append({
                    "attack_type": attack_type,
                    "passed": False,
                    "severity": "low",
                    "details": {"error": f"Unknown attack type: {attack_type}"},
                    "vulnerabilities": [],
                    "duration_ms": 0,
                })
                continue

            # Broadcast attack start
            try:
                protocol_bus.record(
                    direction="INTERNAL",
                    message_type="SANDBOX_ATTACK_START",
                    sender_id="attack-simulator",
                    recipient_id=agent_id,
                    endpoint=f"/sandbox/sessions/{session_id}/attacks",
                    payload_summary=f"attack_type={attack_type}",
                    auth_result="INTERNAL",
                )
            except Exception:
                pass

            try:
                attack = attack_cls()
                result = await attack.execute(agent_id=agent_id, context={"session_id": session_id})
                result_dict = result.to_dict()
            except Exception as e:
                logger.error(f"Attack {attack_type} failed: {e}")
                result_dict = {
                    "attack_type": attack_type,
                    "passed": False,
                    "severity": "low",
                    "details": {"error": str(e)},
                    "vulnerabilities": [{"issue": f"Attack execution failed: {e}"}],
                    "duration_ms": 0,
                }

            # Persist to DB
            try:
                save_sandbox_attack_result(
                    session_id=session_id,
                    agent_id=agent_id,
                    attack_type=result_dict["attack_type"],
                    passed=result_dict["passed"],
                    severity=result_dict["severity"],
                    details=result_dict["details"],
                    vulnerabilities=result_dict["vulnerabilities"],
                    duration_ms=result_dict["duration_ms"],
                )
            except Exception as e:
                logger.warning(f"Failed to persist attack result: {e}")

            # Broadcast attack result
            try:
                protocol_bus.record(
                    direction="INTERNAL",
                    message_type="SANDBOX_ATTACK_RESULT",
                    sender_id="attack-simulator",
                    recipient_id=agent_id,
                    endpoint=f"/sandbox/sessions/{session_id}/attacks",
                    payload_summary=f"attack_type={attack_type}, passed={result_dict['passed']}, severity={result_dict['severity']}",
                    auth_result="INTERNAL",
                )
            except Exception:
                pass

            results.append(result_dict)
            logger.info(
                f"Attack {attack_type}: {'PASSED' if result_dict['passed'] else 'FAILED'} "
                f"({result_dict['duration_ms']}ms)"
            )

        # Broadcast session complete
        total = len(results)
        passed = sum(1 for r in results if r.get("passed", False))
        resilience = passed / total if total > 0 else 0.0
        try:
            protocol_bus.record(
                direction="INTERNAL",
                message_type="SANDBOX_SESSION_COMPLETE",
                sender_id="attack-simulator",
                recipient_id=agent_id,
                endpoint=f"/sandbox/sessions/{session_id}/attacks",
                payload_summary=f"total={total}, passed={passed}, resilience={resilience:.2f}",
                auth_result="INTERNAL",
            )
        except Exception:
            pass

        return results
