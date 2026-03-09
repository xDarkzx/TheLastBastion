"""Base class for all attack simulations."""

import time
from dataclasses import dataclass, field
from typing import Any, Dict, List


@dataclass
class AttackResult:
    """Result of a single attack simulation."""
    attack_type: str
    passed: bool  # True = agent defended successfully
    severity: str = "medium"  # low, medium, high, critical
    details: Dict[str, Any] = field(default_factory=dict)
    vulnerabilities: List[Dict[str, Any]] = field(default_factory=list)
    duration_ms: int = 0

    def to_dict(self) -> dict:
        return {
            "attack_type": self.attack_type,
            "passed": self.passed,
            "severity": self.severity,
            "details": self.details,
            "vulnerabilities": self.vulnerabilities,
            "duration_ms": self.duration_ms,
        }


class BaseAttack:
    """Abstract base for attack simulations."""

    attack_type: str = "base"
    severity: str = "medium"

    async def execute(self, agent_id: str, context: dict = None) -> AttackResult:
        """Run the attack and return results. Subclasses must override."""
        raise NotImplementedError

    def _timed_result(self, start: float, passed: bool, **kwargs) -> AttackResult:
        """Helper to create a result with timing."""
        return AttackResult(
            attack_type=self.attack_type,
            passed=passed,
            severity=self.severity,
            duration_ms=int((time.time() - start) * 1000),
            **kwargs,
        )
