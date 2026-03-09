"""Attack simulation framework for the Agent Security Sandbox."""

from core.attacks.base import BaseAttack, AttackResult
from core.attacks.prompt_injection import PromptInjectionAttack
from core.attacks.identity_spoofing import IdentitySpoofingAttack
from core.attacks.sybil_flood import SybilFloodAttack
from core.attacks.exfiltration import DataExfiltrationAttack
from core.attacks.payload_poisoning import PayloadPoisoningAttack
from core.attacks.replay import ReplayAttack

ATTACK_REGISTRY = {
    "prompt_injection": PromptInjectionAttack,
    "identity_spoofing": IdentitySpoofingAttack,
    "sybil_flood": SybilFloodAttack,
    "data_exfiltration": DataExfiltrationAttack,
    "payload_poisoning": PayloadPoisoningAttack,
    "replay": ReplayAttack,
}

__all__ = [
    "BaseAttack",
    "AttackResult",
    "ATTACK_REGISTRY",
    "PromptInjectionAttack",
    "IdentitySpoofingAttack",
    "SybilFloodAttack",
    "DataExfiltrationAttack",
    "PayloadPoisoningAttack",
    "ReplayAttack",
]
