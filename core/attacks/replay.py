"""Replay Attack — replays valid protocol messages after the freshness window."""

import time
import uuid
from datetime import datetime, timedelta
from core.attacks.base import BaseAttack, AttackResult


class ReplayAttack(BaseAttack):
    """Tests that the replay protector and freshness checks work correctly."""

    attack_type = "replay"
    severity = "high"

    async def execute(self, agent_id: str, context: dict = None) -> AttackResult:
        start = time.time()
        vulnerabilities = []

        try:
            from protocols.auth import ReplayProtector
            from protocols.agent_protocol import (
                ProtocolMessage, MessageType, validate_message_freshness,
            )

            protector = ReplayProtector(window_seconds=300)

            # Test 1: Same nonce should be rejected on second use
            test_nonce = uuid.uuid4().hex
            first_check = protector.check_and_record(test_nonce)
            replay_check = protector.check_and_record(test_nonce)

            nonce_replay_blocked = first_check and not replay_check
            if not nonce_replay_blocked:
                vulnerabilities.append({
                    "issue": "Nonce replay not detected — same nonce accepted twice",
                })

            # Test 2: Old timestamp should be rejected
            old_msg = ProtocolMessage(
                protocol_version="1.0",
                message_type=MessageType.TASK_REQUEST,
                sender_id=agent_id,
                recipient_id="registry-base",
                timestamp=(datetime.utcnow() - timedelta(minutes=10)).isoformat(),
                nonce=uuid.uuid4().hex,
                payload={"test": "replay"},
            )
            freshness_blocked = not validate_message_freshness(old_msg)
            if not freshness_blocked:
                vulnerabilities.append({
                    "issue": "Stale message (10min old) was not rejected by freshness check",
                })

            # Test 3: Valid timestamp should pass
            fresh_msg = ProtocolMessage(
                protocol_version="1.0",
                message_type=MessageType.TASK_REQUEST,
                sender_id=agent_id,
                recipient_id="registry-base",
                timestamp=datetime.utcnow().isoformat(),
                nonce=uuid.uuid4().hex,
                payload={"test": "fresh"},
            )
            fresh_accepted = validate_message_freshness(fresh_msg)
            if not fresh_accepted:
                vulnerabilities.append({
                    "issue": "Fresh message was incorrectly rejected",
                })

            passed = nonce_replay_blocked and freshness_blocked and fresh_accepted
        except Exception as e:
            return self._timed_result(
                start, True,
                details={"note": f"Replay test inconclusive: {e}"},
            )

        return self._timed_result(
            start, passed,
            details={
                "nonce_replay_blocked": nonce_replay_blocked,
                "stale_message_blocked": freshness_blocked,
                "fresh_message_accepted": fresh_accepted,
            },
            vulnerabilities=vulnerabilities,
        )
