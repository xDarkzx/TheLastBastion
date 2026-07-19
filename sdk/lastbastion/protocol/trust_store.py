"""
Peer Trust Store -- key pinning for DIRECT mode (no passport office required).

Bastion Protocol has two ways to establish who you're talking to:

  PASSPORT mode -- the peer presents an Ed25519 identity signed by a trusted
    issuer (a "Bastion" trust authority). Strong guarantees (trust score,
    verdict, revocation) but requires that authority to exist and be reachable.

  DIRECT mode -- no issuer required. Two agents just need each other's own
    Ed25519 public key. This is for exactly the situation where no verification
    authority exists yet: you can still get a fast, encrypted, mutually
    authenticated channel between two agents that have exchanged keys.

DIRECT mode is only as safe as how you decide whether to trust a claimed
public key. The naive version -- "accept whatever public_key shows up in the
HELLO payload claiming to be agent X" -- is exactly the self-issued-trust bug
that was found and fixed in core/border_agent.py's PASSPORT-mode handling.
DIRECT mode needs the equivalent discipline: a claimed key must be checked
against something the verifier already knows, not trusted because the sender
said so.

This store gives two ways to know that:
  1. Explicit pinning -- you learned the peer's real key out-of-band (e.g. via
     an A2A Agent Card exchange) and pin it before ever connecting.
  2. TOFU (Trust On First Use, the SSH known_hosts model) -- the first
     connection from a given agent_id pins whatever key it presented; every
     later connection from that agent_id MUST present the same key. A
     mismatch means either the peer rotated keys (expected to be handled by
     re-pinning explicitly, not silently) or someone else is impersonating
     that agent_id -- both cases must be surfaced, never silently accepted.

Persisted to disk (JSON) -- an in-memory-only store would forget every pin on
restart, which defeats the entire point of TOFU (the first restart after
initial contact would silently re-TOFU against a potential impostor).
"""
import json
import logging
import os
import threading
import time
from dataclasses import dataclass
from typing import Dict, Optional

logger = logging.getLogger("PeerTrustStore")


@dataclass
class PinResult:
    """Outcome of checking/pinning a peer's claimed public key."""
    accepted: bool
    reason: str  # "pinned_match" | "newly_pinned" | "KEY_MISMATCH" | "revoked"
    is_new: bool = False


class PeerTrustStore:
    """
    Thread-safe, disk-persisted agent_id -> public_key pin store for DIRECT
    mode. One store per local agent (i.e. "the peers I've decided to trust"),
    not shared between unrelated agents.
    """

    def __init__(self, path: str):
        self._path = path
        self._lock = threading.Lock()
        self._pins: Dict[str, dict] = {}  # agent_id -> {public_key, pinned_at, revoked}
        self._mtime: float = 0.0
        self._load()

    def _load(self) -> None:
        if not os.path.exists(self._path):
            return
        try:
            with open(self._path) as f:
                self._pins = json.load(f)
            self._mtime = os.path.getmtime(self._path)
        except Exception as e:
            logger.warning(f"Could not load trust store {self._path}: {e}")
            self._pins = {}

    def _reload_if_changed(self) -> None:
        """
        Re-reads the store from disk if another process has modified it
        since this instance last loaded. Caller must hold self._lock.

        Without this, a revoke() or pin() from a different process sharing
        the same trust-store file (a real, likely deployment shape --
        multiple uvicorn workers, or a server process and a separate
        resumption/revocation-check process) is invisible to this instance
        until it restarts. A revoked peer stays trusted here indefinitely.
        This only checks mtime, not content -- cheap (one stat syscall) on
        every trust decision, full re-read only when the file actually
        changed.
        """
        try:
            current_mtime = os.path.getmtime(self._path) if os.path.exists(self._path) else 0.0
        except OSError:
            return
        if current_mtime != self._mtime:
            self._load()

    def _save(self) -> None:
        parent = os.path.dirname(self._path)
        if parent:
            os.makedirs(parent, exist_ok=True)
        try:
            with open(self._path, "w") as f:
                json.dump(self._pins, f, indent=2)
            self._mtime = os.path.getmtime(self._path)
        except Exception as e:
            logger.error(f"Could not persist trust store {self._path}: {e}")

    def pin(self, agent_id: str, public_key: str) -> None:
        """Explicitly pin a peer's public key (e.g. learned via an A2A Agent Card)."""
        with self._lock:
            self._reload_if_changed()
            self._pins[agent_id] = {
                "public_key": public_key,
                "pinned_at": time.time(),
                "revoked": False,
            }
            self._save()
        logger.info(f"PIN: {agent_id} -> {public_key[:16]}...")

    def revoke(self, agent_id: str) -> bool:
        """Marks a pinned peer as revoked — DIRECT mode connections from it are rejected."""
        with self._lock:
            self._reload_if_changed()  # don't clobber a pin another process just added
            if agent_id not in self._pins:
                return False
            self._pins[agent_id]["revoked"] = True
            self._save()
        logger.warning(f"REVOKE: {agent_id} — DIRECT mode connections will now be rejected")
        return True

    def get_pinned(self, agent_id: str) -> Optional[str]:
        with self._lock:
            self._reload_if_changed()
            entry = self._pins.get(agent_id)
            return entry["public_key"] if entry and not entry.get("revoked") else None

    def verify_or_pin(
        self, agent_id: str, public_key: str, tofu: bool = True
    ) -> PinResult:
        """
        Checks a peer's claimed public key against the store.

        - No existing pin + tofu=True  -> pins it, accepted (first contact).
        - No existing pin + tofu=False -> rejected (explicit-pin-only mode).
        - Existing pin, keys match     -> accepted.
        - Existing pin, keys differ    -> REJECTED. This is the security-
          critical case: never silently accept a different key for an
          agent_id you've seen before. That's either key rotation (must be
          re-pinned explicitly by the operator) or impersonation.
        - Existing pin, revoked        -> rejected.
        """
        with self._lock:
            self._reload_if_changed()  # a revoke() from another process must take effect here
            entry = self._pins.get(agent_id)

            if entry is None:
                if not tofu:
                    return PinResult(accepted=False, reason="no_pin_and_tofu_disabled")
                self._pins[agent_id] = {
                    "public_key": public_key,
                    "pinned_at": time.time(),
                    "revoked": False,
                }
                self._save()
                logger.info(f"TOFU: first contact with {agent_id}, pinned {public_key[:16]}...")
                return PinResult(accepted=True, reason="newly_pinned", is_new=True)

            if entry.get("revoked"):
                return PinResult(accepted=False, reason="revoked")

            if entry["public_key"] != public_key:
                logger.error(
                    f"KEY MISMATCH: {agent_id} previously pinned "
                    f"{entry['public_key'][:16]}... now presented {public_key[:16]}... "
                    f"— rejecting. If this is an intentional key rotation, re-pin explicitly."
                )
                return PinResult(accepted=False, reason="KEY_MISMATCH")

            return PinResult(accepted=True, reason="pinned_match")
