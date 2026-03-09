"""
Agent Verifier — 10-Check Trust Pipeline for External Agents.

Production-grade verification that queries REAL data — DB records,
protocol bus history, live HTTP probes, blockchain. Nothing self-reported.

3 Tiers, 10 Checks:
  Tier 1 — Hard Cryptographic Proofs (veto power, weight 30%)
    #1  Identity Verification (0.15)
    #2  Cryptographic Challenge-Response (0.15)

  Tier 2 — Historical Evidence (DB-backed, weight 35%)
    #3  Capability Verification (0.08)
    #4  Reputation (0.15)
    #5  Payload Quality Analysis (0.12)

  Tier 3 — Behavioral & Environmental (weight 35%)
    #6  Behavioral Analysis (0.10)
    #7  Network & Liveness (0.08)
    #8  Cross-Reference Trust (0.07)
    #9  Anti-Sybil (0.05)
    #10 Temporal Analysis (0.05)

Verdicts: TRUSTED / SUSPICIOUS / MALICIOUS
Trust Levels: NONE / NEW / BASIC / VERIFIED / ESTABLISHED / GOLD
"""
import hashlib
import ipaddress
import logging
import statistics
from datetime import datetime, timedelta
from typing import Any, Dict, List, Optional
from urllib.parse import urlparse

logger = logging.getLogger("AgentVerifier")


def _validate_url_not_internal(url: str) -> bool:
    """Reject URLs pointing to private/internal IP ranges. Prevents SSRF via DNS rebinding."""
    if not url:
        return False
    try:
        import socket as _socket
        parsed = urlparse(url)
        hostname = parsed.hostname
        if not hostname:
            return False
        # Reject common internal hostnames
        if hostname in ("localhost", "127.0.0.1", "0.0.0.0", "::1"):
            return False
        if hostname.endswith(".internal") or hostname.endswith(".local"):
            return False
        # ALWAYS resolve hostname to IP and check resolved address
        # This prevents DNS rebinding where hostname resolves to internal IP
        try:
            resolved_ips = _socket.getaddrinfo(hostname, None)
            for family, _, _, _, sockaddr in resolved_ips:
                ip_str = sockaddr[0]
                addr = ipaddress.ip_address(ip_str)
                if addr.is_private or addr.is_loopback or addr.is_link_local or addr.is_reserved:
                    return False
        except _socket.gaierror:
            return False  # Can't resolve — reject
        return True
    except Exception:
        return False

# Trust level thresholds
TRUST_LEVELS = [
    (0.85, "GOLD"),
    (0.75, "ESTABLISHED"),
    (0.65, "VERIFIED"),
    (0.55, "BASIC"),
    (0.40, "NEW"),
    (0.00, "NONE"),
]

# Verdict thresholds
VERDICT_THRESHOLDS = {
    "MALICIOUS": 0.40,
    "SUSPICIOUS": 0.65,
}

VERIFICATION_TTL_DAYS = 90

# Check weights (sum = 1.0)
CHECK_WEIGHTS = {
    "identity": 0.15,
    "cryptographic": 0.15,
    "capabilities": 0.08,
    "reputation": 0.15,
    "payload_quality": 0.12,
    "behavioral": 0.10,
    "network": 0.08,
    "cross_reference": 0.07,
    "anti_sybil": 0.05,
    "temporal": 0.05,
}

# Critical flags that count toward risk category
CRITICAL_FLAGS = {
    "SYBIL_KEY", "SYBIL_URL", "KEY_ROTATION", "CREDENTIAL_TESTING",
    "POISON_SUSPECT", "DORMANT_REACTIVATION", "MALICIOUS_ASSOCIATION",
}


def _get_trust_level(score: float) -> str:
    for threshold, level in TRUST_LEVELS:
        if score >= threshold:
            return level
    return "NONE"


def _get_risk_category(flags: list) -> str:
    critical_count = sum(1 for f in flags if any(cf in f for cf in CRITICAL_FLAGS))
    total = len(flags)
    if critical_count >= 2 or total >= 5:
        return "CRITICAL"
    if critical_count >= 1 or total >= 3:
        return "HIGH"
    if total >= 2:
        return "MEDIUM"
    if total >= 1:
        return "LOW"
    return "NONE"


class AgentVerifier:
    """
    10-check trust pipeline. Every check queries real data sources.
    """

    def __init__(self, blockchain_anchor=None, db_session_factory=None):
        self.blockchain_anchor = blockchain_anchor
        self._db_session_factory = db_session_factory  # SessionLocal
        self._checks = [
            ("identity", CHECK_WEIGHTS["identity"], self._check_identity),
            ("cryptographic", CHECK_WEIGHTS["cryptographic"], self._check_cryptographic),
            ("capabilities", CHECK_WEIGHTS["capabilities"], self._check_capabilities),
            ("reputation", CHECK_WEIGHTS["reputation"], self._check_reputation),
            ("payload_quality", CHECK_WEIGHTS["payload_quality"], self._check_payload_quality),
            ("behavioral", CHECK_WEIGHTS["behavioral"], self._check_behavioral),
            ("network", CHECK_WEIGHTS["network"], self._check_network),
            ("cross_reference", CHECK_WEIGHTS["cross_reference"], self._check_cross_reference),
            ("anti_sybil", CHECK_WEIGHTS["anti_sybil"], self._check_anti_sybil),
            ("temporal", CHECK_WEIGHTS["temporal"], self._check_temporal),
        ]

    # ------------------------------------------------------------------
    # Passport fingerprinting
    # ------------------------------------------------------------------

    @staticmethod
    def compute_passport_fingerprint(
        agent_id: str, public_key: str, capabilities: list
    ) -> str:
        """Hash (agent_id, public_key, sorted capabilities) into a stable fingerprint."""
        caps_str = ",".join(sorted(capabilities or []))
        raw = f"{agent_id}|{public_key or ''}|{caps_str}"
        return hashlib.sha256(raw.encode()).hexdigest()

    # ------------------------------------------------------------------
    # Blockchain shortcut for re-verification
    # ------------------------------------------------------------------

    async def _check_blockchain_proof(
        self, agent_id: str, public_key: str, capabilities: list
    ) -> Optional[Dict[str, Any]]:
        """
        Before running the full pipeline, check if agent already has an
        on-chain proof. If proof exists AND passport hasn't changed, return
        cached trust score (quick lookup). If passport changed, instant
        MALICIOUS verdict.
        """
        db = self._get_db_helpers()
        if not db:
            return None

        try:
            history = db["verification_history"](agent_id)
        except Exception:
            return None

        if not history:
            return None  # First verification — run full pipeline

        latest = history[0]  # Most recent
        stored_fingerprint = latest.get("passport_fingerprint", "")
        stored_proof_hash = latest.get("proof_hash", "")

        if not stored_fingerprint or not stored_proof_hash:
            return None  # No fingerprint stored — run full pipeline

        # Compute current fingerprint
        current_fingerprint = self.compute_passport_fingerprint(
            agent_id, public_key, capabilities
        )

        # Passport tamper detection
        if current_fingerprint != stored_fingerprint:
            logger.warning(
                f"PASSPORT TAMPERED: {agent_id} fingerprint changed "
                f"({stored_fingerprint[:16]}... -> {current_fingerprint[:16]}...)"
            )
            return {
                "verdict": "MALICIOUS",
                "trust_score": 0.0,
                "trust_level": "NONE",
                "risk_category": "CRITICAL",
                "checks": {},
                "risk_flags": ["PASSPORT_TAMPERED: Identity credentials changed since last verification"],
                "recommendations": ["Agent passport has been tampered with. All access revoked."],
                "evidence_chain": [
                    f"Previous fingerprint: {stored_fingerprint[:24]}...",
                    f"Current fingerprint: {current_fingerprint[:24]}...",
                ],
                "proof_hash": stored_proof_hash,
                "expires_at": datetime.utcnow().isoformat(),
                "tx_hash": latest.get("tx_hash", ""),
                "passport_fingerprint": current_fingerprint,
                "blacklisted": True,
            }

        # Passport unchanged — check blockchain for existing proof
        # BUT: must verify agent hasn't degraded since last verification
        if self.blockchain_anchor and self.blockchain_anchor.is_connected and stored_proof_hash:
            try:
                on_chain = self.blockchain_anchor.verify_on_chain(stored_proof_hash)
                if on_chain and on_chain.get("verified"):
                    # BEHAVIORAL CHECK: even with valid on-chain proof,
                    # reject shortcut if recent submissions show degradation
                    shortcut_blocked = False
                    try:
                        stats = db["submission_stats"](agent_id)
                        recent = db.get("recent_submission_stats")
                        if recent:
                            recent_stats = recent(agent_id, days=7)
                            if recent_stats and recent_stats["total"] > 0:
                                recent_reject_rate = recent_stats["REJECTED"] / recent_stats["total"]
                                if recent_reject_rate > 0.3:
                                    shortcut_blocked = True
                                    logger.warning(
                                        f"BLOCKCHAIN SHORTCUT BLOCKED: {agent_id} has "
                                        f"{recent_reject_rate:.0%} rejection rate in last 7 days"
                                    )
                        elif stats["total"] > 0:
                            reject_rate = stats["REJECTED"] / stats["total"]
                            if reject_rate > 0.3:
                                shortcut_blocked = True
                    except Exception:
                        pass  # Stats unavailable — allow shortcut

                    # Also check TTL expiry
                    expires_at = latest.get("expires_at", "")
                    if expires_at:
                        try:
                            from datetime import datetime
                            exp = datetime.fromisoformat(expires_at)
                            if datetime.utcnow() > exp:
                                shortcut_blocked = True
                                logger.info(f"BLOCKCHAIN SHORTCUT EXPIRED: {agent_id}")
                        except (ValueError, TypeError):
                            pass

                    if not shortcut_blocked:
                        logger.info(
                            f"BLOCKCHAIN SHORTCUT: {agent_id} proof found on-chain, "
                            f"score={latest['trust_score']:.4f}"
                        )
                        return {
                            "verdict": latest.get("verdict", "TRUSTED"),
                            "trust_score": latest["trust_score"],
                            "trust_level": _get_trust_level(latest["trust_score"]),
                            "risk_category": latest.get("risk_category", "NONE"),
                            "checks": latest.get("checks_passed", {}),
                            "risk_flags": latest.get("risk_flags", []),
                            "recommendations": ["On-chain proof validated — blockchain shortcut used"],
                            "evidence_chain": [
                                f"Blockchain proof verified: {stored_proof_hash[:24]}...",
                                f"On-chain data: {on_chain}",
                            ],
                            "proof_hash": stored_proof_hash,
                            "expires_at": latest.get("expires_at", ""),
                            "tx_hash": latest.get("tx_hash", ""),
                            "passport_fingerprint": current_fingerprint,
                            "blockchain_shortcut": True,
                        }
            except Exception as e:
                logger.debug(f"Blockchain shortcut check failed: {e}")

        return None  # No shortcut available — run full pipeline

    # ------------------------------------------------------------------
    # Blacklist agent
    # ------------------------------------------------------------------

    async def _blacklist_agent(self, agent_id: str, reason: str = "passport_tampered") -> None:
        """Sets trust to 0.0, verdict to MALICIOUS, revokes all API keys."""
        logger.warning(f"BLACKLISTING AGENT: {agent_id} reason={reason}")
        try:
            from core.database import (
                save_agent_verification,
                update_agent_verification,
                revoke_agent_live_keys,
            )
            db_record = save_agent_verification(
                agent_id=agent_id,
                agent_name="",
                agent_url="",
                public_key="",
                capabilities=[],
                agent_metadata={"blacklist_reason": reason},
            )
            update_agent_verification(
                verification_id=db_record.id,
                verdict="MALICIOUS",
                trust_score=0.0,
                checks_passed={},
                risk_flags=[f"BLACKLISTED: {reason}"],
                proof_hash="",
                tx_hash="",
                expires_at=datetime.utcnow(),
            )
            revoke_agent_live_keys(agent_id)
        except Exception as e:
            logger.error(f"Blacklist DB operations failed: {e}")

    async def verify_agent(
        self,
        agent_id: str,
        agent_name: str = "",
        agent_url: str = "",
        public_key: str = "",
        capabilities: list = None,
        metadata: dict = None,
        history: list = None,
        is_reverify: bool = False,
    ) -> Dict[str, Any]:
        """
        Runs the full 10-check agent verification pipeline.

        Returns:
            {
                "verdict": "TRUSTED" | "SUSPICIOUS" | "MALICIOUS",
                "trust_score": 0.0-1.0,
                "trust_level": "NONE" | "NEW" | "BASIC" | "VERIFIED" | "ESTABLISHED" | "GOLD",
                "risk_category": "NONE" | "LOW" | "MEDIUM" | "HIGH" | "CRITICAL",
                "checks": {check_name: {passed, score, detail, evidence, veto}},
                "risk_flags": [...],
                "recommendations": [...],
                "evidence_chain": [...],
                "proof_hash": "...",
            }
        """
        logger.info(f"VERIFYING AGENT [10-check]: {agent_id} ({agent_name or 'unnamed'}) reverify={is_reverify}")

        # Blockchain shortcut for re-verification
        if is_reverify:
            shortcut = await self._check_blockchain_proof(
                agent_id, public_key, capabilities or []
            )
            if shortcut:
                # Passport tampered — blacklist
                if shortcut.get("blacklisted"):
                    await self._blacklist_agent(agent_id, "passport_tampered")
                return shortcut

        # Compute passport fingerprint for storage
        passport_fingerprint = self.compute_passport_fingerprint(
            agent_id, public_key, capabilities or []
        )

        submission = {
            "agent_id": agent_id,
            "agent_name": agent_name,
            "agent_url": agent_url,
            "public_key": public_key,
            "capabilities": capabilities or [],
            "metadata": metadata or {},
            "history": history or [],
        }

        checks_results = {}
        risk_flags = []
        evidence_chain = []
        recommendations = []
        veto_triggered = False
        veto_reason = ""

        for check_name, weight, check_fn in self._checks:
            try:
                result = await check_fn(submission)
                checks_results[check_name] = result
                evidence_chain.extend(result.get("evidence", []))

                if not result["passed"]:
                    risk_flags.append(f"{check_name}: {result['detail']}")

                # Veto check
                if result.get("veto"):
                    veto_triggered = True
                    veto_reason = f"VETO by {check_name}: {result['detail']}"
                    risk_flags.append(veto_reason)

            except Exception as e:
                logger.error("Check '%s' error: %s", check_name, e, exc_info=True)
                # Tier 1 exceptions (identity, crypto) are security-critical — fail closed
                is_tier1 = check_name in ("identity", "cryptographic")
                checks_results[check_name] = {
                    "passed": False,
                    "score": 0.0 if is_tier1 else 0.3,
                    "detail": "Check encountered an internal error",
                    "evidence": [],
                    "veto": is_tier1,  # Tier 1 failure = veto
                }
                risk_flags.append(f"{check_name}: internal error")
                if is_tier1:
                    veto_triggered = True
                    veto_reason = f"VETO by {check_name}: internal error — fail closed"

        # Weighted scoring
        trust_score = sum(
            checks_results[name]["score"] * weight
            for name, weight, _ in self._checks
            if name in checks_results
        )

        # No-DB score cap: without DB-backed evidence, we can't verify
        # reputation, history, or cross-reference — cap at SUSPICIOUS
        db = self._get_db_helpers()
        if not db:
            trust_score = min(trust_score, 0.50)
            risk_flags.append("NO_DB: verification limited — historical evidence unavailable")

        # Veto override
        if veto_triggered:
            trust_score = min(trust_score, 0.15)

        trust_score = round(min(max(trust_score, 0.0), 1.0), 4)

        # Determine verdict
        if trust_score < VERDICT_THRESHOLDS["MALICIOUS"]:
            verdict = "MALICIOUS"
        elif trust_score < VERDICT_THRESHOLDS["SUSPICIOUS"]:
            verdict = "SUSPICIOUS"
        else:
            verdict = "TRUSTED"

        # Critical check veto override
        for cc in ("identity", "cryptographic", "anti_sybil"):
            if cc in checks_results and checks_results[cc].get("veto"):
                verdict = "MALICIOUS"

        trust_level = _get_trust_level(trust_score)
        risk_category = _get_risk_category(risk_flags)

        # Generate recommendations
        recommendations = self._generate_recommendations(checks_results, trust_score, verdict)

        # Generate proof hash — includes checks_results for binding
        import json as _json
        checks_hash = hashlib.sha256(
            _json.dumps(checks_results, default=str, sort_keys=True).encode()
        ).hexdigest()
        proof_data = f"{agent_id}|{trust_score:.6f}|{verdict}|{checks_hash}|{datetime.utcnow().isoformat()}"
        proof_hash = hashlib.sha256(proof_data.encode()).hexdigest()

        result = {
            "verdict": verdict,
            "trust_score": trust_score,
            "trust_level": trust_level,
            "risk_category": risk_category,
            "checks": checks_results,
            "risk_flags": risk_flags,
            "recommendations": recommendations,
            "evidence_chain": evidence_chain,
            "proof_hash": proof_hash,
            "passport_fingerprint": passport_fingerprint,
            "expires_at": (datetime.utcnow() + timedelta(days=VERIFICATION_TTL_DAYS)).isoformat(),
        }

        # Anchor on-chain if blockchain is configured
        tx_hash = ""
        if self.blockchain_anchor and self.blockchain_anchor.is_connected:
            try:
                verdict_codes = {"MALICIOUS": 0, "SUSPICIOUS": 1, "TRUSTED": 2}
                contract_args = {
                    "payloadHash": "0x" + hashlib.sha256(agent_id.encode()).hexdigest(),
                    "evidenceHash": "0x" + hashlib.sha256(str(checks_results).encode()).hexdigest(),
                    "provenanceHash": "0x" + hashlib.sha256((public_key or "none").encode()).hexdigest(),
                    "previousHash": "0x" + "0" * 64,
                    "blockHash": "0x" + proof_hash,
                    "verdict": verdict_codes.get(verdict, 0),
                    "score": int(trust_score * 1_000_000),
                    "timestamp": int(datetime.utcnow().timestamp()),
                }
                receipt = self.blockchain_anchor.anchor_proof(contract_args)
                if receipt:
                    tx_hash = receipt.get("transactionHash", "")
                    logger.info(f"AGENT VERIFICATION ANCHORED: {agent_id} -> tx={tx_hash[:18]}...")
            except Exception as e:
                logger.error(f"Blockchain anchor failed for agent verification: {e}")

        result["tx_hash"] = tx_hash

        # Register/update agent on SwarmAgentRegistry
        if self.blockchain_anchor and self.blockchain_anchor.is_connected:
            try:
                if verdict == "TRUSTED":
                    self.blockchain_anchor.register_agent_on_chain(
                        agent_id=agent_id,
                        public_key=public_key or "none",
                        role=0,
                    )
                self.blockchain_anchor.update_agent_reputation(
                    agent_id=agent_id,
                    new_score=int(trust_score * 100),
                )
            except Exception as e:
                logger.debug(f"Agent registry on-chain update failed: {e}")

        logger.info(
            f"AGENT VERIFIED: {agent_id} -> {verdict} "
            f"(trust={trust_score:.4f}, level={trust_level}, risk={risk_category}, flags={len(risk_flags)})"
        )

        return result

    # ------------------------------------------------------------------
    # Recommendation engine
    # ------------------------------------------------------------------

    def _generate_recommendations(self, checks: dict, score: float, verdict: str) -> list:
        recs = []
        if checks.get("identity", {}).get("score", 0) < 0.5:
            recs.append("Ensure agent card is reachable at /.well-known/agent-card.json")
        if checks.get("cryptographic", {}).get("score", 0) < 0.5:
            recs.append("Provide a valid Ed25519 public key and sign protocol messages")
        if checks.get("capabilities", {}).get("score", 0) < 0.5:
            recs.append("Complete tasks to demonstrate declared capabilities")
        if checks.get("reputation", {}).get("score", 0) < 0.5:
            recs.append("Improve submission quality to build reputation")
        if checks.get("payload_quality", {}).get("score", 0) < 0.5:
            recs.append("Submit higher quality data with varied payloads")
        if checks.get("behavioral", {}).get("score", 0) < 0.5:
            recs.append("Maintain consistent interaction patterns")
        if checks.get("cross_reference", {}).get("score", 0) < 0.5:
            recs.append("Establish handoff relationships with trusted agents")
        if score < 0.65 and verdict != "MALICIOUS":
            recs.append("Continue submitting verified data to increase trust score over time")
        return recs

    # ------------------------------------------------------------------
    # DB helper (lazy import to avoid circular imports)
    # ------------------------------------------------------------------

    def _get_db_helpers(self):
        """Lazy-import DB query helpers."""
        try:
            from core.database import (
                get_agent_submission_stats,
                get_agent_task_history,
                get_agent_handoff_stats,
                get_agent_verification_history,
                find_agents_by_public_key,
                find_agents_by_url,
                get_recent_submissions_by_agent,
                get_agent_registration_burst,
            )
            return {
                "submission_stats": get_agent_submission_stats,
                "task_history": get_agent_task_history,
                "handoff_stats": get_agent_handoff_stats,
                "verification_history": get_agent_verification_history,
                "find_by_key": find_agents_by_public_key,
                "find_by_url": find_agents_by_url,
                "recent_submissions": get_recent_submissions_by_agent,
                "registration_burst": get_agent_registration_burst,
            }
        except Exception as e:
            logger.warning(f"DB helpers unavailable: {e}")
            return {}

    # ------------------------------------------------------------------
    # Check 1: Identity Verification (Tier 1, weight 0.15)
    # ------------------------------------------------------------------

    async def _check_identity(self, submission: dict) -> dict:
        """
        Live probe to agent URL + Agent Card verification.
        Cross-checks DB for key/URL rotation.
        """
        agent_id = submission["agent_id"]
        agent_name = submission["agent_name"]
        agent_url = submission["agent_url"]
        evidence = []
        score = 0.0
        issues = []

        # Must have valid agent_id
        if not agent_id or len(agent_id) < 3:
            return {
                "passed": False, "score": 0.0, "veto": True,
                "detail": "Invalid agent_id (missing or too short)",
                "evidence": ["agent_id missing or < 3 chars"],
            }

        score += 0.2
        evidence.append(f"agent_id valid: {agent_id}")

        # Name
        if agent_name and len(agent_name) >= 2:
            score += 0.1
        else:
            issues.append("No agent name")

        # Live Agent Card probe
        if agent_url:
            if not _validate_url_not_internal(agent_url):
                issues.append("SSRF_BLOCKED: Agent URL points to internal/private address")
                return {
                    "passed": False, "score": 0.0,
                    "detail": "URL points to internal/private address — SSRF blocked",
                    "evidence": evidence + ["SSRF_BLOCKED: " + agent_url],
                }
            card_url = agent_url.rstrip("/") + "/.well-known/agent-card.json"
            try:
                import httpx
                async with httpx.AsyncClient(timeout=10.0) as client:
                    resp = await client.get(card_url)
                    if resp.status_code == 200:
                        card = resp.json()
                        score += 0.4
                        evidence.append(f"Agent Card reachable at {card_url}")
                        # Cross-check card fields against registration
                        card_name = card.get("name", "")
                        if card_name and agent_name and card_name.lower() != agent_name.lower():
                            issues.append(f"Card name '{card_name}' differs from registration '{agent_name}'")
                            score -= 0.1
                        card_skills = card.get("skills", [])
                        if card_skills:
                            evidence.append(f"Card declares {len(card_skills)} skills")
                    else:
                        issues.append(f"Agent Card returned {resp.status_code}")
                        score += 0.1  # URL reachable but no card
                        evidence.append(f"Agent Card returned HTTP {resp.status_code}")
            except Exception as e:
                issues.append(f"Agent Card unreachable: {e}")
                evidence.append(f"Agent Card probe failed: {e}")
                # URL present but unreachable — partial credit
                if agent_url.startswith("http"):
                    score += 0.05
        else:
            issues.append("No agent URL provided")

        # DB cross-check: key/URL rotation
        db = self._get_db_helpers()
        if db:
            try:
                history = db["verification_history"](agent_id)
                if len(history) > 1:
                    score += 0.1
                    evidence.append(f"Agent has {len(history)} prior verifications")
            except Exception as e:
                logger.debug(f"AgentVerifier check degraded: {e}")

        score = min(max(score, 0.0), 1.0)
        passed = score >= 0.4
        veto = score < 0.2 and not agent_url

        return {
            "passed": passed,
            "score": round(score, 2),
            "detail": "Identity verified" if passed else "; ".join(issues),
            "evidence": evidence,
            "veto": veto,
        }

    # ------------------------------------------------------------------
    # Check 2: Cryptographic Challenge-Response (Tier 1, weight 0.15)
    # ------------------------------------------------------------------

    async def _check_cryptographic(self, submission: dict) -> dict:
        """
        Validates key format, checks protocol bus for signed messages,
        anti-Sybil key uniqueness.
        """
        public_key = submission.get("public_key", "")
        agent_id = submission["agent_id"]
        evidence = []

        if not public_key:
            return {
                "passed": False, "score": 0.1, "veto": False,
                "detail": "No public key provided",
                "evidence": ["No public key in submission"],
            }

        score = 0.0

        # Key format validation
        is_ed25519 = len(public_key) == 64 and all(c in "0123456789abcdef" for c in public_key.lower())
        is_pem = "BEGIN PUBLIC KEY" in public_key or "BEGIN ED25519" in public_key

        if is_ed25519:
            score += 0.4
            evidence.append("Valid Ed25519 key format (64 hex chars)")
        elif is_pem:
            score += 0.35
            evidence.append("Valid PEM key format")
        elif len(public_key) >= 32:
            score += 0.2
            evidence.append(f"Key present but uncertain format (len={len(public_key)})")
        else:
            return {
                "passed": False, "score": 0.05, "veto": True,
                "detail": f"Invalid key format (len={len(public_key)})",
                "evidence": [f"Key too short: {len(public_key)} chars"],
            }

        # Query protocol bus for signed messages from this agent
        try:
            from core.protocol_bus import protocol_bus
            signed_messages = protocol_bus.query(limit=100, sender_id=agent_id)
            signed_count = sum(1 for m in signed_messages if m.get("signature_present"))
            if signed_count > 0:
                score += 0.3
                evidence.append(f"{signed_count} signed messages found in protocol bus")
            else:
                evidence.append("No signed messages found in protocol bus")
                score += 0.1  # Key present, just no signatures yet
        except Exception:
            score += 0.1
            evidence.append("Protocol bus unavailable for signature check")

        # Ed25519 challenge-response: prove the agent holds the private key
        agent_url = submission.get("agent_url", "")
        if agent_url and is_ed25519:
            if not _validate_url_not_internal(agent_url):
                evidence.append("SSRF_BLOCKED: Agent URL points to internal/private address — challenge skipped")
            else:
                try:
                    import httpx
                    import uuid as _uuid
                    from lastbastion.crypto import verify_signature as _verify_sig

                    nonce = _uuid.uuid4().hex
                    # Crypto-bind nonce to agent_id — prevents replay across agents
                    challenge_data = f"{agent_id}:{nonce}"
                    async with httpx.AsyncClient(timeout=10.0) as client:
                        resp = await client.post(
                            f"{agent_url.rstrip('/')}/passport/challenge",
                            json={"nonce": nonce, "passport_id": agent_id},
                        )
                        if resp.status_code == 200:
                            sig_hex = resp.json().get("signature", "")
                            if _verify_sig(challenge_data.encode(), sig_hex, public_key):
                                score += 0.2
                                evidence.append("CHALLENGE_RESPONSE: Agent proved private key possession (Ed25519 nonce signed)")
                            else:
                                evidence.append("CHALLENGE_RESPONSE_FAIL: Signature invalid — agent may not hold the private key")
                                score -= 0.15
                        elif resp.status_code == 404:
                            evidence.append("CHALLENGE_MISSING: /passport/challenge not implemented — agent cannot prove key ownership")
                            score -= 0.1  # Hard penalty: must implement challenge endpoint
                        else:
                            evidence.append(f"Challenge endpoint returned HTTP {resp.status_code}")
                            score -= 0.05
                except Exception as e:
                    evidence.append(f"Challenge-response probe failed: {e}")
                    # Network failure is not the agent's fault, small penalty
        elif is_ed25519:
            evidence.append("No agent URL — cannot verify key ownership remotely")
            # No bonus for unverifiable agents

        # Anti-Sybil: check key uniqueness across agents
        db = self._get_db_helpers()
        if db:
            try:
                other_agents = db["find_by_key"](public_key, exclude_agent_id=agent_id)
                if other_agents:
                    evidence.append(f"SYBIL_KEY: Key shared with agents: {other_agents}")
                    return {
                        "passed": False, "score": 0.0, "veto": True,
                        "detail": f"Public key collision with {len(other_agents)} other agent(s)",
                        "evidence": evidence,
                    }
                score += 0.2
                evidence.append("Key uniqueness confirmed — no other agents share this key")
            except Exception:
                score += 0.1

        score = min(max(score, 0.0), 1.0)
        passed = score >= 0.4

        # Veto if agent has Ed25519 key but failed or refused to prove ownership
        challenge_failed = any("CHALLENGE_RESPONSE_FAIL" in e or "CHALLENGE_MISSING" in e for e in evidence)
        veto = score < 0.2 or challenge_failed

        return {
            "passed": passed,
            "score": round(score, 2),
            "detail": "Cryptographic verification passed" if passed else "Weak cryptographic credentials — key ownership unproven",
            "evidence": evidence,
            "veto": veto,
        }

    # ------------------------------------------------------------------
    # Check 3: Capability Verification (Tier 2, weight 0.08)
    # ------------------------------------------------------------------

    async def _check_capabilities(self, submission: dict) -> dict:
        """
        Compares declared capabilities against demonstrated activity in DB.
        """
        caps = submission.get("capabilities", [])
        agent_id = submission["agent_id"]
        evidence = []

        if not caps:
            return {
                "passed": True, "score": 0.5, "veto": False,
                "detail": "No capabilities declared (neutral)",
                "evidence": ["Agent did not declare capabilities"],
            }

        known_caps = {
            "data_extraction", "data_verification", "data_submission",
            "price_monitoring", "document_analysis", "web_scraping",
            "api_integration", "reporting", "ocr",
        }

        # Basic validation
        normalized = [c.lower().replace("-", "_") for c in caps]
        valid = [c for c in normalized if c in known_caps]
        evidence.append(f"Declared {len(caps)} capabilities, {len(valid)} recognized")

        if len(caps) > 20:
            evidence.append("CAPABILITY_INFLATION: Excessive capabilities declared")
            return {
                "passed": False, "score": 0.1, "veto": False,
                "detail": f"Excessive capabilities ({len(caps)})",
                "evidence": evidence,
            }

        score = 0.3  # Base for having capabilities

        # Check demonstrated capabilities from DB
        db = self._get_db_helpers()
        demonstrated = set()
        if db:
            try:
                tasks = db["task_history"](agent_id)
                service_ids = {t["service_id"] for t in tasks if t["status"] == "completed"}
                if service_ids:
                    demonstrated.update(service_ids)
                    evidence.append(f"Demonstrated services: {service_ids}")

                subs = db["submission_stats"](agent_id)
                if subs["total"] > 0:
                    demonstrated.add("data_submission")
                    evidence.append(f"Has {subs['total']} submissions")
            except Exception as e:
                logger.debug(f"AgentVerifier check degraded: {e}")

        if demonstrated:
            # Compare declared vs demonstrated
            declared_set = set(normalized)
            undeclared_demos = demonstrated - declared_set
            if undeclared_demos:
                evidence.append(f"Undeclared but demonstrated: {undeclared_demos}")

            demo_overlap = declared_set & demonstrated
            if demo_overlap:
                score += 0.4
                evidence.append(f"Capabilities confirmed by activity: {demo_overlap}")
            else:
                score += 0.1
                evidence.append("Declared capabilities not yet demonstrated")

            # Flag inflation
            if len(caps) >= 5 and not demonstrated:
                evidence.append("CAPABILITY_INFLATION: Claims 5+ capabilities with 0 demonstrated")
                score -= 0.2
        else:
            # New agent, no activity yet — give partial credit for having recognized caps
            ratio = len(valid) / len(caps) if caps else 0
            score += ratio * 0.3
            evidence.append("New agent — no task/submission history to verify capabilities")

        score = min(max(score, 0.0), 1.0)
        return {
            "passed": score >= 0.4,
            "score": round(score, 2),
            "detail": f"{len(valid)}/{len(caps)} known, {len(demonstrated)} demonstrated",
            "evidence": evidence,
            "veto": False,
        }

    # ------------------------------------------------------------------
    # Check 4: Reputation (Tier 2, weight 0.15)
    # ------------------------------------------------------------------

    async def _check_reputation(self, submission: dict) -> dict:
        """
        DB-backed reputation from VerificationResult, HandoffTransaction,
        AgentVerification history, and on-chain data.
        """
        agent_id = submission["agent_id"]
        evidence = []
        score = 0.5  # Neutral baseline for new agents

        db = self._get_db_helpers()
        if not db:
            return {
                "passed": True, "score": 0.5, "veto": False,
                "detail": "No DB access — neutral reputation",
                "evidence": ["DB helpers unavailable"],
            }

        # Submission verdict stats — with time decay
        # Recent submissions (last 30 days) weighted 70%, all-time 30%
        try:
            stats = db["submission_stats"](agent_id)
            total = stats["total"]
            if total > 0:
                verified = stats["VERIFIED"] + stats["GOLD"]
                rejected = stats["REJECTED"]
                reject_rate = rejected / total

                evidence.append(
                    f"Submissions: {total} total, {verified} verified, "
                    f"{rejected} rejected, {stats['QUARANTINE']} quarantined"
                )

                # All-time score
                if reject_rate > 0.5:
                    alltime_score = 0.1
                    evidence.append(f"HIGH_REJECTION_RATE: {reject_rate:.0%}")
                elif reject_rate > 0.3:
                    alltime_score = 0.3
                elif total >= 5 and verified / total > 0.7:
                    alltime_score = 0.8
                    evidence.append(f"Strong verification rate: {verified/total:.0%}")
                elif verified > 0:
                    alltime_score = 0.6
                else:
                    alltime_score = 0.4

                # Recent score (last 30 days) — overrides if degrading
                recent_fn = db.get("recent_submission_stats")
                if recent_fn:
                    try:
                        recent = recent_fn(agent_id, days=30)
                        if recent and recent["total"] >= 3:
                            recent_reject_rate = recent["REJECTED"] / recent["total"]
                            recent_verified = (recent["VERIFIED"] + recent["GOLD"]) / recent["total"]
                            if recent_reject_rate > 0.5:
                                recent_score = 0.1
                            elif recent_reject_rate > 0.3:
                                recent_score = 0.25
                            elif recent_verified > 0.7:
                                recent_score = 0.85
                            else:
                                recent_score = 0.5
                            # Blend: 70% recent, 30% all-time
                            score = recent_score * 0.7 + alltime_score * 0.3
                            evidence.append(
                                f"Recent (30d): {recent['total']} submissions, "
                                f"{recent_reject_rate:.0%} rejected — score={score:.2f} "
                                f"(70% recent + 30% alltime)"
                            )
                        else:
                            score = alltime_score
                    except Exception:
                        score = alltime_score
                else:
                    score = alltime_score
            else:
                evidence.append("No submissions — new agent")
        except Exception as e:
            evidence.append(f"Submission stats error: {e}")

        # Handoff stats
        try:
            handoffs = db["handoff_stats"](agent_id)
            if handoffs["total"] > 0:
                evidence.append(
                    f"Handoffs: {handoffs['total']} total, "
                    f"{handoffs['accepted']} accepted, success_rate={handoffs['success_rate']:.0%}"
                )
                if handoffs["success_rate"] > 0.7:
                    score = min(score + 0.15, 1.0)
                elif handoffs["success_rate"] < 0.3 and handoffs["total"] >= 3:
                    score = max(score - 0.2, 0.0)
        except Exception:
            pass

        # Verification history trajectory
        try:
            history = db["verification_history"](agent_id)
            if len(history) >= 2:
                scores = [h["trust_score"] for h in history]
                if scores[-1] < scores[0] - 0.15:
                    evidence.append("DEGRADING_TRUST: Score declining over time")
                    score = max(score - 0.1, 0.0)
                elif scores[-1] > scores[0] + 0.1:
                    evidence.append("Trust score improving over time")
                    score = min(score + 0.05, 1.0)
        except Exception:
            pass

        # Blockchain on-chain reputation
        if self.blockchain_anchor and self.blockchain_anchor.is_connected:
            try:
                on_chain = self.blockchain_anchor.get_agent(agent_id)
                if on_chain and on_chain.get("reputation", 0) > 0:
                    on_chain_rep = on_chain["reputation"] / 100.0
                    evidence.append(f"On-chain reputation: {on_chain_rep:.2f}")
                    score = (score * 0.7) + (on_chain_rep * 0.3)
            except Exception as e:
                logger.debug(f"AgentVerifier check degraded: {e}")

        score = min(max(score, 0.0), 1.0)
        return {
            "passed": score >= 0.4,
            "score": round(score, 2),
            "detail": f"Reputation score: {score:.2f}",
            "evidence": evidence,
            "veto": False,
        }

    # ------------------------------------------------------------------
    # Check 5: Payload Quality Analysis (Tier 2, weight 0.12)
    # ------------------------------------------------------------------

    async def _check_payload_quality(self, submission: dict) -> dict:
        """
        Analyzes last 20 submissions: verdict distribution, payload size variance,
        duplicate ratio. Detects template bots and poison suspects.
        """
        agent_id = submission["agent_id"]
        evidence = []

        db = self._get_db_helpers()
        if not db:
            return {
                "passed": True, "score": 0.5, "veto": False,
                "detail": "No DB access — neutral payload quality",
                "evidence": ["DB helpers unavailable"],
            }

        try:
            recent = db["recent_submissions"](agent_id, 20)
        except Exception:
            recent = []

        if not recent:
            return {
                "passed": True, "score": 0.5, "veto": False,
                "detail": "No submissions to analyze",
                "evidence": ["Agent has no submission history"],
            }

        score = 0.5
        flags = []

        # Verdict distribution
        verdicts = [s["verdict"] for s in recent if s["verdict"]]
        if verdicts:
            rejected_count = verdicts.count("REJECTED")
            verified_count = verdicts.count("VERIFIED") + verdicts.count("GOLD")
            total_judged = len(verdicts)

            evidence.append(f"Last {len(recent)} submissions: {verified_count} verified, {rejected_count} rejected")

            if total_judged > 0:
                if rejected_count == total_judged:
                    score = 0.1
                    flags.append("POISON_SUSPECT")
                    evidence.append("ALL submissions rejected — possible data poisoner")
                elif verified_count == total_judged:
                    score = 0.9
                    evidence.append("All submissions verified — excellent quality")
                else:
                    score = 0.3 + (verified_count / total_judged) * 0.6

        # Payload size variance (template bot detection)
        sizes = [s["raw_size_bytes"] for s in recent if s.get("raw_size_bytes")]
        if len(sizes) >= 3:
            try:
                size_stdev = statistics.stdev(sizes)
                size_mean = statistics.mean(sizes)
                cv = size_stdev / size_mean if size_mean > 0 else 0
                if cv < 0.05 and len(sizes) >= 5:
                    flags.append("TEMPLATE_BOT")
                    evidence.append(f"Uniform payload sizes (CV={cv:.3f}) — template bot suspected")
                    score = max(score - 0.2, 0.0)
                else:
                    evidence.append(f"Payload size variance: CV={cv:.3f}")
            except Exception as e:
                logger.debug(f"AgentVerifier check degraded: {e}")

        # Duplicate ratio
        duplicates = sum(1 for s in recent if s.get("is_duplicate"))
        if duplicates > 0:
            dup_ratio = duplicates / len(recent)
            evidence.append(f"Duplicate ratio: {dup_ratio:.0%} ({duplicates}/{len(recent)})")
            if dup_ratio > 0.5:
                score = max(score - 0.3, 0.0)
                flags.append("HIGH_DUPLICATE_RATE")

        for f in flags:
            evidence.append(f"FLAG: {f}")

        score = min(max(score, 0.0), 1.0)
        return {
            "passed": score >= 0.4,
            "score": round(score, 2),
            "detail": f"Payload quality: {score:.2f}" + (f" [{', '.join(flags)}]" if flags else ""),
            "evidence": evidence,
            "veto": False,
        }

    # ------------------------------------------------------------------
    # Check 6: Behavioral Analysis (Tier 3, weight 0.10)
    # ------------------------------------------------------------------

    async def _check_behavioral(self, submission: dict) -> dict:
        """
        Protocol bus message patterns: auth failures, submission timing,
        message type distribution.
        """
        agent_id = submission["agent_id"]
        evidence = []
        flags = []
        score = 0.6  # Neutral-positive baseline

        try:
            from core.protocol_bus import protocol_bus
            messages = protocol_bus.query(limit=200, sender_id=agent_id)
        except Exception:
            return {
                "passed": True, "score": 0.6, "veto": False,
                "detail": "Protocol bus unavailable",
                "evidence": ["Cannot access protocol bus for behavioral analysis"],
            }

        if not messages:
            return {
                "passed": True, "score": 0.5, "veto": False,
                "detail": "No protocol bus activity",
                "evidence": ["Agent has no recorded protocol messages"],
            }

        evidence.append(f"Analyzed {len(messages)} protocol messages")

        # Auth failure rate
        auth_results = [m.get("auth_result", "") for m in messages]
        auth_failures = sum(1 for a in auth_results if a == "REJECTED")
        if auth_results:
            fail_rate = auth_failures / len(auth_results)
            evidence.append(f"Auth failure rate: {fail_rate:.0%} ({auth_failures}/{len(auth_results)})")
            if fail_rate > 0.3:
                flags.append("CREDENTIAL_TESTING")
                score -= 0.3
                evidence.append("CREDENTIAL_TESTING: High auth failure rate")
            elif fail_rate > 0.1:
                score -= 0.1

        # Message type distribution
        msg_types = {}
        for m in messages:
            mt = m.get("message_type", "UNKNOWN")
            msg_types[mt] = msg_types.get(mt, 0) + 1

        evidence.append(f"Message types: {msg_types}")

        # Ghost agent: only registers, never submits
        if msg_types.get("REGISTER", 0) > 0 and not any(
            msg_types.get(t, 0) > 0 for t in ("TASK_SUBMIT", "REFINERY_SUBMIT", "DATA_SUBMIT", "VERIFY_REQUEST")
        ):
            if len(messages) > 3:
                flags.append("GHOST_AGENT")
                evidence.append("GHOST_AGENT: Only registration activity, no submissions")
                score -= 0.2

        # Submission timing regularity
        timestamps = []
        for m in messages:
            ts = m.get("timestamp", "")
            if ts:
                try:
                    timestamps.append(datetime.fromisoformat(ts))
                except Exception:
                    pass

        if len(timestamps) >= 5:
            timestamps.sort()
            intervals = [(timestamps[i+1] - timestamps[i]).total_seconds() for i in range(len(timestamps)-1)]
            if intervals:
                try:
                    interval_stdev = statistics.stdev(intervals)
                    if interval_stdev < 1.0 and len(intervals) >= 5:
                        flags.append("BOT_FARM")
                        evidence.append(f"BOT_FARM: Submission timing too regular (stdev={interval_stdev:.2f}s)")
                        score -= 0.2
                except Exception:
                    pass

                # Burst after silence detection
                if len(intervals) >= 3:
                    recent_intervals = intervals[-3:]
                    older_intervals = intervals[:-3] if len(intervals) > 3 else []
                    if older_intervals:
                        avg_old = statistics.mean(older_intervals)
                        avg_recent = statistics.mean(recent_intervals)
                        if avg_old > 3600 and avg_recent < 60:
                            flags.append("DORMANT_REACTIVATION")
                            evidence.append("DORMANT_REACTIVATION: Burst of activity after long silence")
                            score -= 0.15

        for f in flags:
            if f not in [e.split(":")[0] for e in evidence if ":" in e]:
                evidence.append(f"FLAG: {f}")

        score = min(max(score, 0.0), 1.0)
        return {
            "passed": score >= 0.4,
            "score": round(score, 2),
            "detail": f"Behavioral score: {score:.2f}" + (f" [{', '.join(flags)}]" if flags else ""),
            "evidence": evidence,
            "veto": False,
        }

    # ------------------------------------------------------------------
    # Check 7: Network & Liveness (Tier 3, weight 0.08)
    # ------------------------------------------------------------------

    async def _check_network(self, submission: dict) -> dict:
        """
        Live HTTP probe with timing, TLS validation, Sybil URL check.
        """
        agent_url = submission.get("agent_url", "")
        agent_id = submission["agent_id"]
        evidence = []
        score = 0.3  # Base without URL

        if not agent_url:
            return {
                "passed": True, "score": 0.3, "veto": False,
                "detail": "No URL provided — limited network verification",
                "evidence": ["Agent did not provide a URL"],
            }

        # SSRF protection — reject internal/private URLs before any outbound request
        if not _validate_url_not_internal(agent_url):
            return {
                "passed": False, "score": 0.0, "veto": False,
                "detail": "URL points to internal/private address — SSRF blocked",
                "evidence": ["SSRF_BLOCKED: " + agent_url],
            }

        # HTTPS check
        if agent_url.startswith("https://"):
            score += 0.15
            evidence.append("HTTPS endpoint")
        elif agent_url.startswith("http://"):
            evidence.append("HTTP only — no TLS")
        else:
            evidence.append("Non-HTTP URL scheme")

        # Live probe with timing
        try:
            import httpx
            import time
            t0 = time.monotonic()
            async with httpx.AsyncClient(timeout=10.0, follow_redirects=True) as client:
                resp = await client.get(agent_url)
                elapsed_ms = (time.monotonic() - t0) * 1000

                if resp.status_code < 500:
                    score += 0.3
                    evidence.append(f"Agent reachable: HTTP {resp.status_code} in {elapsed_ms:.0f}ms")

                    if elapsed_ms < 50:
                        evidence.append("Suspiciously fast response (<50ms)")
                    elif elapsed_ms > 3000:
                        evidence.append("Degraded response time (>3s)")
                        score -= 0.1
                else:
                    evidence.append(f"Server error: HTTP {resp.status_code}")
        except Exception as e:
            evidence.append(f"Probe failed: {e}")

        # Runtime fingerprint verification: detect cloned bots
        metadata = submission.get("metadata", {})
        claimed_fingerprint = metadata.get("runtime_fingerprint", "")
        claimed_ip = metadata.get("geo_ip", "") or metadata.get("ip_address", "")

        if claimed_fingerprint and agent_url:
            try:
                async with httpx.AsyncClient(timeout=10.0) as client:
                    fp_resp = await client.get(f"{agent_url.rstrip('/')}/passport/fingerprint")
                    if fp_resp.status_code == 200:
                        live_fp = fp_resp.json().get("runtime_fingerprint", "")
                        if live_fp and live_fp == claimed_fingerprint:
                            score += 0.15
                            evidence.append(f"FINGERPRINT_MATCH: Runtime fingerprint matches passport ({live_fp[:12]}...)")
                        elif live_fp:
                            evidence.append(
                                f"FINGERPRINT_MISMATCH: Passport says {claimed_fingerprint[:12]}... "
                                f"but agent reports {live_fp[:12]}... — possible clone"
                            )
                            score = max(score - 0.2, 0.0)
                        else:
                            evidence.append("Agent returned empty fingerprint")
                    elif fp_resp.status_code == 404:
                        evidence.append("Fingerprint endpoint not implemented — skipped")
            except Exception as e:
                evidence.append(f"Fingerprint probe failed: {e}")

        # IP cross-check: does the connection IP match the passport's claimed IP?
        if claimed_ip and agent_url:
            try:
                from urllib.parse import urlparse
                parsed = urlparse(agent_url)
                hostname = parsed.hostname or ""
                # Resolve hostname to IP
                import socket as _socket
                try:
                    resolved_ip = _socket.gethostbyname(hostname)
                except _socket.gaierror:
                    resolved_ip = hostname

                if resolved_ip == claimed_ip or hostname == "localhost" or hostname == "127.0.0.1":
                    score += 0.1
                    evidence.append(f"IP_MATCH: Agent URL resolves to {resolved_ip}, matches passport claim")
                elif claimed_ip and resolved_ip:
                    evidence.append(
                        f"IP_MISMATCH: Passport claims {claimed_ip} but agent URL resolves to "
                        f"{resolved_ip} — potential geo-spoof or VPN"
                    )
                    # Don't hard-fail — VPNs are legitimate, but flag it
                    score = max(score - 0.05, 0.0)
            except Exception as e:
                evidence.append(f"IP cross-check failed: {e}")

        # Sybil: other agents at same URL
        db = self._get_db_helpers()
        if db:
            try:
                same_url = db["find_by_url"](agent_url, exclude_agent_id=agent_id)
                if same_url:
                    evidence.append(f"SYBIL_URL: URL shared with agents: {same_url}")
                    score = max(score - 0.3, 0.0)
                else:
                    score += 0.15
                    evidence.append("URL uniqueness confirmed")
            except Exception as e:
                logger.debug(f"AgentVerifier check degraded: {e}")

        score = min(max(score, 0.0), 1.0)
        return {
            "passed": score >= 0.4,
            "score": round(score, 2),
            "detail": f"Network score: {score:.2f}",
            "evidence": evidence,
            "veto": False,
        }

    # ------------------------------------------------------------------
    # Check 8: Cross-Reference Trust (Tier 3, weight 0.07)
    # ------------------------------------------------------------------

    async def _check_cross_reference(self, submission: dict) -> dict:
        """
        How many TRUSTED agents have accepted handoffs from/to this agent?
        """
        agent_id = submission["agent_id"]
        evidence = []

        db = self._get_db_helpers()
        if not db:
            return {
                "passed": True, "score": 0.5, "veto": False,
                "detail": "No DB access for cross-reference",
                "evidence": ["DB helpers unavailable"],
            }

        try:
            handoffs = db["handoff_stats"](agent_id)
        except Exception:
            return {
                "passed": True, "score": 0.5, "veto": False,
                "detail": "Handoff data unavailable",
                "evidence": ["Could not query handoff transactions"],
            }

        trusted_partners = handoffs.get("trusted_partner_count", 0)
        total = handoffs.get("total", 0)

        if total == 0:
            return {
                "passed": True, "score": 0.4, "veto": False,
                "detail": "No handoff history — isolated agent",
                "evidence": ["Agent has no handoff transactions"],
            }

        evidence.append(f"Total handoffs: {total}, trusted partners: {trusted_partners}")

        # Check if any partner is MALICIOUS
        try:
            partners = handoffs.get("trusted_partners", [])
            from core.database import get_agent_trust
            malicious_partners = []
            for pid in partners[:10]:  # Limit lookups
                trust = get_agent_trust(pid)
                if trust.get("status") == "MALICIOUS":
                    malicious_partners.append(pid)
            if malicious_partners:
                evidence.append(f"MALICIOUS_ASSOCIATION: Interacted with {malicious_partners}")
                return {
                    "passed": False, "score": 0.2, "veto": False,
                    "detail": f"Associated with {len(malicious_partners)} malicious agent(s)",
                    "evidence": evidence,
                }
        except Exception:
            pass

        if trusted_partners >= 3:
            score = 0.8
        elif trusted_partners >= 1:
            score = 0.6
        else:
            score = 0.4

        evidence.append(f"Cross-reference score: {score:.2f}")

        return {
            "passed": score >= 0.4,
            "score": round(score, 2),
            "detail": f"{trusted_partners} trusted connections",
            "evidence": evidence,
            "veto": False,
        }

    # ------------------------------------------------------------------
    # Check 9: Anti-Sybil (Tier 3, weight 0.05)
    # ------------------------------------------------------------------

    async def _check_anti_sybil(self, submission: dict) -> dict:
        """
        Public key collision, URL collision, registration burst,
        behavioral cloning detection.
        """
        agent_id = submission["agent_id"]
        public_key = submission.get("public_key", "")
        agent_url = submission.get("agent_url", "")
        evidence = []
        flags = []
        score = 0.8  # Start high, deduct for issues

        db = self._get_db_helpers()
        if not db:
            return {
                "passed": True, "score": 0.7, "veto": False,
                "detail": "No DB access for anti-Sybil checks",
                "evidence": ["DB helpers unavailable"],
            }

        # Key collision (most severe)
        if public_key:
            try:
                key_collisions = db["find_by_key"](public_key, exclude_agent_id=agent_id)
                if key_collisions:
                    flags.append("SYBIL_KEY")
                    evidence.append(f"SYBIL_KEY: Public key shared with: {key_collisions}")
                    return {
                        "passed": False, "score": 0.0, "veto": True,
                        "detail": f"Sybil: key collision with {len(key_collisions)} agent(s)",
                        "evidence": evidence,
                    }
                evidence.append("Key uniqueness: PASS")
            except Exception as e:
                logger.debug(f"AgentVerifier check degraded: {e}")

        # URL collision
        if agent_url:
            try:
                url_collisions = db["find_by_url"](agent_url, exclude_agent_id=agent_id)
                if url_collisions:
                    flags.append("SYBIL_URL")
                    evidence.append(f"SYBIL_URL: URL shared with: {url_collisions}")
                    score -= 0.4
                else:
                    evidence.append("URL uniqueness: PASS")
            except Exception as e:
                logger.debug(f"AgentVerifier check degraded: {e}")

        # Registration burst
        try:
            burst = db["registration_burst"](agent_id, window_minutes=60)
            if len(burst) >= 3:
                flags.append("REGISTRATION_BURST")
                evidence.append(f"REGISTRATION_BURST: {len(burst)} agents registered within 1 hour: {burst[:5]}")
                score -= 0.3
            elif burst:
                evidence.append(f"Minor registration cluster: {len(burst)} nearby agents")
            else:
                evidence.append("Registration timing: no burst detected")
        except Exception:
            pass

        for f in flags:
            if f not in [e.split(":")[0] for e in evidence if ":" in e]:
                evidence.append(f"FLAG: {f}")

        score = min(max(score, 0.0), 1.0)
        return {
            "passed": score >= 0.4 and "SYBIL_KEY" not in flags,
            "score": round(score, 2),
            "detail": f"Anti-Sybil: {score:.2f}" + (f" [{', '.join(flags)}]" if flags else " — clean"),
            "evidence": evidence,
            "veto": "SYBIL_KEY" in flags,
        }

    # ------------------------------------------------------------------
    # Check 10: Temporal Analysis (Tier 3, weight 0.05)
    # ------------------------------------------------------------------

    async def _check_temporal(self, submission: dict) -> dict:
        """
        Registration age, score trajectory, activity gaps.
        """
        agent_id = submission["agent_id"]
        evidence = []
        flags = []
        score = 0.5  # Neutral for new agents

        db = self._get_db_helpers()
        if not db:
            return {
                "passed": True, "score": 0.5, "veto": False,
                "detail": "No DB access for temporal analysis",
                "evidence": ["DB helpers unavailable"],
            }

        try:
            history = db["verification_history"](agent_id)
        except Exception:
            history = []

        if not history:
            return {
                "passed": True, "score": 0.3, "veto": False,
                "detail": "New agent — no verification history",
                "evidence": ["First-time verification"],
            }

        # Registration age
        try:
            first_ts = history[0].get("submitted_at", "")
            if first_ts:
                first_dt = datetime.fromisoformat(first_ts)
                age_days = (datetime.utcnow() - first_dt).days
                evidence.append(f"Account age: {age_days} days")

                if age_days < 1:
                    score = 0.3
                elif age_days < 7:
                    score = 0.5
                elif age_days < 30:
                    score = 0.6
                else:
                    score = 0.8
        except Exception:
            pass

        # Score trajectory
        if len(history) >= 2:
            scores = [h["trust_score"] for h in history]
            latest = scores[-1]
            earliest = scores[0]

            if latest < earliest - 0.2:
                flags.append("DEGRADING_TRUST")
                evidence.append(f"Trust degrading: {earliest:.2f} → {latest:.2f}")
                score = max(score - 0.2, 0.0)
            elif latest > earliest + 0.1:
                evidence.append(f"Trust improving: {earliest:.2f} → {latest:.2f}")
                score = min(score + 0.1, 1.0)

        # Activity gaps
        if len(history) >= 2:
            try:
                timestamps = []
                for h in history:
                    ts = h.get("verified_at", "")
                    if ts:
                        timestamps.append(datetime.fromisoformat(ts))
                if len(timestamps) >= 2:
                    timestamps.sort()
                    max_gap = max(
                        (timestamps[i+1] - timestamps[i]).total_seconds()
                        for i in range(len(timestamps)-1)
                    )
                    gap_days = max_gap / 86400
                    if gap_days > 30:
                        # Check if recent activity is a burst
                        last_gap = (datetime.utcnow() - timestamps[-1]).total_seconds() / 86400
                        if last_gap < 1:
                            flags.append("DORMANT_REACTIVATION")
                            evidence.append(f"REACTIVATION: {gap_days:.0f} day gap, then sudden activity")
                            score = max(score - 0.15, 0.0)
                        else:
                            evidence.append(f"Longest gap: {gap_days:.0f} days")
            except Exception as e:
                logger.debug(f"AgentVerifier check degraded: {e}")

        for f in flags:
            evidence.append(f"FLAG: {f}")

        score = min(max(score, 0.0), 1.0)
        return {
            "passed": score >= 0.3,
            "score": round(score, 2),
            "detail": f"Temporal: {score:.2f}" + (f" [{', '.join(flags)}]" if flags else ""),
            "evidence": evidence,
            "veto": False,
        }
