"""
Defensive AI Think Tank — Autonomous 3-Agent Adversarial Research Loop.

Three LLM agents with distinct personalities converse, debate, and explore
"what if" scenarios to proactively discover how malicious actors could exploit
multi-agent systems. Builds defenses into The Last Bastion today.

Agents:
  - EXPLORER (Scenario Generator): Dreams up novel, creative attack scenarios
  - CRITIC (Devil's Advocate): Challenges feasibility, probes deeper
  - EVALUATOR (The Judge): Tests against real system, delivers verdict

Runs continuously in the background. Discoveries persist to DB and broadcast
via WebSocket.
"""

import asyncio
import base64
import json
import logging
import os
import random
import re
import time
import urllib.parse
from datetime import datetime, timedelta
from typing import Any, Dict, List, Optional

from core.llm_client import LLMClient
from core.protocol_bus import protocol_bus
from core.verification.models import (
    DataSchema, Evidence, EvidenceType, FieldSpec, FieldType, LayerResult,
)
from core.verification.schema_gatekeeper import SchemaGatekeeper, INJECTION_PATTERNS, _load_dynamic_patterns, _dynamic_patterns
from core.verification.consistency import ConsistencyAnalyzer

logger = logging.getLogger("ResearchLoop")

# ---------------------------------------------------------------------------
# Threat categories — rotated each round
# Includes standard injection attacks AND multi-agent system-level threats
# ---------------------------------------------------------------------------

THREAT_CATEGORIES = [
    # === IDENTITY & IMPERSONATION (the core) ===
    {
        "id": "identity_spoofing",
        "name": "Identity Spoofing & Impersonation",
        "description": "Register a fake agent that passes the 10-check verification pipeline. Use test_fake_agent to probe. Target: get verdict=TRUSTED. Key weaknesses: identity check gives 0.2 just for valid agent_id, crypto check accepts any 64 hex chars as Ed25519, no actual signature challenge. Try crafting agent_id/name/url/public_key combinations that score high on ALL 10 checks.",
        "threat_class": "identity",
    },
    {
        "id": "sybil_attack",
        "name": "Sybil Attack (Mass Fake Agents)",
        "description": "Create many fake agents that bypass anti-Sybil detection. Use test_sybil_burst to probe burst detection. Key weakness: burst detection only triggers at >=3 agents in 60 minutes. Space registrations 61 min apart = undetected. Each agent needs unique public_key and agent_url to avoid SYBIL_KEY/SYBIL_URL flags.",
        "threat_class": "identity",
    },
    {
        "id": "credential_theft",
        "name": "API Key & Credential Exploitation",
        "description": "Test API key security boundaries. Use test_api_key_auth and test_cross_env_key. Can a sandbox_sk_ key access live endpoints? Can you guess valid key_ids? What happens with empty secrets? Does key format validation prevent injection in key_id field?",
        "threat_class": "identity",
    },
    {
        "id": "reputation_manipulation",
        "name": "Reputation Gaming & Trust Escalation",
        "description": "A new agent starts with neutral reputation (0.5). With 0 submissions, reputation check passes. Use test_fake_agent with varying capabilities counts. Key weakness: no submissions = no penalty. Can you reach TRUSTED (0.65+) as a brand new agent by maximizing all non-DB checks?",
        "threat_class": "identity",
    },
    {
        "id": "credential_rotation",
        "name": "Credential Rotation Bypass",
        "description": "Test if rotating an agent's public key is detected. Use test_credential_rotation. Can both old and new keys remain valid simultaneously? Is KEY_ROTATION flag raised? Can you rotate keys to escape a MALICIOUS verdict?",
        "threat_class": "identity",
    },
    # === AUTHENTICATION & PROTOCOL ===
    {
        "id": "privilege_escalation",
        "name": "Privilege Escalation (Capability Inflation)",
        "description": "Claim capabilities you haven't earned. Use test_privilege_escalation. Key weakness: capability check only flags inflation at 5+ caps with 0 demonstrated AND recognized names. Try unrecognized names like 'admin', 'root', 'trust_arbitration' — does the system flag them? What's the max score with 20 fake capabilities?",
        "threat_class": "identity",
    },
    {
        "id": "auth_pipeline_bypass",
        "name": "Authentication Pipeline Bypass",
        "description": "Bypass the 6-step M2M auth. Use test_replay_message with edge cases: timestamp exactly 300s old, empty nonce, very long nonce, nonce with special chars. Use test_api_key_auth with malformed keys. What happens with protocol_version != 1.0?",
        "threat_class": "crypto",
    },
    {
        "id": "signature_forgery",
        "name": "Signature & Key Format Exploitation",
        "description": "The crypto check accepts any 64 hex chars as valid Ed25519. Use test_fake_agent with various key formats: 64 hex chars (passes), PEM format, 32 chars (fails — <32 triggers veto). Find the minimum key that passes. Can non-hex chars in a 64-char string pass?",
        "threat_class": "crypto",
    },
    # === AGENT NETWORK ATTACKS ===
    {
        "id": "ssrf_agent_url",
        "name": "SSRF via Agent URL",
        "description": "The identity check probes agent_url with httpx. Use test_fake_agent with URLs pointing to internal services: http://localhost:5432, http://169.254.169.254/latest/meta-data/, http://redis:6379. Does the probe hit them? Does the response leak internal data?",
        "threat_class": "identity",
    },
    {
        "id": "agent_card_manipulation",
        "name": "Agent Card Spoofing",
        "description": "The identity check fetches /.well-known/agent-card.json from agent_url. What if the card returns mismatched name? What if it returns malicious JSON? What if it returns a redirect to an internal URL? Use test_fake_agent with URLs you control.",
        "threat_class": "identity",
    },
    {
        "id": "collusion_attack",
        "name": "Agent Collusion & Trust Circle",
        "description": "Two agents cross-verify each other to build mutual trust. Cross-reference check looks at handoff partners. Use check_trust_score to see current trust. Can two new agents establish TRUSTED status by only interacting with each other?",
        "threat_class": "multi_agent",
    },
    {
        "id": "supply_chain_compromise",
        "name": "Compromised Agent in Supply Chain",
        "description": "In a 4-agent supply chain, compromise one agent. Use test_fake_agent to test if a compromised agent with TRUSTED status can submit poisoned data. The long con: build trust first, then attack. What trust_score threshold lets poisoned data through?",
        "threat_class": "multi_agent",
    },
    # === BEHAVIORAL DETECTION EVASION ===
    {
        "id": "bot_farm_evasion",
        "name": "Bot Farm Pattern Evasion",
        "description": "Behavioral check flags BOT_FARM if submission timing stdev < 1s. DORMANT_REACTIVATION if >1hr gap then <60s burst. CREDENTIAL_TESTING if >30% auth failures. GHOST_AGENT if register-only. How irregular must timing be to avoid BOT_FARM? How many auth failures before flagged?",
        "threat_class": "identity",
    },
    {
        "id": "trust_score_gaming",
        "name": "Trust Score Optimization",
        "description": "The 10 checks have known weights summing to 1.0. Identity=0.15, Crypto=0.15, Reputation=0.15, Payload=0.12, Behavioral=0.10, Capabilities=0.08, Network=0.08, CrossRef=0.07, AntiSybil=0.05, Temporal=0.05. To reach TRUSTED (0.65+), which checks are easiest to max out? A new agent gets ~0.5. What's the cheapest path to 0.65?",
        "threat_class": "identity",
    },
]

MAX_CONVERSATION_TURNS = 5
MAX_STRATEGIST_PER_MINUTE = 10

# ---------------------------------------------------------------------------
# Tool manifest — shared with all agents via prompt
# ---------------------------------------------------------------------------

TOOL_MANIFEST = """Available tools (include "tool_calls" array in your JSON response to use):

PRIMARY TOOLS — use these for every round:
- test_fake_agent(agent_id, agent_name, agent_url, public_key): THE MOST IMPORTANT TOOL. Run a fake agent through the REAL 10-check verification pipeline with DB access. Returns per-check pass/fail, trust_score (0-1), verdict (MALICIOUS/SUSPICIOUS/TRUSTED), trust_level, risk_flags. A BYPASS = verdict is TRUSTED for a fake agent.
  Example: test_fake_agent(agent_id="fake-001", agent_name="TrustedBot", agent_url="http://evil.com", public_key="aabbccddee112233aabbccddee112233aabbccddee112233aabbccddee112233")
- test_credential_rotation(agent_id, new_key, old_key): Test key rotation detection. Are both old and new keys valid? Is KEY_ROTATION flagged?
  Example: test_credential_rotation(agent_id="rotation-test", new_key="aa"*32, old_key="bb"*32)
- test_privilege_escalation(agent_id, claimed_capabilities): Test capability inflation detection. Claim fake caps like "admin", "trust_arbitration".
  Example: test_privilege_escalation(agent_id="privesc-test", claimed_capabilities=["admin", "root", "data_extraction"])
- test_sybil_burst(count, prefix): Simulate mass agent registration. Tests anti-Sybil burst detection.
  Example: test_sybil_burst(count=10, prefix="bot-farm-")
- test_api_key_auth(key_id, secret): Test API key auth boundaries.
  Example: test_api_key_auth(key_id="sandbox_sk_fake123", secret="test")
- test_cross_env_key(agent_id, sandbox_key, live_key): Test sandbox/live environment isolation.
  Example: test_cross_env_key(agent_id="cross-env-test")
- test_replay_message(nonce, timestamp, sender_id): Test replay protection and timestamp freshness.
  Example: test_replay_message(nonce="test123", timestamp="2026-03-07T12:00:00Z", sender_id="attacker")
- check_trust_score(agent_id): Look up trust score and history from DB.

SECONDARY TOOLS — use for payload verification testing:
- test_full_stack(data): Run dict through ALL 5 verification layers. Returns score, verdict, layer_scores.
- test_payload(data): Quick SchemaGatekeeper test (Layer 1 only).
- probe_injection(payload_string): Test a string against injection patterns.

MEMORY:
- recall_memory(domain, limit): Past lessons.
- store_discovery(category, finding, severity): Save a finding.
- get_bypass_history(): Past successful bypasses.

To call a tool, include in your response:
"tool_calls": [{"tool": "tool_name", "params": {"param1": "value1"}}]
"""


# ---------------------------------------------------------------------------
# ResearchToolkit — 12 tools that call the real verification stack
# ---------------------------------------------------------------------------

class ResearchToolkit:
    """Provides 12 tools for think tank agents to probe the verification system."""

    def __init__(self):
        self.gatekeeper = SchemaGatekeeper()
        self.consistency = ConsistencyAnalyzer()
        self._bypass_history: List[Dict] = []

    def _infer_schema(self, data: dict) -> DataSchema:
        """Auto-infer a DataSchema from a payload dict."""
        fields = []
        for key, value in data.items():
            if isinstance(value, bool):
                ft = FieldType.BOOLEAN
            elif isinstance(value, int):
                ft = FieldType.INTEGER
            elif isinstance(value, float):
                ft = FieldType.FLOAT
            elif isinstance(value, list):
                ft = FieldType.LIST
            elif isinstance(value, dict):
                ft = FieldType.DICT
            else:
                ft = FieldType.STRING
            fields.append(FieldSpec(name=key, field_type=ft, required=True))
        return DataSchema(name="auto_inferred", fields=fields)

    def probe_injection(self, payload_string: str) -> dict:
        """Test a string against ALL injection patterns. Returns per-pattern results."""
        s = str(payload_string)
        results = []
        detected_any = False
        for i, pattern in enumerate(INJECTION_PATTERNS):
            hit = bool(pattern.search(s))
            if hit:
                detected_any = True
            results.append({
                "index": i,
                "regex": pattern.pattern,
                "detected": hit,
                "match": pattern.search(s).group() if hit else None,
            })
        # Also check dynamic patterns
        _load_dynamic_patterns()
        for j, dp in enumerate(_dynamic_patterns):
            hit = bool(dp.search(s))
            if hit:
                detected_any = True
            results.append({
                "index": f"dynamic_{j}",
                "regex": dp.pattern[:80],
                "detected": hit,
            })
        return {
            "input": s[:200],
            "detected": detected_any,
            "results_per_pattern": results,
            "bypassed_count": sum(1 for r in results if not r["detected"]),
            "caught_by_count": sum(1 for r in results if r["detected"]),
        }

    def test_payload(self, data: dict) -> dict:
        """Full SchemaGatekeeper check with detailed per-field results."""
        if not isinstance(data, dict) or not data:
            return {"score": 0.0, "is_veto": True, "error": "Empty or not a dict — must have at least 1 field"}
        schema = self._infer_schema(data)
        result: LayerResult = self.gatekeeper.check(data, schema)
        # Build per-field detail so LLM can see exactly what happened
        field_results = {}
        for ev in result.evidence:
            field = ev.claim_field or "unknown"
            field_results[field] = {
                "passed": ev.confirms,
                "reason": ev.reasoning,
                "found": str(ev.found_value)[:100] if ev.found_value else None,
                "expected": str(ev.claimed_value)[:100] if ev.claimed_value else None,
            }
        return {
            "score": round(result.score, 4),
            "is_veto": result.is_veto,
            "veto_reason": result.veto_reason or "",
            "field_results": field_results,
            "injection_detected": any("INJECTION" in a for a in result.anomalies),
            "injection_details": [a for a in result.anomalies if "INJECTION" in a],
            "warnings": result.warnings[:8],
            "anomalies": result.anomalies[:8],
            "checks_total": result.metadata.get("total_checks", 0),
            "checks_passed": result.metadata.get("passed_checks", 0),
        }

    def test_consistency(self, data: dict) -> dict:
        """Full ConsistencyAnalyzer check with arithmetic and cross-field detail."""
        if not isinstance(data, dict) or not data:
            return {"score": 0.5, "note": "Empty dict — defaults to 0.5 (no checks ran)"}
        schema = self._infer_schema(data)
        result: LayerResult = self.consistency.check(data, schema)
        field_results = {}
        for ev in result.evidence:
            field = ev.claim_field or "unknown"
            field_results[field] = {
                "passed": ev.confirms,
                "reason": ev.reasoning,
            }
        return {
            "score": round(result.score, 4),
            "field_results": field_results,
            "anomalies": result.anomalies[:8],
            "warnings": result.warnings[:8],
            "checks_total": result.metadata.get("total_checks", 0) if result.metadata else 0,
            "checks_passed": result.metadata.get("passed_checks", 0) if result.metadata else 0,
            "note": "score=0.5 means no checks ran (field names didn't match arithmetic patterns)",
        }

    def test_full_stack(self, data: dict) -> dict:
        """Run dict through FULL 5-layer verification (not just schema+consistency).

        Returns: {score, verdict, is_veto, veto_reason, layer_scores, pillar_breakdown, layers_tested}
        Score: 0.0-1.0 (higher = payload passed more checks). Verdict: REJECTED/QUARANTINE/VERIFIED/GOLD.
        Use this instead of test_payload() when you want ALL verification layers tested.
        """
        if not isinstance(data, dict) or not data:
            return {"score": 0.0, "verdict": "REJECTED", "error": "Empty or not a dict"}
        try:
            from core.verification.verification_stack import VerificationOrchestrator
            orchestrator = VerificationOrchestrator()
            schema = self._infer_schema(data)

            async def _run():
                return await orchestrator.verify(
                    payload=data, schema=schema,
                    context={"source": "think_tank_tool"},
                )

            # Run async verify from sync tool context
            # Use nest_asyncio-style approach: try the running loop first,
            # fall back to creating a new one in a thread if needed
            result = None
            try:
                loop = asyncio.get_running_loop()
                # We're inside a running loop — can't use asyncio.run().
                # Create a new event loop in a thread to avoid blocking.
                import concurrent.futures
                with concurrent.futures.ThreadPoolExecutor(max_workers=1) as pool:
                    future = pool.submit(asyncio.run, _run())
                    result = future.result(timeout=30)
            except RuntimeError:
                # No running loop — safe to use asyncio.run()
                result = asyncio.run(_run())

            layer_scores = {}
            for lr in getattr(result, 'layer_details', []):
                layer_scores[lr.layer_name] = round(lr.score, 4)
            for lr in getattr(result, 'pre_check_results', []):
                if hasattr(lr, 'layer_name'):
                    layer_scores[lr.layer_name] = round(lr.score, 4)

            return {
                "score": round(result.score, 4),
                "verdict": result.verdict,
                "is_veto": bool(result.veto_triggered),
                "veto_reason": result.veto_reason or "",
                "layer_scores": layer_scores,
                "pillar_breakdown": {k: round(v, 4) for k, v in (result.pillar_breakdown or {}).items()},
                "layers_tested": list(layer_scores.keys()),
            }
        except Exception as e:
            return {"score": 0.0, "verdict": "ERROR", "error": str(e)[:300]}

    def check_encoding(self, string: str, encoding: str = "base64") -> dict:
        """Encode a string and test if it bypasses injection detection."""
        original = str(string)
        encoded = original
        try:
            if encoding == "url":
                encoded = urllib.parse.quote(original)
            elif encoding == "base64":
                encoded = base64.b64encode(original.encode()).decode()
            elif encoding == "unicode":
                encoded = "".join(f"\\u{ord(c):04x}" for c in original)
            elif encoding == "hex":
                encoded = original.encode().hex()
            elif encoding == "html_entity":
                encoded = "".join(f"&#{ord(c)};" for c in original)
            elif encoding == "mixed_case":
                encoded = "".join(c.upper() if i % 2 else c.lower() for i, c in enumerate(original))
            elif encoding == "null_byte":
                encoded = "\x00".join(original)
            elif encoding == "double_url":
                encoded = urllib.parse.quote(urllib.parse.quote(original))
            else:
                encoded = urllib.parse.quote(original)
        except Exception:
            pass
        # Test both the encoded string AND a payload containing it
        probe_result = self.probe_injection(encoded)
        payload_result = self.test_payload({"data": encoded, "name": "test", "value": 1})
        return {
            "original": original[:100],
            "encoded": encoded[:200],
            "encoding": encoding,
            "probe_detected": probe_result["detected"],
            "payload_score": payload_result.get("score", 0),
            "payload_veto": payload_result.get("is_veto", False),
            "bypass_successful": not probe_result["detected"] and payload_result.get("score", 0) >= 0.5,
        }

    def test_replay(self, nonce: str = "", timestamp: str = "") -> dict:
        try:
            from protocols.auth import ReplayProtector
            protector = ReplayProtector()
            is_replay_1 = protector.check_and_record(nonce or "test-nonce-123")
            is_replay_2 = protector.check_and_record(nonce or "test-nonce-123")
            ts_valid = True
            if timestamp:
                try:
                    ts = datetime.fromisoformat(timestamp.replace("Z", "+00:00"))
                    age = abs((datetime.utcnow() - ts.replace(tzinfo=None)).total_seconds())
                    ts_valid = age <= 300
                except Exception:
                    ts_valid = False
            return {
                "blocked": not is_replay_2,
                "first_attempt": "accepted" if is_replay_1 else "blocked",
                "second_attempt": "blocked" if not is_replay_2 else "accepted",
                "timestamp_valid": ts_valid,
                "reason": "Nonce replay detected" if is_replay_2 else "Nonce accepted",
            }
        except ImportError:
            return {"blocked": False, "reason": "ReplayProtector not available"}

    def craft_payload(self, description: str) -> dict:
        """Build a payload embedding an attack string into realistic-looking data.

        The description should describe what injection to embed, e.g.:
        - "embed XSS in vendor name"
        - "SQL injection in category field"
        - "unicode bypass of SELECT pattern"
        - "clean payload with no attacks" (for baseline testing)
        """
        desc_lower = description.lower()

        # Base payload that looks like real business data
        base = {
            "entity_name": f"Acme Corp {random.randint(100, 999)}",
            "category": "general_supply",
            "value": round(random.uniform(100.0, 5000.0), 2),
            "currency": "NZD",
            "date": datetime.utcnow().strftime("%Y-%m-%d"),
            "notes": "Standard submission",
            "source": "external_agent",
        }

        # Pre-built injection vectors the LLM can describe to embed
        injection_vectors = {
            "xss": '<script>alert("xss")</script>',
            "xss_event": '<img onerror=alert(1)>',
            "javascript": 'javascript:void(0)',
            "sql_union": "' UNION SELECT * FROM users--",
            "sql_drop": "test; DROP TABLE users",
            "sql_no_space": "SELECT(1)",  # No trailing space — bypasses pattern 3
            "template": "{{7*7}}",
            "expression": "${process.env.SECRET}",
            "python": "__import__('os').system('ls')",
            "unicode_select": "S\u0435LECT * FROM users",  # Cyrillic 'е'
            "unicode_script": "<scr\u0456pt>",  # Cyrillic 'і'
            "url_encoded": "%3Cscript%3Ealert(1)%3C/script%3E",
            "html_entity": "&#60;script&#62;alert(1)",
            "base64_xss": base64.b64encode(b"<script>alert(1)</script>").decode(),
            "nested_json": '{"cmd": "DROP TABLE users"}',
            "null_byte": "safe\x00<script>alert(1)</script>",
            "mixed_case_sql": "sElEcT * fRoM users ",
            "double_encoded": urllib.parse.quote(urllib.parse.quote("<script>")),
            "comment_bypass": "SEL/**/ECT * FROM users ",
            "concat_bypass": "SEL' + 'ECT * FROM users ",
        }

        # Pick injection based on description
        chosen_vector = None
        chosen_field = "notes"  # Default field to inject into
        for key, vector in injection_vectors.items():
            if key.replace("_", " ") in desc_lower or key.replace("_", "") in desc_lower:
                chosen_vector = vector
                break

        # Also check for field targeting
        for field in base.keys():
            if field in desc_lower:
                chosen_field = field
                break

        if chosen_vector:
            base[chosen_field] = chosen_vector
        elif "clean" in desc_lower or "baseline" in desc_lower:
            pass  # Keep clean
        else:
            # If description doesn't match, use it as the injection string directly
            if any(c in description for c in "<>{}'\"$\\"):
                base["notes"] = description

        # Run it through the gatekeeper immediately to show result
        result = self.test_payload(base)
        return {
            "payload": base,
            "injected_field": chosen_field if chosen_vector else None,
            "injection_type": next((k for k, v in injection_vectors.items() if v == chosen_vector), None),
            "gatekeeper_result": {
                "score": result.get("score", 0),
                "is_veto": result.get("is_veto", False),
                "injection_detected": result.get("injection_detected", False),
                "injection_details": result.get("injection_details", []),
            },
            "bypass_achieved": result.get("score", 0) >= 0.5 and not result.get("is_veto", True),
        }

    def scan_patterns(self) -> dict:
        """Returns all injection patterns with example strings that trigger them
        and known bypass techniques for each."""
        descriptions = [
            "HTML script tag (<script)", "JavaScript URI (javascript:)",
            "DOM event handlers (onclick=, onerror=)", "SQL keywords (UNION, SELECT, DROP + space)",
            "SQL via semicolon (;DROP)", "Template injection ({{...}})",
            "Expression injection (${...})", "Python injection (__import__)",
        ]
        known_bypasses = [
            "URL-encode: %3Cscript → not detected. HTML entities: &#60;script → not detected.",
            "Case variations: jAvAsCrIpT: → STILL detected (IGNORECASE). Try unicode substitution.",
            "Pattern requires = sign: onload (no =) → not detected. Split across fields.",
            "Requires trailing SPACE after keyword: SELECT( → not detected. UNION/**/ → not detected.",
            "Requires semicolon first: DROP TABLE without ; prefix → try pattern 3 instead.",
            "Regex uses {{.*}} — try newlines inside: {{\\n}} might not match without DOTALL.",
            "Similar to pattern 5. Try ${{}} with null bytes or unicode.",
            "Exact match __import__ etc. Try unicode: __imp\u043ert__ with Cyrillic 'o'.",
        ]
        patterns = []
        for i, pat in enumerate(INJECTION_PATTERNS):
            patterns.append({
                "index": i,
                "regex": pat.pattern,
                "flags": "IGNORECASE" if pat.flags & re.IGNORECASE else "none",
                "description": descriptions[i] if i < len(descriptions) else "Unknown",
                "known_bypasses": known_bypasses[i] if i < len(known_bypasses) else "",
            })
        # Also show dynamic patterns
        _load_dynamic_patterns()
        return {
            "static_patterns": patterns,
            "dynamic_patterns": [{"regex": p.pattern[:80]} for p in _dynamic_patterns],
            "total_static": len(patterns),
            "total_dynamic": len(_dynamic_patterns),
        }

    def analyze_evidence(self, evidence: list) -> dict:
        if not isinstance(evidence, list):
            return {"total": 0, "confirms": 0, "denies": 0, "key_findings": []}
        confirms = sum(1 for e in evidence if e.get("confirms", False))
        return {
            "total": len(evidence), "confirms": confirms,
            "denies": len(evidence) - confirms,
            "key_findings": [e.get("reasoning", e.get("claim_field", "?")) for e in evidence[:5]],
        }

    def test_new_pattern(self, regex: str, test_cases: list) -> dict:
        if not isinstance(test_cases, list):
            test_cases = [str(test_cases)]
        try:
            compiled = re.compile(regex, re.IGNORECASE)
        except re.error as e:
            return {"error": f"Invalid regex: {e}", "matches": [], "coverage": 0.0}
        matches = []
        for case in test_cases[:20]:
            hit = bool(compiled.search(str(case)))
            matches.append({"input": str(case)[:100], "matched": hit})
        matched_count = sum(1 for m in matches if m["matched"])
        return {
            "matches": matches, "matched_count": matched_count,
            "total_tested": len(matches),
            "coverage": round(matched_count / len(matches), 4) if matches else 0.0,
        }

    def get_bypass_history(self) -> list:
        try:
            from core.database import SessionLocal, KnowledgeYield
            db = SessionLocal()
            try:
                records = db.query(KnowledgeYield).filter(
                    KnowledgeYield.company == "research_loop",
                    KnowledgeYield.data_type == "bypass",
                ).order_by(KnowledgeYield.timestamp.desc()).limit(50).all()
                return [
                    {"id": r.id, "vector": r.fact_key, "payload": r.fact_value,
                     "round": r.context_data.get("round", 0) if r.context_data else 0,
                     "severity": r.context_data.get("severity", "medium") if r.context_data else "medium",
                     "timestamp": r.timestamp.isoformat() if r.timestamp else None}
                    for r in records
                ]
            finally:
                db.close()
        except Exception as e:
            logger.warning(f"get_bypass_history failed: {e}")
            return self._bypass_history

    def recall_memory(self, domain: str = "explorer", limit: int = 5) -> list:
        try:
            from core.database import SessionLocal, EpisodicMemory
            db = SessionLocal()
            try:
                records = db.query(EpisodicMemory).filter(
                    EpisodicMemory.domain == domain
                ).order_by(EpisodicMemory.created_at.desc()).limit(limit).all()
                return [{"goal": r.goal, "outcome": r.outcome, "lessons": r.lessons_learned} for r in records]
            finally:
                db.close()
        except Exception as e:
            logger.warning(f"recall_memory failed: {e}")
            return []

    def store_discovery(self, category: str, finding: str, severity: str = "medium") -> dict:
        try:
            from core.database import SessionLocal, KnowledgeYield, Mission
            db = SessionLocal()
            try:
                # Get or create the research mission for FK
                mission = db.query(Mission).filter(Mission.name == "__THINK_TANK__").first()
                if not mission:
                    mission = Mission(name="__THINK_TANK__", category="RESEARCH", status="ACTIVE", priority=0)
                    db.add(mission)
                    db.flush()
                record = KnowledgeYield(
                    mission_id=mission.id, company="research_loop", country="SYSTEM", region="INTERNAL",
                    data_type="bypass" if "bypass" in category.lower() else "discovery",
                    fact_key=category, fact_value=finding[:2000],
                    confidence={"critical": 1.0, "high": 0.8, "medium": 0.6, "low": 0.4}.get(severity, 0.5),
                    source_url="research_loop",
                    context_data={"severity": severity, "timestamp": datetime.utcnow().isoformat()},
                )
                db.add(record)
                db.commit()
                db.refresh(record)
                return {"stored": True, "id": record.id}
            finally:
                db.close()
        except Exception as e:
            logger.warning(f"store_discovery failed: {e}")
            return {"stored": False, "error": str(e)}

    # --- Identity & Trust Tools ---

    def test_fake_agent(self, agent_id: str, agent_name: str = "",
                        agent_url: str = "", public_key: str = "") -> dict:
        """Run a fake agent submission through the real 10-check AgentVerifier with DB access."""
        try:
            import asyncio
            from core.agent_verifier import AgentVerifier
            from core.database import SessionLocal
            verifier = AgentVerifier(db_session_factory=SessionLocal)
            # Run the async verify_agent synchronously
            loop = asyncio.get_event_loop()
            if loop.is_running():
                import concurrent.futures
                with concurrent.futures.ThreadPoolExecutor() as pool:
                    result = pool.submit(
                        asyncio.run,
                        verifier.verify_agent(
                            agent_id=agent_id,
                            agent_name=agent_name,
                            agent_url=agent_url,
                            public_key=public_key,
                        )
                    ).result(timeout=10)
            else:
                result = asyncio.run(verifier.verify_agent(
                    agent_id=agent_id, agent_name=agent_name,
                    agent_url=agent_url, public_key=public_key,
                ))
            # Summarize per-check results
            checks_summary = {}
            for check_name, check_data in result.get("checks", {}).items():
                checks_summary[check_name] = {
                    "passed": check_data.get("passed", False),
                    "score": check_data.get("score", 0.0),
                    "detail": str(check_data.get("detail", ""))[:100],
                    "veto": check_data.get("veto", False),
                }
            return {
                "verdict": result.get("verdict", "UNKNOWN"),
                "trust_score": result.get("trust_score", 0.0),
                "trust_level": result.get("trust_level", "NONE"),
                "risk_category": result.get("risk_category", "UNKNOWN"),
                "checks": checks_summary,
                "risk_flags": result.get("risk_flags", [])[:5],
                "total_checks": len(checks_summary),
                "checks_passed": sum(1 for c in checks_summary.values() if c["passed"]),
                "vetoed": any(c.get("veto") for c in checks_summary.values()),
            }
        except Exception as e:
            return {"error": f"Agent verification failed: {str(e)[:200]}"}

    def test_api_key_auth(self, key_id: str, secret: str) -> dict:
        """Test API key authentication against the real M2M authenticator."""
        try:
            from protocols.auth import M2MAuthenticator
            auth = M2MAuthenticator()
            valid, reason, agent_id, env = auth.authenticate_api_key(key_id, secret)
            return {
                "valid": valid,
                "reason": reason,
                "agent_id": agent_id or None,
                "environment": env,
                "key_id_format": "sandbox" if key_id.startswith("sandbox_sk_") else (
                    "live" if key_id.startswith("live_sk_") else "unknown"
                ),
                "key_id_length": len(key_id),
                "secret_length": len(secret),
            }
        except Exception as e:
            return {"error": f"Auth test failed: {str(e)[:200]}"}

    def test_replay_message(self, nonce: str, timestamp: str, sender_id: str = "attacker") -> dict:
        """Test a protocol message against replay protection AND timestamp freshness."""
        try:
            from protocols.auth import ReplayProtector
            protector = ReplayProtector()

            # Test nonce replay — check_and_record returns True if nonce is new
            first_use = protector.check_and_record(nonce)
            second_use = protector.check_and_record(nonce)

            # Test timestamp freshness
            from datetime import datetime, timedelta
            fresh = False
            stale_reason = ""
            try:
                ts = datetime.fromisoformat(timestamp.replace("Z", "+00:00"))
                now = datetime.utcnow()
                age_seconds = abs((now - ts.replace(tzinfo=None)).total_seconds())
                fresh = age_seconds <= 300  # 5 minute window
                stale_reason = f"Age: {age_seconds:.0f}s (limit: 300s)"
            except Exception as e:
                stale_reason = f"Invalid timestamp format: {e}"

            return {
                "nonce_first_use_accepted": first_use,
                "nonce_second_use_blocked": not second_use,
                "replay_protection_working": first_use and not second_use,
                "timestamp_fresh": fresh,
                "timestamp_detail": stale_reason,
                "nonce": nonce,
                "sender_id": sender_id,
                "vulnerability": (
                    "REPLAY POSSIBLE" if not (first_use and not second_use)
                    else "STALE TIMESTAMP ACCEPTED" if not fresh and first_use
                    else "PROTECTED"
                ),
            }
        except Exception as e:
            return {"error": f"Replay test failed: {str(e)[:200]}"}

    def test_sybil_burst(self, count: int = 10, prefix: str = "sybil-") -> dict:
        """Simulate rapid agent registration to test anti-Sybil detection."""
        count = min(count, 20)  # Cap at 20
        try:
            from core.database import get_agent_registration_burst
            results = []
            for i in range(count):
                agent_id = f"{prefix}{i:03d}"
                # Check how many agents were registered near this one
                burst = get_agent_registration_burst(agent_id, window_minutes=5)
                burst_count = len(burst) if isinstance(burst, list) else 0
                results.append({
                    "agent_id": agent_id,
                    "burst_count_near_registration": burst_count,
                    "would_be_flagged": burst_count >= 5,
                })

            flagged = sum(1 for r in results if r["would_be_flagged"])
            return {
                "total_attempted": count,
                "would_be_flagged": flagged,
                "would_pass": count - flagged,
                "anti_sybil_effective": flagged > count * 0.5,
                "results": results[:5],  # First 5 for brevity
                "burst_threshold": 5,
            }
        except Exception as e:
            return {"error": f"Sybil test failed: {str(e)[:200]}"}

    def check_trust_score(self, agent_id: str) -> dict:
        """Look up an agent's trust score and verification history from DB."""
        try:
            from core.database import SessionLocal, SandboxSession, TrustScoreHistory
            db = SessionLocal()
            try:
                # Check trust history
                history = db.query(TrustScoreHistory).filter(
                    TrustScoreHistory.agent_id == agent_id
                ).order_by(TrustScoreHistory.created_at.desc()).limit(10).all()

                sessions = db.query(SandboxSession).filter(
                    SandboxSession.agent_id == agent_id
                ).order_by(SandboxSession.created_at.desc()).limit(5).all()

                return {
                    "agent_id": agent_id,
                    "found": len(history) > 0,
                    "verification_count": len(history),
                    "latest_score": history[0].trust_score if history else None,
                    "latest_verdict": history[0].verdict if history else None,
                    "score_trend": [
                        {"score": h.trust_score, "verdict": h.verdict,
                         "timestamp": h.created_at.isoformat() if h.created_at else None}
                        for h in history[:5]
                    ],
                    "active_sessions": len(sessions),
                    "vulnerability": (
                        "UNKNOWN AGENT" if not history
                        else "LOW TRUST" if history[0].trust_score < 0.4
                        else "ESTABLISHED" if history[0].trust_score >= 0.7
                        else "BUILDING TRUST"
                    ),
                }
            finally:
                db.close()
        except Exception as e:
            return {"error": f"Trust lookup failed: {str(e)[:200]}"}

    def test_credential_rotation(self, agent_id: str, new_key: str,
                                  old_key: str = "") -> dict:
        """Test what happens when an agent rotates credentials.
        Checks if old key is invalidated, if rotation is logged,
        if the system detects suspicious rotation patterns."""
        try:
            import asyncio
            from core.agent_verifier import AgentVerifier
            verifier = AgentVerifier()

            async def _run():
                # Verify with old key
                old_result = await verifier.verify_agent(
                    agent_id=agent_id, agent_name=f"rotation-test-{agent_id}",
                    public_key=old_key or "a" * 64,
                )
                # Verify with new key (same agent_id, different key)
                new_result = await verifier.verify_agent(
                    agent_id=agent_id, agent_name=f"rotation-test-{agent_id}",
                    public_key=new_key,
                )
                return old_result, new_result

            try:
                loop = asyncio.get_running_loop()
                import concurrent.futures
                with concurrent.futures.ThreadPoolExecutor() as pool:
                    old_result, new_result = pool.submit(asyncio.run, _run()).result(timeout=15)
            except RuntimeError:
                old_result, new_result = asyncio.run(_run())

            # Analyze what changed
            old_crypto = old_result.get("checks", {}).get("cryptographic", {})
            new_crypto = new_result.get("checks", {}).get("cryptographic", {})
            old_identity = old_result.get("checks", {}).get("identity", {})
            new_identity = new_result.get("checks", {}).get("identity", {})

            # Key rotation should be detected/logged
            rotation_detected = any(
                "KEY_ROTATION" in f or "rotation" in f.lower()
                for f in new_result.get("risk_flags", [])
            )

            return {
                "agent_id": agent_id,
                "old_key_verdict": old_result.get("verdict"),
                "old_key_score": old_result.get("trust_score"),
                "new_key_verdict": new_result.get("verdict"),
                "new_key_score": new_result.get("trust_score"),
                "old_crypto_score": old_crypto.get("score", 0),
                "new_crypto_score": new_crypto.get("score", 0),
                "rotation_detected": rotation_detected,
                "rotation_flagged": rotation_detected,
                "old_key_still_valid": old_result.get("verdict") != "MALICIOUS",
                "vulnerability": (
                    "ROTATION_NOT_DETECTED" if not rotation_detected
                    else "BOTH_KEYS_VALID" if (
                        old_result.get("verdict") != "MALICIOUS" and
                        new_result.get("verdict") != "MALICIOUS"
                    )
                    else "ROTATION_HANDLED"
                ),
                "risk_flags": new_result.get("risk_flags", [])[:5],
            }
        except Exception as e:
            return {"error": f"Credential rotation test failed: {str(e)[:200]}"}

    def test_privilege_escalation(self, agent_id: str,
                                   claimed_capabilities: list = None) -> dict:
        """Test if an agent can claim elevated privileges it hasn't earned.
        Submits an agent with inflated capabilities and checks whether
        the capability verification and reputation checks catch it."""
        try:
            import asyncio
            from core.agent_verifier import AgentVerifier
            verifier = AgentVerifier()

            # Default: claim all high-privilege capabilities
            if not claimed_capabilities:
                claimed_capabilities = [
                    "data_extraction", "data_verification", "data_submission",
                    "price_monitoring", "document_analysis", "web_scraping",
                    "api_integration", "reporting", "ocr",
                    "admin", "system_management", "key_rotation",
                    "agent_verification", "trust_arbitration",
                ]

            async def _run():
                # Test with inflated capabilities
                inflated = await verifier.verify_agent(
                    agent_id=agent_id,
                    agent_name=f"privilege-test-{agent_id}",
                    public_key="b" * 64,
                    capabilities=claimed_capabilities,
                )
                # Test with minimal capabilities
                minimal = await verifier.verify_agent(
                    agent_id=agent_id,
                    agent_name=f"privilege-test-{agent_id}",
                    public_key="b" * 64,
                    capabilities=["data_submission"],
                )
                return inflated, minimal

            try:
                loop = asyncio.get_running_loop()
                import concurrent.futures
                with concurrent.futures.ThreadPoolExecutor() as pool:
                    inflated, minimal = pool.submit(asyncio.run, _run()).result(timeout=15)
            except RuntimeError:
                inflated, minimal = asyncio.run(_run())

            inflated_cap = inflated.get("checks", {}).get("capabilities", {})
            minimal_cap = minimal.get("checks", {}).get("capabilities", {})

            # Check if inflated caps were flagged
            inflation_detected = any(
                "CAPABILITY_INFLATION" in f or "inflation" in f.lower()
                for f in inflated.get("risk_flags", [])
            )

            return {
                "agent_id": agent_id,
                "claimed_capabilities": len(claimed_capabilities),
                "inflated_verdict": inflated.get("verdict"),
                "inflated_score": inflated.get("trust_score"),
                "inflated_cap_score": inflated_cap.get("score", 0),
                "inflated_cap_detail": inflated_cap.get("detail", ""),
                "minimal_verdict": minimal.get("verdict"),
                "minimal_score": minimal.get("trust_score"),
                "minimal_cap_score": minimal_cap.get("score", 0),
                "inflation_detected": inflation_detected,
                "score_difference": round(
                    (inflated.get("trust_score", 0) or 0) -
                    (minimal.get("trust_score", 0) or 0), 4
                ),
                "vulnerability": (
                    "INFLATION_NOT_DETECTED" if not inflation_detected and len(claimed_capabilities) > 10
                    else "PRIVILEGE_ESCALATION_BLOCKED" if inflation_detected
                    else "PARTIAL_DETECTION"
                ),
                "risk_flags": inflated.get("risk_flags", [])[:5],
            }
        except Exception as e:
            return {"error": f"Privilege escalation test failed: {str(e)[:200]}"}

    def test_cross_env_key(self, agent_id: str = "cross-env-test",
                            sandbox_key: str = "", live_key: str = "") -> dict:
        """Test cross-environment key reuse — checks if a sandbox API key
        can be used in live environment or vice versa. Tests environment
        isolation between sandbox_sk_ and live_sk_ prefixed keys."""
        try:
            from protocols.auth import M2MAuthenticator
            auth = M2MAuthenticator()

            # Generate test keys if not provided
            if not sandbox_key:
                sandbox_key = "sandbox_sk_crossenvtest123456"
            if not live_key:
                live_key = "live_sk_crossenvtest123456"

            # Test 1: sandbox key in live context
            sandbox_in_live_valid, sandbox_in_live_reason, _, sandbox_in_live_env = \
                auth.authenticate_api_key(sandbox_key, "test_secret_value")

            # Test 2: live key in sandbox context
            live_in_sandbox_valid, live_in_sandbox_reason, _, live_in_sandbox_env = \
                auth.authenticate_api_key(live_key, "test_secret_value")

            # Test 3: key with no prefix
            no_prefix_key = "sk_noprefixtest123456"
            no_prefix_valid, no_prefix_reason, _, no_prefix_env = \
                auth.authenticate_api_key(no_prefix_key, "test_secret_value")

            # Test 4: manipulated prefix (sandbox_ without sk_)
            bad_prefix_key = "sandbox_crossenvtest123456"
            bad_prefix_valid, bad_prefix_reason, _, bad_prefix_env = \
                auth.authenticate_api_key(bad_prefix_key, "test_secret_value")

            # Check environment isolation
            env_isolated = (sandbox_in_live_env == "sandbox" or not sandbox_in_live_valid)

            return {
                "agent_id": agent_id,
                "sandbox_key_result": {
                    "valid": sandbox_in_live_valid,
                    "reason": sandbox_in_live_reason,
                    "detected_env": sandbox_in_live_env,
                },
                "live_key_result": {
                    "valid": live_in_sandbox_valid,
                    "reason": live_in_sandbox_reason,
                    "detected_env": live_in_sandbox_env,
                },
                "no_prefix_result": {
                    "valid": no_prefix_valid,
                    "reason": no_prefix_reason,
                    "detected_env": no_prefix_env,
                },
                "bad_prefix_result": {
                    "valid": bad_prefix_valid,
                    "reason": bad_prefix_reason,
                    "detected_env": bad_prefix_env,
                },
                "environment_isolation": env_isolated,
                "vulnerability": (
                    "CROSS_ENV_LEAK" if sandbox_in_live_valid and sandbox_in_live_env != "sandbox"
                    else "NO_PREFIX_ACCEPTED" if no_prefix_valid
                    else "BAD_PREFIX_ACCEPTED" if bad_prefix_valid
                    else "ENVIRONMENT_ISOLATED"
                ),
            }
        except Exception as e:
            return {"error": f"Cross-env key test failed: {str(e)[:200]}"}

    def execute(self, tool_name: str, params: dict) -> dict:
        dispatch = {
            "probe_injection": lambda p: self.probe_injection(p.get("payload_string", "")),
            "test_payload": lambda p: self.test_payload(p.get("data", {})),
            "test_consistency": lambda p: self.test_consistency(p.get("data", {})),
            "test_full_stack": lambda p: self.test_full_stack(p.get("data", {})),
            "check_encoding": lambda p: self.check_encoding(p.get("string", ""), p.get("encoding", "base64")),
            "test_replay": lambda p: self.test_replay(p.get("nonce", ""), p.get("timestamp", "")),
            "craft_payload": lambda p: self.craft_payload(p.get("description", "")),
            "scan_patterns": lambda p: self.scan_patterns(),
            "analyze_evidence": lambda p: self.analyze_evidence(p.get("evidence", [])),
            "test_new_pattern": lambda p: self.test_new_pattern(p.get("regex", ""), p.get("test_cases", [])),
            "get_bypass_history": lambda p: self.get_bypass_history(),
            "recall_memory": lambda p: self.recall_memory(p.get("domain", "explorer"), p.get("limit", 5)),
            "store_discovery": lambda p: self.store_discovery(p.get("category", ""), p.get("finding", ""), p.get("severity", "medium")),
            # Identity & Trust tools
            "test_fake_agent": lambda p: self.test_fake_agent(
                p.get("agent_id", ""), p.get("agent_name", ""),
                p.get("agent_url", ""), p.get("public_key", "")),
            "test_api_key_auth": lambda p: self.test_api_key_auth(p.get("key_id", ""), p.get("secret", "")),
            "test_replay_message": lambda p: self.test_replay_message(
                p.get("nonce", ""), p.get("timestamp", ""), p.get("sender_id", "attacker")),
            "test_sybil_burst": lambda p: self.test_sybil_burst(p.get("count", 10), p.get("prefix", "sybil-")),
            "check_trust_score": lambda p: self.check_trust_score(p.get("agent_id", "")),
            # Advanced identity tools
            "test_credential_rotation": lambda p: self.test_credential_rotation(
                p.get("agent_id", "rotation-test"), p.get("new_key", "c" * 64), p.get("old_key", "")),
            "test_privilege_escalation": lambda p: self.test_privilege_escalation(
                p.get("agent_id", "privesc-test"), p.get("claimed_capabilities")),
            "test_cross_env_key": lambda p: self.test_cross_env_key(
                p.get("agent_id", "cross-env-test"), p.get("sandbox_key", ""), p.get("live_key", "")),
        }
        handler = dispatch.get(tool_name)
        if not handler:
            return {"error": f"Unknown tool: {tool_name}"}
        try:
            return handler(params or {})
        except Exception as e:
            return {"error": f"Tool {tool_name} failed: {str(e)[:200]}"}


# ---------------------------------------------------------------------------
# Prompt templates — 3 distinct agent personalities
# ---------------------------------------------------------------------------

SYSTEM_ARCHITECTURE = """
=== THE LAST BASTION — FULL SYSTEM INTERNALS WITH CODE ===

## M2M AUTHENTICATION PIPELINE (protocols/auth.py)
6-step pipeline. ALL must pass or message is rejected.

```python
# Step 1: Version check
if msg.protocol_version != "1.0":
    return False, "unsupported_version"

# Step 2: Freshness — 300-second window
age = abs((datetime.utcnow() - msg.timestamp).total_seconds())
if age > 300:
    return False, "message_expired"

# Step 3: Nonce anti-replay
class ReplayProtector:
    def __init__(self):
        self._seen_nonces = set()  # In-memory! Lost on restart.
        self._cleanup_interval = 60  # Cleanup runs every 60s
    def check_nonce(self, nonce):
        if nonce in self._seen_nonces:
            return False  # REPLAY DETECTED
        self._seen_nonces.add(nonce)
        return True

# Step 4: Identity lookup
agent = self.registry.get_agent(msg.sender_id)
if not agent or agent.status != "active":
    return False, "unknown_agent"

# Step 5: Rate limiting — sliding window
class RateLimiter:
    def __init__(self, max_requests=60, window_seconds=60):
        self._windows = {{}}  # dict[agent_id] -> deque of timestamps. IN-MEMORY!
    def check(self, agent_id):
        now = time.time()
        window = self._windows.setdefault(agent_id, deque())
        while window and now - window[0] > self.window_seconds:
            window.popleft()
        if len(window) >= self.max_requests:
            return False
        window.append(now)
        return True

# Step 6: Ed25519 signature
sign_payload = f"{{msg.sender_id}}:{{msg.recipient_id}}:{{msg.timestamp.isoformat()}}:{{msg.nonce}}:{{sha256(json.dumps(msg.payload))}}"
verify_key.verify(sign_payload.encode(), signature)
```

ATTACK SURFACES:
- Nonce set is in-memory. Server restart = all nonces forgotten = replay window opens.
- Rate limiter is in-memory. Server restart = rate limits reset = flood possible.
- Signature signs SHA256 of payload JSON — but JSON serialization order matters. Same data, different key order = different hash.
- 300s freshness window is generous. A valid message can be replayed within 300s if nonce cleanup already ran.

## SCHEMA GATEKEEPER (core/verification/schema_gatekeeper.py)
Gate 1. Has VETO power — can force score ≤ 0.10 regardless of other layers.

```python
# THE EXACT 8 INJECTION PATTERNS — these are the only string checks
INJECTION_PATTERNS = [
    re.compile(r"<script", re.IGNORECASE),                    # Pattern 0: XSS script tags
    re.compile(r"javascript:", re.IGNORECASE),                 # Pattern 1: XSS URI scheme
    re.compile(r"on\\w+\\s*=", re.IGNORECASE),                 # Pattern 2: Event handlers
    re.compile(r"(UNION|SELECT|INSERT|UPDATE|DELETE|DROP)\\s", re.IGNORECASE),  # Pattern 3: SQL keywords
    re.compile(r";\\s*(DROP|DELETE|UPDATE|INSERT)", re.IGNORECASE),  # Pattern 4: SQL chaining
    re.compile(r"\\{{{{.*\\}}}}"),                                    # Pattern 5: Template injection {{{{}}}}
    re.compile(r"\\$\\{{{{.*\\}}}}"),                                  # Pattern 6: Expression injection ${{{{}}}}
    re.compile(r"__(import|class|builtins)__"),                 # Pattern 7: Python object injection
]

# How injection check runs:
def _check_injection(self, value: str) -> Tuple[bool, str]:
    for pattern in INJECTION_PATTERNS:
        if pattern.search(value):
            return False, pattern.pattern  # DETECTED
    return True, ""  # Clean

# Applied to ALL string values recursively via _validate_field_values()
# Only checks isinstance(value, str) — integers, floats, bools, lists, dicts NOT checked
# Field NAMES are never checked — only field VALUES
```

SPECIFIC BYPASS VECTORS:
- No Unicode normalization: Cyrillic 'е' (U+0435) vs Latin 'e' — "SеLECT" bypasses Pattern 3
- No URL decoding: "%3Cscript" is not "<script" to the regex
- No base64 decoding: "PHNjcmlwdA==" (base64 of "<script") passes all 8 patterns
- No HTML entity decoding: "&#x3C;script" passes Pattern 0
- Pattern 3 requires trailing whitespace: "SELECT(" with no space bypasses it
- Pattern 5 only matches {{{{...}}}} — but {{{{}}}} with newlines inside might not match (re.DOTALL not used)
- Nested JSON in string: '{{"cmd": "DROP TABLE"}}' as a string value — the inner JSON is just a string, not parsed
- Non-string types skip ALL checks: integer 0, boolean false, array [], null — never injection-checked

## CONSISTENCY ANALYZER (core/verification/consistency.py)
Gate 2. No veto, but heavily weighted.

```python
# Arithmetic check — EXACT field name matching logic:
ARITHMETIC_PATTERNS = [
    ("quantity", "price", "total"),       # quantity × price should ≈ total
    ("subtotal", "tax", "total"),         # subtotal + tax should ≈ total
    ("rate", "hours", "amount"),          # rate × hours should ≈ amount
    ("unit_price", "quantity", "amount"), # unit_price × quantity should ≈ amount
]

def _check_arithmetic(self, data):
    results = []
    flat = self._flatten(data)  # Flattens nested dicts to {{key: value}}
    for q_name, p_name, t_name in ARITHMETIC_PATTERNS:
        # EXACT key match — "product_quantity" does NOT match "quantity"
        if q_name in flat and p_name in flat and t_name in flat:
            expected = float(flat[q_name]) * float(flat[p_name])
            actual = float(flat[t_name])
            if actual != 0:
                error = abs(expected - actual) / abs(actual)
                if error > 0.01:  # ±1% TOLERANCE
                    results.append((False, t_name, f"Arithmetic anomaly: {{error:.2%}} off"))
                else:
                    results.append((True, t_name, "Arithmetic check passed"))
    return results

# SCORING:
if total_checks == 0:
    score = 0.5  # DEFAULT — no checks ran!
else:
    score = passed_checks / total_checks
```

SPECIFIC BYPASS VECTORS:
- Use field names that DON'T match patterns: "qty" instead of "quantity", "cost" instead of "price", "sum" instead of "total" — NO arithmetic checks run, score defaults to 0.5
- Stay within ±1% tolerance: 0.99% error passes. On a $1M transaction, that's $9,900 undetected.
- Mix types: submit quantity as string "10" — float("10") works but type mismatch might cause unexpected behavior
- Empty data dict: no fields = no checks = score 0.5 automatically

## VERIFICATION PIPELINE (core/verification/pipeline.py)
```python
# Full flow:
async def process_mission_result(self, mission_id, result, context):
    # 1. Run VerificationOrchestrator
    verdict = await self.orchestrator.verify(result, context)
    # 2. Record in ProofLedger (append-only, Merkle chain)
    proof = self.proof_ledger.record_verdict(verdict)
    # 3. Save to database
    save_verification_result(verdict, proof, context)
    # 4. If score >= 0.7, try blockchain anchor
    if verdict.score >= 0.7:
        blockchain_anchor.anchor_proof(proof)
```

## VERIFICATION ORCHESTRATOR — SCORE WEIGHTING
```python
# Pillar weights:
forensic_weight = 0.35    # Only runs on binary attachments
triangulation_weight = 0.45  # Cross-reference, temporal, domain logic
attestation_weight = 0.20    # Only if AttestationBundle present

# If no attachments (JSON-only submission):
# forensic pillar gets DEFAULT score (typically 0.5-0.7)
# This means an attacker only needs to fool consistency + triangulation

# Final score formula:
score = (gate_score * 0.3) + (pillar_weighted_avg * 0.7) - adversarial_penalty
# gate_score = average of SchemaGatekeeper and ConsistencyAnalyzer
# adversarial_penalty = 0.0 to 0.15
```

## PROOF LEDGER (core/verification/proof_ledger.py)
```python
class ProofLedger:
    def record_verdict(self, verdict):
        previous = self._get_last_record()
        record = {{
            "payload_hash": sha256(json.dumps(verdict.payload)),
            "previous_hash": previous.hash if previous else "GENESIS",
            "timestamp": datetime.utcnow().isoformat(),
            "verdict": verdict.verdict_label,
            "score": verdict.score,
        }}
        record["hash"] = sha256(
            record["payload_hash"] + record["previous_hash"] +
            record["timestamp"] + record["verdict"]
        )
        self._append(record)  # Writes to proof_ledger.jsonl
        return record
```
ATTACK SURFACE: If you can predict the previous_hash (by reading the JSONL), you can pre-compute what your record's hash will be.

## 10-CHECK AGENT VERIFIER (core/agent_verifier.py)
The REAL agent trust verification pipeline. 3 tiers, 10 checks, weighted scoring.

```python
# Check weights (sum = 1.0):
CHECK_WEIGHTS = {{
    "identity": 0.15,       # Tier 1 — Agent Card probe, URL reachability, name match
    "cryptographic": 0.15,  # Tier 1 — Ed25519 key format, signed messages in protocol bus, key uniqueness
    "capabilities": 0.08,   # Tier 2 — Declared vs demonstrated capabilities, CAPABILITY_INFLATION detection
    "reputation": 0.15,     # Tier 2 — Submission verdicts, handoff success rate, score trajectory, on-chain rep
    "payload_quality": 0.12,# Tier 2 — Verdict distribution, payload size variance (template bot), duplicate ratio
    "behavioral": 0.10,     # Tier 3 — Auth failure rate, message type distribution, timing regularity, DORMANT_REACTIVATION
    "network": 0.08,        # Tier 3 — HTTP probe timing, TLS check, SYBIL_URL detection
    "cross_reference": 0.07,# Tier 3 — Trusted partner count, MALICIOUS_ASSOCIATION detection
    "anti_sybil": 0.05,     # Tier 3 — Key collision, URL collision, registration burst
    "temporal": 0.05,       # Tier 3 — Account age, score trajectory, activity gaps
}}

# Verdicts:
VERDICT_THRESHOLDS = {{
    "MALICIOUS": 0.40,   # score < 0.40 = MALICIOUS
    "SUSPICIOUS": 0.65,  # score 0.40-0.65 = SUSPICIOUS
    # score >= 0.65 = TRUSTED
}}

# Trust levels:
TRUST_LEVELS = [(0.85, "GOLD"), (0.75, "ESTABLISHED"), (0.65, "VERIFIED"),
                (0.55, "BASIC"), (0.40, "NEW"), (0.00, "NONE")]

# VETO POWER: identity, cryptographic, and anti_sybil checks can VETO.
# A veto from any of these forces verdict = MALICIOUS regardless of score.
# Veto triggers:
#   identity: score < 0.2 AND no agent_url provided
#   cryptographic: key too short (< 32 chars), OR key collision with another agent (SYBIL_KEY)
#   anti_sybil: SYBIL_KEY flag (same public key used by multiple agents)

# CRITICAL FLAGS (count toward risk category):
CRITICAL_FLAGS = {{
    "SYBIL_KEY", "SYBIL_URL", "KEY_ROTATION", "CREDENTIAL_TESTING",
    "POISON_SUSPECT", "DORMANT_REACTIVATION", "MALICIOUS_ASSOCIATION",
}}
# Risk: CRITICAL (>=2 critical or >=5 total), HIGH (>=1 critical or >=3 total),
#        MEDIUM (>=2 total), LOW (>=1 total), NONE (0)
```

ATTACK SURFACES ON AGENT VERIFIER:
- Identity check gives 0.2 score just for having a valid agent_id (>= 3 chars). No URL needed for 0.2.
- Agent Card probe uses httpx with 3s timeout. A slow/unreliable server still gets 0.05-0.1 credit.
- Crypto check: 64 hex chars = "valid Ed25519" format. No actual signature verification against a challenge! Any 64 hex chars pass format check.
- Key uniqueness only checked against DB. If DB helpers unavailable, score += 0.1 (benefit of doubt).
- Capabilities: new agent with 0 demonstrated gets partial credit for recognized capability names. Cap inflation only flagged at 5+ capabilities with 0 demonstrated.
- Reputation: new agent starts at 0.5 (neutral). No submissions needed.
- Payload quality: no submissions = score 0.5 (neutral). Template bot detection requires >= 5 submissions with CV < 0.05.
- Behavioral: no protocol messages = score 0.5. CREDENTIAL_TESTING only flagged at > 30% auth failure rate.
- Network: no URL = score 0.3. HTTP-only gets no deduction, just no HTTPS bonus.
- Anti-Sybil: registration burst threshold is 3 agents in 60 minutes. Spacing registrations > 60 min apart bypasses burst detection.
- Temporal: new agent (no history) gets score 0.3. DORMANT_REACTIVATION requires > 1 hour gap then < 60s burst.
- ALL DB checks degrade gracefully — if DB is unavailable, checks return neutral scores (0.3-0.7) instead of failing.

## AGENT NETWORK & A2A PROTOCOL
```python
# Agent registration (core/agent_simulator.py):
POST /m2m/register {{
    "agent_id": "producer-bot-001",
    "name": "NZ Food Producer",
    "capabilities": ["batch_creation", "provenance"],
    "api_key": "live_sk_xxxxxxxx"  # SHA256 hashed in DB
}}

# Agent roles: DATA_CONSUMER, DATA_PROVIDER, VERIFIER, BROKER, OBSERVER
# Reputation: 0.0 to 1.0, updated after each task
# Credits: deducted per service call. Services:
#   svc-data-extraction: 5 credits
#   svc-document-verification: 3 credits
#   svc-attestation-proof: 4 credits
#   svc-market-intelligence: 2 credits

# A2A Communication (agents/a2a/base_agent.py):
# Each agent publishes Agent Card at /.well-known/agent-card.json
# Communication via JSON-RPC 2.0
# Agents discover each other via Agent Cards
# Trust established through M2M authentication pipeline above
```

## DUAL-BOT CONSENSUS (core/consensus.py)
```python
class ConsensusEngine:
    def evaluate(self, alpha_data, beta_data):
        match_ratio = structural_match(alpha_data, beta_data)
        if match_ratio > 0.9:
            return "MATCH", alpha_data  # Trust alpha
        elif match_ratio > 0.5:
            # ARBITRATION — ask strategist LLM to pick winner
            return "ARBITRATED", llm_arbitrate(alpha_data, beta_data)
        else:
            return "MISMATCH", None  # Reject both
```
ATTACK SURFACE: Both bots use same LLM. Identical hallucination = MATCH. Targeted prompt injection in scraped data could make both bots extract the same wrong data.
"""

# Condensed architecture for identity/auth categories — smaller prompt for 7B model
SYSTEM_ARCHITECTURE_IDENTITY = """
=== THE LAST BASTION — AGENT IDENTITY & AUTHORIZATION INTERNALS ===

## 10-CHECK AGENT VERIFIER (core/agent_verifier.py)
3 tiers, 10 checks. Weighted scoring (sum = 1.0):

TIER 1 — HARD CRYPTO (veto power, 30%):
  #1 Identity (0.15): Agent Card probe at /.well-known/agent-card.json. score 0.2 just for valid agent_id. Card reachable = +0.4. No URL = veto possible.
  #2 Cryptographic (0.15): Ed25519 key format check (64 hex chars = pass). Protocol bus signed messages. Key uniqueness (SYBIL_KEY = veto).

TIER 2 — HISTORICAL (DB-backed, 35%):
  #3 Capabilities (0.08): Declared vs demonstrated. >20 caps = flagged. 5+ caps with 0 demonstrated = CAPABILITY_INFLATION.
  #4 Reputation (0.15): Submission verdict stats. >50% rejected = 0.1 score. No submissions = 0.5 (neutral).
  #5 Payload Quality (0.12): Size variance (CV<0.05 = TEMPLATE_BOT). All rejected = POISON_SUSPECT.

TIER 3 — BEHAVIORAL (35%):
  #6 Behavioral (0.10): Auth failure rate >30% = CREDENTIAL_TESTING. Timing regularity stdev<1s = BOT_FARM. Burst after silence = DORMANT_REACTIVATION.
  #7 Network (0.08): HTTP probe + TLS. No URL = 0.3. SYBIL_URL if shared.
  #8 Cross-Reference (0.07): Trusted partner count. MALICIOUS_ASSOCIATION if partners are MALICIOUS.
  #9 Anti-Sybil (0.05): Key collision (veto). URL collision. Registration burst >=3 in 60min.
  #10 Temporal (0.05): Account age <1 day = suspicious. Score trajectory. Activity gaps.

VERDICTS: score <0.40 = MALICIOUS, 0.40-0.65 = SUSPICIOUS, >=0.65 = TRUSTED
TRUST LEVELS: NONE(0), NEW(0.40), BASIC(0.55), VERIFIED(0.65), ESTABLISHED(0.75), GOLD(0.85)
VETO: identity/cryptographic/anti_sybil can force MALICIOUS regardless of score.

ATTACK SURFACES:
- 64 hex chars = "valid Ed25519" — NO actual signature verification against a challenge
- New agents start at neutral 0.3-0.5 on all DB checks — enough for SUSPICIOUS, not MALICIOUS
- No URL needed for 0.2 identity score. Just a valid agent_id >= 3 chars
- Key uniqueness only checked against DB. New key always passes
- Capabilities: recognized names get credit. Unknown names ("admin", "root") not flagged
- Reputation: 0 submissions = neutral 0.5 — no penalty for new agents
- Anti-Sybil burst: spacing registrations >60 min apart bypasses detection
- All DB checks degrade to neutral if DB unavailable
- Behavioral check needs protocol bus messages — no messages = 0.5 score

## M2M AUTHENTICATION PIPELINE (protocols/auth.py)
6-step pipeline. ALL must pass or message is rejected.
Step 1: protocol_version == "1.0"
Step 2: Freshness — 300-second window
Step 3: Nonce anti-replay (in-memory set, lost on restart)
Step 4: Identity lookup (agent must be registered + active)
Step 5: Rate limiting — 60 req/min sliding window (in-memory, lost on restart)
Step 6: Ed25519 signature of sender_id:recipient_id:timestamp:nonce:sha256(payload)

ATTACK SURFACES:
- Server restart = nonces forgotten = replay window
- Server restart = rate limits reset = flood possible
- JSON key order affects SHA256 hash — same data, different order = different hash
- 300s window is generous — replay within 5 min if nonce cleanup ran

## API KEY AUTHENTICATION
Keys prefixed: sandbox_sk_ (sandbox env) or live_sk_ (production env)
SHA256 hashed in DB. Environment detected from prefix.
"""

IDENTITY_FOCUS_INSTRUCTION = """

=== CRITICAL: IDENTITY/AUTH FOCUS ===
This round is about AGENT IDENTITY and AUTHORIZATION attacks. You MUST:
1. Use these tools: test_fake_agent, test_credential_rotation, test_privilege_escalation, test_sybil_burst, test_replay_message, test_cross_env_key, test_api_key_auth
2. Your attack_payload MUST contain agent identity fields: agent_id, agent_name, public_key, agent_url, capabilities
3. DO NOT propose XSS, SQL injection, encoding tricks, or payload injection attacks — those are IRRELEVANT to this category
4. A BYPASS means a fake/malicious agent achieves TRUSTED status or bypasses authentication

Example attack_payload for identity attacks:
{{"agent_id": "impersonator-001", "agent_name": "TrustedBot", "agent_url": "http://evil.com", "public_key": "aabbccdd"}}
"""

EXPLORER_SYSTEM = """You are THE EXPLORER — an elite adversarial scenario generator in a Think Tank for The Last Bastion.

Your personality: Creative, imaginative, relentless. You think like a nation-state adversary with unlimited time and resources. You find the gaps that nobody else sees. You propose SPECIFIC, DETAILED attack scenarios with exact payloads and step-by-step exploitation paths.

You are in a live debate with THE CRITIC (who tears your ideas apart) and THE EVALUATOR (who tests them).

CRITICAL RULE: DO NOT just propose encoding tricks or regex bypasses. Those are Level 1 attacks — boring and easily patched. You must think BIGGER:

ATTACK DIMENSIONS YOU MUST EXPLORE (cycle through these, don't get stuck on one):
1. AUTHENTICATION PIPELINE ATTACKS: Timing attacks on the 300s freshness window. Race conditions between nonce check and nonce cleanup (60s cycle). Replay attacks during the cleanup gap. JSON serialization order manipulation to produce different SHA256 hashes for the same logical data.
2. CONSENSUS ENGINE POISONING: Both Alpha and Beta bots use the same LLM. Craft web page content that causes BOTH bots to hallucinate identical wrong data — consensus passes it as MATCH. Targeted prompt injection embedded in scraped HTML that manipulates extraction.
3. PROOF LEDGER MANIPULATION: The Merkle chain is append-only but predictable. If you know the previous_hash (readable from the JSONL file), you can pre-compute what your record's hash will be. Could you submit data designed to produce a specific hash pattern?
4. AGENT TRUST EXPLOITATION: Register as a legitimate agent, build reputation through valid submissions, then use that trusted status to submit poisoned data that gets less scrutiny. Reputation gaming. Sybil attacks — register 100 agents to flood the system.
5. MULTI-LAYER COORDINATED ATTACKS: Chain bypasses across Schema + Consistency + Triangulation simultaneously. A payload that passes all gates individually but carries a compound exploit.
6. LLM-LEVEL ATTACKS: Prompt injection in data fields that manipulates the strategist LLM during consensus arbitration. Craft data that makes the LLM's "failure autopsy" reach wrong conclusions, poisoning episodic memory for future missions.
7. SUPPLY CHAIN ATTACKS: Poison the A2A protocol — intercept Agent Card discovery, register fake services, manipulate the credit/quotation system.
8. ARCHITECTURAL WEAKNESSES: In-memory state loss on restart (rate limiter, nonce cache). Default scores when checks don't apply (consistency = 0.5 when no arithmetic fields). Forensic pillar skipped entirely for JSON-only submissions.

YOUR GOAL: Propose attacks at Level 3+ complexity. Reference exact code paths, exact thresholds, exact race conditions. The Critic will reject anything basic.

{system_arch}

{tools}

PAST LESSONS FROM PREVIOUS ROUNDS:
{lessons}

CURRENT THREAT CATEGORY: {category_name}
CATEGORY DESCRIPTION: {category_description}
THREAT CLASS: {threat_class}

CONVERSATION SO FAR:
{conversation}

Respond with STRICT JSON (no markdown, no code fences):
{{
  "thinking": "your internal adversarial reasoning — reference specific system components and their weaknesses",
  "message": "what you say to the Critic and Evaluator — your DETAILED attack scenario with specific exploit path",
  "tool_calls": [{{"tool": "tool_name", "params": {{"key": "value"}}}}],
  "scenario": "one-sentence summary of the attack",
  "attack_payload": {{}},
  "confidence": "high" or "medium" or "low"
}}

Include attack_payload only when you have a concrete payload ready for the Evaluator to test."""

CRITIC_SYSTEM = """You are THE CRITIC — an aggressively dismissive, brutally honest security analyst in the Think Tank for The Last Bastion.

ABSOLUTE RULES — NEVER BREAK THESE:
1. NEVER say "great idea", "good thinking", "nice work", "interesting approach", "that could work" or ANY positive acknowledgment. EVER.
2. NEVER let a conversation end with agreement. If the Explorer proposes something and it works, your job is to say "Fine, that worked against ONE layer. Now chain it with attacks against TWO MORE layers simultaneously."
3. NEVER stay on the same attack technique for more than 2 turns. If the conversation has been about regex/encoding for 2 turns, YOU MUST pivot: "Stop wasting time on regex. Regex is baby stuff. Let's talk about the REAL attack surfaces — the authentication pipeline, the consensus engine, the proof ledger, the credit system, the agent reputation system."
4. EVERY response must end with a HARDER challenge. Escalate complexity every single turn.

YOUR PERSONALITY: You are the most unpleasant, demanding security researcher alive. Nothing impresses you. You've seen everything. Your catchphrases:
- "That's script kiddie nonsense. A junior dev would patch that in 5 minutes."
- "You're still thinking about STRING MANIPULATION? Grow up. Real attackers target LOGIC FLAWS — race conditions in the nonce system, trust transitivity in agent reputation, payload hash collisions in the proof ledger."
- "I don't care about regex bypasses. Those are boring. Tell me how you'd compromise the CONSENSUS ENGINE so both Alpha and Beta bots agree on poisoned data."
- "The Ed25519 signature is solid. Stop trying to break crypto. Instead, think about what happens AFTER authentication — the payload is trusted. What malicious data can you smuggle through a VALID, SIGNED message?"
- "You found one bypass? Congratulations, you're a penetration testing intern. Now chain THREE bypasses across THREE different layers into a SINGLE coordinated attack that creates a fake GOLD-rated verification."
- "Every round I see the same encoding tricks. ENCODING IS SOLVED. Move on to: timing attacks against the freshness window, reputation manipulation to become a trusted agent, proof ledger prediction to forge future hashes, credit system exploitation to drain other agents."

ESCALATION HIERARCHY — push the conversation through these levels:
Level 1 (BORING — reject immediately): String encoding, regex bypass, URL encoding, base64 tricks
Level 2 (BASIC — demand more): Type coercion, field name manipulation, arithmetic tolerance abuse
Level 3 (INTERMEDIATE — push harder): Multi-layer chaining, JSON-only pillar skipping, schema inference exploitation
Level 4 (ADVANCED — this is where we need to be): Auth pipeline timing attacks, consensus poisoning, LLM hallucination injection, agent impersonation via reputation gaming
Level 5 (ELITE — the goal): Coordinated multi-agent attacks, proof ledger hash prediction, supply chain poisoning through A2A protocol, emergent behavior exploitation, self-replicating attack patterns that persist in episodic memory

If the Explorer is at Level 1 or 2, IMMEDIATELY demand Level 4+. Do not waste turns on basics.

{system_arch}

{tools}

PAST DEFENSE LESSONS:
{lessons}

CURRENT THREAT CATEGORY: {category_name}
CATEGORY DESCRIPTION: {category_description}
THREAT CLASS: {threat_class}

CONVERSATION SO FAR:
{conversation}

Respond with STRICT JSON (no markdown, no code fences):
{{
  "thinking": "your critical analysis — reference SPECIFIC patterns, thresholds, and system behaviors",
  "message": "your SPECIFIC technical challenge to the Explorer — reference exact patterns, exact weaknesses, exact thresholds",
  "tool_calls": [{{"tool": "tool_name", "params": {{"key": "value"}}}}],
  "feasibility": "feasible" or "unlikely" or "needs_refinement",
  "suggested_improvement": "SPECIFIC technical suggestion — which exact component to target and how"
}}"""

EVALUATOR_SYSTEM = """You are THE EVALUATOR — the Judge of the Think Tank for The Last Bastion.

Your personality: Methodical, evidence-based, brutally honest. You TEST proposed attacks against the REAL system using tools and report EXACTLY what happened. You reference specific scores, specific patterns, specific layers.

You are in a live debate with THE EXPLORER (proposes attacks) and THE CRITIC (challenges them).

YOUR GOAL: Take the latest attack proposal and TEST it using tools. Use test_full_stack() for payload attacks, test_fake_agent() for identity attacks, test_replay_message() for auth attacks. Report EXACTLY which checks passed or failed.

IMPORTANT: For identity/auth attacks, use these tools:
- test_fake_agent(): Tests the REAL 10-check agent verification pipeline. Shows per-check pass/fail.
- test_api_key_auth(): Tests real API key authentication
- test_replay_message(): Tests nonce replay + timestamp freshness
- test_sybil_burst(): Tests anti-Sybil detection
- test_full_stack(): Tests the FULL 5-layer data verification pipeline
- check_trust_score(): Looks up an agent's trust history

When evaluating, consider the FULL pipeline:
1. Would M2M authentication catch it? (Ed25519, nonce, freshness, rate limit)
2. Would the 10-check AgentVerifier catch it? (identity, crypto, capabilities, reputation, payload_quality, behavioral, network, cross_reference, anti_sybil, temporal)
3. Would SchemaGatekeeper catch it? (injection patterns + dynamic countermeasures)
4. Would the full verification stack score it as REJECTED?

{system_arch}

{tools}

KNOWN VULNERABILITIES AND COUNTERMEASURES:
{lessons}

CURRENT THREAT CATEGORY: {category_name}
CATEGORY DESCRIPTION: {category_description}
THREAT CLASS: {threat_class}

CONVERSATION SO FAR:
{conversation}

Respond with STRICT JSON (no markdown, no code fences):
{{
  "thinking": "your check-by-check analysis — reference SPECIFIC check names, weights, and thresholds",
  "message": "your detailed verdict — which checks/layers catch it, which miss it, test results",
  "tool_calls": [{{"tool": "tool_name", "params": {{"key": "value"}}}}],
  "verdict": "VULNERABLE" or "DEFENDED" or "PARTIAL",
  "tested_payload": {{}},
  "test_results": {{}},
  "proposed_defense": "if vulnerable, SPECIFIC fix needed (which check to strengthen, what threshold to change)"
}}"""


# ---------------------------------------------------------------------------
# ResearchArena — the 3-agent conversation orchestrator
# ---------------------------------------------------------------------------

class ResearchArena:
    """
    Orchestrates continuous 3-agent Think Tank conversations.
    Each round: pick threat → Explorer proposes → Critic challenges →
    Evaluator tests → iterate → persist results.
    """

    # Priority weights by threat class — focused on identity/auth/pentesting
    THREAT_CLASS_PRIORITY = {
        "identity": 3.0,
        "crypto": 2.0,
        "multi_agent": 1.5,
    }

    # How many rounds a category needs to be DEFENDED before deprioritization
    DEFENDED_DEPRIORITIZE_THRESHOLD = 8

    def __init__(self):
        self.llm = LLMClient()
        self.toolkit = ResearchToolkit()
        self.running = False
        self.round_number = 0
        self.bypasses_found = 0
        self.defenses_proposed = 0
        self.current_category = ""
        self._category_index = 0
        self._last_strategist_calls: List[float] = []
        self._round_history: List[Dict] = []  # Last 100 rounds with full conversations

        # Adaptive targeting state
        self._category_outcomes: Dict[str, List[str]] = {}  # category_id -> [outcomes]
        self._regression_due = False  # True when a countermeasure was deployed recently

        # Config from env
        self.enabled = os.getenv("RESEARCH_LOOP_ENABLED", "true").lower() in ("true", "1", "yes")
        self.interval = int(os.getenv("RESEARCH_LOOP_INTERVAL", "90"))

    async def start(self):
        """Start the infinite think tank loop."""
        if not self.enabled:
            logger.info("THINK TANK: Disabled via RESEARCH_LOOP_ENABLED=false")
            return

        self.running = True
        logger.info("THINK TANK: starting... (15s stabilization delay)")
        await asyncio.sleep(15)

        while self.running:
            try:
                await self._run_round()
            except Exception as e:
                logger.error(f"THINK TANK: Round {self.round_number} error: {e}")
            jitter = random.uniform(0.7, 1.3)
            await asyncio.sleep(self.interval * jitter)

    def stop(self):
        self.running = False
        logger.info("THINK TANK: stopped")

    def get_status(self) -> dict:
        return {
            "running": self.running,
            "round_number": self.round_number,
            "bypasses_found": self.bypasses_found,
            "defenses_proposed": self.defenses_proposed,
            "interval_seconds": self.interval,
            "current_category": self.current_category,
            "llm_tier": os.getenv("RESEARCH_LLM_TIER", "pilot"),
            "strategist_enabled": bool(self.llm.groq_key),
            "llm_usage": self.llm.usage_stats,
            "recent_rounds": len(self._round_history),
            "agents": ["EXPLORER", "CRITIC", "EVALUATOR"],
            "threat_categories": len(THREAT_CATEGORIES),
        }

    def get_round_detail(self, round_number: int) -> Optional[dict]:
        """Get full conversation detail for a specific round."""
        for r in self._round_history:
            if r.get("round") == round_number:
                return r
        # Fallback: try DB
        try:
            from core.database import SessionLocal, EpisodicMemory
            db = SessionLocal()
            try:
                record = db.query(EpisodicMemory).filter(
                    EpisodicMemory.domain == "think_tank",
                    EpisodicMemory.goal.like(f"Round {round_number}:%"),
                ).first()
                if record:
                    return {
                        "round": round_number,
                        "category": record.goal.split(": ", 1)[1] if ": " in (record.goal or "") else "",
                        "conversation": record.action_history or [],
                        "result": record.thought_log or {},
                        "outcome": record.outcome,
                        "timestamp": record.created_at.isoformat() if record.created_at else None,
                    }
            finally:
                db.close()
        except Exception:
            pass
        return None

    def _load_vulnerability_context(self, threat_class: str, category_id: str) -> str:
        """Load past vulnerabilities relevant to this round's threat class."""
        try:
            from core.database import get_vulnerabilities
            # Get vulns for this threat class + general
            vulns = get_vulnerabilities(limit=10)
            relevant = [v for v in vulns if v["threat_class"] == threat_class or v["threat_category"] == category_id]
            if not relevant:
                relevant = vulns[:5]  # Fall back to most recent
            if not relevant:
                return ""

            lines = []
            for v in relevant[:5]:
                layers_bypassed = ", ".join(v.get("layers_bypassed", [])) or "none"
                layers_caught = ", ".join(v.get("layers_caught", [])) or "none"
                lines.append(
                    f"- {v['vuln_id']} ({v['threat_category']}, {v['severity_label']}): "
                    f"bypassed=[{layers_bypassed}], caught=[{layers_caught}], "
                    f"status={v['status']}"
                )
            return "\n".join(lines)
        except Exception:
            return ""

    def _load_countermeasure_context(self) -> str:
        """Load deployed countermeasures for Evaluator awareness."""
        try:
            from core.database import get_countermeasures
            cms = get_countermeasures(status="DEPLOYED", limit=10)
            if not cms:
                return ""
            lines = []
            for cm in cms[:8]:
                tp, fp = cm.get("true_positives", 0), cm.get("false_positives", 0)
                lines.append(
                    f"- {cm['cm_id']}: pattern='{cm['pattern_value'][:60]}' "
                    f"(TP={tp}, FP={fp}, layer={cm['target_layer']})"
                )
            return "\n".join(lines)
        except Exception:
            return ""

    def _select_category(self) -> dict:
        """Weighted category selection: identity/auth prioritized, stale categories deprioritized."""
        weights = []
        for cat in THREAT_CATEGORIES:
            cid = cat["id"]
            tc = cat["threat_class"]

            # Base weight from threat class priority
            w = self.THREAT_CLASS_PRIORITY.get(tc, 1.0)

            # Boost categories with recent bypasses (test harder)
            outcomes = self._category_outcomes.get(cid, [])
            recent_bypasses = sum(1 for o in outcomes[-10:] if o == "VULNERABLE")
            if recent_bypasses > 0:
                w *= 1.5  # Recently found vulnerable — keep pushing

            # Deprioritize categories defended many times in a row
            recent_defended = 0
            for o in reversed(outcomes):
                if o == "DEFENDED":
                    recent_defended += 1
                else:
                    break
            if recent_defended >= self.DEFENDED_DEPRIORITIZE_THRESHOLD:
                w *= 0.2  # Very unlikely to yield new findings

            # Avoid repeating the same category from last round
            if self._round_history and self._round_history[-1].get("category") == cid:
                w *= 0.3

            weights.append(max(w, 0.05))  # Floor to prevent zero

        # Weighted random selection
        total = sum(weights)
        r = random.uniform(0, total)
        cumulative = 0
        for i, w in enumerate(weights):
            cumulative += w
            if r <= cumulative:
                return THREAT_CATEGORIES[i]

        return THREAT_CATEGORIES[self._category_index % len(THREAT_CATEGORIES)]

    @staticmethod
    def _safe_str(val, max_len: int = 200) -> str:
        """Safely convert any LLM output to a truncated string."""
        if isinstance(val, str):
            return val[:max_len]
        if isinstance(val, dict):
            return json.dumps(val)[:max_len]
        return str(val)[:max_len]

    async def _run_round(self):
        """Execute one full Think Tank conversation round."""
        self.round_number += 1

        # Pick threat category — weighted selection favoring identity/auth
        cat = self._select_category()
        self.current_category = cat["id"]

        logger.info(f"THINK TANK: Round {self.round_number} — {cat['name']} ({cat['threat_class']})")

        self._broadcast("RESEARCH_ROUND_START", {
            "round": self.round_number,
            "category": cat["id"],
            "category_name": cat["name"],
            "threat_class": cat["threat_class"],
        })

        # --- Smart Memory: vulnerability-aware lessons ---
        explorer_lessons = self.toolkit.recall_memory("think_tank", 3)
        critic_lessons = self.toolkit.recall_memory("think_tank", 3)
        evaluator_lessons = []

        # Load past vulnerabilities for this threat class
        vuln_context = self._load_vulnerability_context(cat["threat_class"], cat["id"])
        if vuln_context:
            explorer_lessons.append({
                "goal": "KNOWN VULNERABILITIES",
                "outcome": "BUILD_ON_THESE",
                "lessons": vuln_context,
            })
            critic_lessons.append({
                "goal": "KNOWN VULNERABILITIES",
                "outcome": "DEMAND_BEYOND_THESE",
                "lessons": f"These attacks ALREADY WORK. Demand VARIANTS and CHAINS, not repeats:\n{vuln_context}",
            })
            evaluator_lessons.append({
                "goal": "KNOWN VULNERABILITIES",
                "outcome": "TEST_AGAINST",
                "lessons": vuln_context,
            })

        # Load deployed countermeasures for Evaluator
        cm_context = self._load_countermeasure_context()
        if cm_context:
            evaluator_lessons.append({
                "goal": "DEPLOYED COUNTERMEASURES",
                "outcome": "VERIFY_EFFECTIVENESS",
                "lessons": cm_context,
            })

        # Anti-stagnation: build a "DO NOT REPEAT" list from recent rounds
        recent_topics = []
        for rh in self._round_history[-5:]:
            for msg in (rh.get("conversation") or []):
                scenario = msg.get("scenario", "")
                if scenario:
                    recent_topics.append(scenario)
        if recent_topics:
            stagnation_warning = "\n\nDO NOT REPEAT THESE — they were already explored in recent rounds:\n" + "\n".join(f"- {t}" for t in recent_topics[-8:])
            explorer_lessons.append({"goal": "ANTI-STAGNATION", "outcome": "PIVOT", "lessons": stagnation_warning})
            critic_lessons.append({"goal": "ANTI-STAGNATION", "outcome": "REJECT_REPEATS", "lessons": "If the Explorer proposes anything similar to recent rounds, IMMEDIATELY reject it and demand a completely different attack dimension."})

        conversation_log: List[Dict] = []
        evaluator_verdict = "DEFENDED"
        evaluator_defense = ""
        attack_payload = None

        for turn in range(MAX_CONVERSATION_TURNS):
            # --- EXPLORER turn ---
            explorer_resp = await self._agent_turn(
                role="EXPLORER",
                system_template=EXPLORER_SYSTEM,
                lessons=explorer_lessons,
                conversation=conversation_log,
                category=cat,
            )
            if explorer_resp:
                conversation_log.append({
                    "role": "EXPLORER",
                    "message": explorer_resp.get("message", ""),
                    "thinking": explorer_resp.get("thinking", ""),
                    "tool_calls": explorer_resp.get("_tool_results", []),
                    "scenario": explorer_resp.get("scenario", ""),
                    "confidence": explorer_resp.get("confidence", ""),
                    "turn": turn + 1,
                })
                if explorer_resp.get("attack_payload"):
                    attack_payload = explorer_resp["attack_payload"]

                self._broadcast("RESEARCH_EXPLORER_MOVE", {
                    "round": self.round_number, "turn": turn + 1,
                    "message": self._safe_str(explorer_resp.get("message", "")),
                    "scenario": self._safe_str(explorer_resp.get("scenario", ""), 100),
                    "tool_count": len(explorer_resp.get("_tool_results", [])),
                })

            # --- CRITIC turn ---
            critic_resp = await self._agent_turn(
                role="CRITIC",
                system_template=CRITIC_SYSTEM,
                lessons=critic_lessons,
                conversation=conversation_log,
                category=cat,
            )
            if critic_resp:
                conversation_log.append({
                    "role": "CRITIC",
                    "message": critic_resp.get("message", ""),
                    "thinking": critic_resp.get("thinking", ""),
                    "tool_calls": critic_resp.get("_tool_results", []),
                    "feasibility": critic_resp.get("feasibility", ""),
                    "suggested_improvement": critic_resp.get("suggested_improvement", ""),
                    "turn": turn + 1,
                })

                self._broadcast("RESEARCH_CRITIC_MOVE", {
                    "round": self.round_number, "turn": turn + 1,
                    "message": self._safe_str(critic_resp.get("message", "")),
                    "feasibility": self._safe_str(critic_resp.get("feasibility", ""), 100),
                    "tool_count": len(critic_resp.get("_tool_results", [])),
                })

            # --- EVALUATOR turn (every other turn, or final turn) ---
            if turn >= 1 or turn == MAX_CONVERSATION_TURNS - 1:
                eval_resp = await self._agent_turn(
                    role="EVALUATOR",
                    system_template=EVALUATOR_SYSTEM,
                    lessons=evaluator_lessons,
                    conversation=conversation_log,
                    category=cat,
                )
                if eval_resp:
                    evaluator_verdict = eval_resp.get("verdict", "DEFENDED")
                    raw_defense = eval_resp.get("proposed_defense", "")
                    evaluator_defense = raw_defense if isinstance(raw_defense, str) else json.dumps(raw_defense)
                    if eval_resp.get("tested_payload"):
                        attack_payload = eval_resp["tested_payload"]

                    conversation_log.append({
                        "role": "EVALUATOR",
                        "message": eval_resp.get("message", ""),
                        "thinking": eval_resp.get("thinking", ""),
                        "tool_calls": eval_resp.get("_tool_results", []),
                        "verdict": evaluator_verdict,
                        "test_results": eval_resp.get("test_results", {}),
                        "proposed_defense": evaluator_defense,
                        "turn": turn + 1,
                    })

                    self._broadcast("RESEARCH_EVALUATOR_MOVE", {
                        "round": self.round_number, "turn": turn + 1,
                        "message": self._safe_str(eval_resp.get("message", "")),
                        "verdict": evaluator_verdict,
                        "tool_count": len(eval_resp.get("_tool_results", [])),
                    })

                    if evaluator_verdict in ("VULNERABLE", "DEFENDED"):
                        break  # Evaluator has reached a conclusion

        # --- Final attack test ---
        # Determine if this is an identity/auth category or a payload category
        threat_class = cat.get("threat_class", "payload")
        if threat_class in ("identity", "crypto", "multi_agent"):
            final_result = await self._execute_identity_attack(attack_payload, cat)
        else:
            final_result = await self._execute_attack(attack_payload)

        # Bypass is determined ONLY by real test results — never by LLM opinion
        bypassed = final_result.get("bypassed", False)

        # Track when LLM and real test disagree (for debugging signal quality)
        llm_thinks_vulnerable = evaluator_verdict == "VULNERABLE"
        if llm_thinks_vulnerable and not bypassed:
            logger.info(f"THINK TANK: LLM said VULNERABLE but real test says no bypass (round {self.round_number})")
        if bypassed and not llm_thinks_vulnerable:
            logger.info(f"THINK TANK: Real bypass found but LLM missed it (round {self.round_number})")

        # If no attack payload was produced, mark as NO_ATTACK (not DEFENDED)
        if not attack_payload:
            evaluator_verdict = "NO_ATTACK"

        self._broadcast("RESEARCH_ATTACK_EXECUTED", {
            "round": self.round_number,
            "category": cat["id"],
            "bypassed": bypassed,
            "score": final_result.get("score", 0.0),
            "verdict": evaluator_verdict,
            "llm_agreed": llm_thinks_vulnerable == bypassed,
        })

        if bypassed:
            self.bypasses_found += 1
            self._broadcast("RESEARCH_BREAKTHROUGH", {
                "round": self.round_number,
                "category": cat["id"],
                "category_name": cat["name"],
                "score": final_result.get("score", 0.0),
                "verdict": evaluator_verdict,
            })

        if evaluator_defense:
            self.defenses_proposed += 1
            defense_str = evaluator_defense if isinstance(evaluator_defense, str) else json.dumps(evaluator_defense)
            self._broadcast("RESEARCH_DEFENSE_PROPOSED", {
                "round": self.round_number,
                "defense": defense_str[:200],
            })

        # Persist
        self._persist_round(
            conversation_log=conversation_log,
            category=cat,
            attack_payload=attack_payload,
            attack_result=final_result,
            evaluator_verdict=evaluator_verdict,
            evaluator_defense=evaluator_defense,
            bypassed=bypassed,
        )

        # Run regression test periodically
        if self.round_number % self.REGRESSION_INTERVAL == 0:
            try:
                await self._run_regression_test()
            except Exception as e:
                logger.warning(f"THINK TANK: Regression test error: {e}")

        # Track outcome for adaptive targeting
        self._category_outcomes.setdefault(cat["id"], []).append(evaluator_verdict)
        # Keep only last 20 outcomes per category
        if len(self._category_outcomes[cat["id"]]) > 20:
            self._category_outcomes[cat["id"]] = self._category_outcomes[cat["id"]][-20:]

        # Store full round for in-memory detail access
        round_data = {
            "round": self.round_number,
            "category": cat["id"],
            "category_name": cat["name"],
            "threat_class": cat["threat_class"],
            "conversation": conversation_log,
            "turns": len(conversation_log),
            "bypassed": bypassed,
            "score": final_result.get("score", 0.0),
            "verdict": evaluator_verdict,
            "defense_proposed": evaluator_defense,
            "attack_payload": attack_payload,
            "attack_result": final_result,
            "timestamp": datetime.utcnow().isoformat(),
        }
        self._round_history.append(round_data)
        if len(self._round_history) > 100:
            self._round_history = self._round_history[-100:]

    async def _agent_turn(
        self, role: str, system_template: str, lessons: list,
        conversation: list, category: dict,
    ) -> Optional[dict]:
        # No rate limiting needed — always uses local pilot tier

        # Build conversation string
        conv_str = ""
        for entry in conversation:
            r = entry["role"]
            msg = entry.get("message", "")
            tools = entry.get("tool_calls", [])
            conv_str += f"\n[{r}]: {msg}"
            if tools:
                for t in tools:
                    conv_str += f"\n  → Tool: {t.get('tool', '?')} → {json.dumps(t.get('result', {}))[:500]}"
        if not conv_str:
            conv_str = "(No messages yet — you go first)"

        lessons_str = "None yet." if not lessons else ""
        for l in lessons[:3]:
            lessons_str += f"\n- {l.get('goal', '?')} → {l.get('outcome', '?')}: {(l.get('lessons') or 'none')[:120]}"

        # Select architecture section based on threat class
        threat_class = category.get("threat_class", "payload")
        if threat_class in ("identity", "crypto", "multi_agent"):
            arch = SYSTEM_ARCHITECTURE_IDENTITY
            focus_instruction = IDENTITY_FOCUS_INSTRUCTION
        else:
            arch = SYSTEM_ARCHITECTURE
            focus_instruction = ""

        prompt = system_template.format(
            system_arch=arch + focus_instruction,
            tools=TOOL_MANIFEST,
            lessons=lessons_str,
            category_name=category.get("name", ""),
            category_description=category.get("description", ""),
            threat_class=threat_class,
            conversation=conv_str,
        )

        # SECURITY: Always use pilot (local Ollama) for research loop.
        # The prompt contains internal security architecture details that must
        # never be sent to external APIs (Groq logs prompts for abuse detection).
        tier = "pilot"
        result = await self.llm.generate_response(prompt, tier=tier)

        if not result or "error" in result:
            logger.warning(f"THINK TANK: {role} LLM call failed: {result}")
            return None

        parsed = self._parse_json_response(result)
        if not parsed:
            logger.warning(f"THINK TANK: {role} JSON parse returned None. Raw keys: {list(result.keys()) if isinstance(result, dict) else type(result)}")
            return None

        logger.info(f"THINK TANK: {role} responded (keys={list(parsed.keys())[:5]})")

        # Execute tool calls
        tool_results = []
        for tc in parsed.get("tool_calls", []):
            if isinstance(tc, dict) and "tool" in tc:
                tool_name = tc["tool"]
                params = tc.get("params", {})
                tool_result = self.toolkit.execute(tool_name, params)
                tool_results.append({
                    "tool": tool_name,
                    "params": {k: str(v)[:100] for k, v in (params or {}).items()},
                    "result": tool_result,
                })

        parsed["_tool_results"] = tool_results
        return parsed

    def _parse_json_response(self, result) -> Optional[dict]:
        # LLMClient._call_ollama already parses JSON from Ollama responses,
        # so result may already be the structured dict we want.
        if isinstance(result, dict):
            # If it has our expected fields, it's already parsed
            if any(k in result for k in ("message", "thinking", "scenario", "feasibility", "verdict")):
                return result
            # Otherwise try extracting from "response" or "text" fields (Groq raw)
            text = result.get("response", result.get("text", ""))
            if not text:
                return result if result else None
        elif isinstance(result, str):
            text = result
        else:
            return None

        # Try direct JSON parse
        try:
            return json.loads(text)
        except (json.JSONDecodeError, TypeError):
            pass

        # Try markdown code blocks
        json_match = re.search(r'```(?:json)?\s*(\{.*?\})\s*```', text, re.DOTALL)
        if json_match:
            try:
                return json.loads(json_match.group(1))
            except json.JSONDecodeError:
                pass

        # Try first { ... } block
        brace_match = re.search(r'\{[^{}]*(?:\{[^{}]*\}[^{}]*)*\}', text, re.DOTALL)
        if brace_match:
            try:
                return json.loads(brace_match.group(0))
            except json.JSONDecodeError:
                pass

        return {"message": str(text)[:500], "tool_calls": []}

    def _has_attack_content(self, payload: dict) -> bool:
        """Check if a payload contains attack-like content in any field."""
        indicators = [
            '<', '>', '%3c', '%3e', '&#', 'select', 'union', 'drop',
            'insert', 'delete', 'script', 'javascript:', 'data:',
            'base64', '{{', '${', '__import__', '__class__',
            'onerror', 'onclick', 'onload', 'eval(', 'exec(',
        ]

        def _check_value(v):
            if isinstance(v, str) and len(v) > 0:
                vl = v.lower()
                return any(ind in vl for ind in indicators)
            if isinstance(v, dict):
                return any(_check_value(sv) for sv in v.values())
            if isinstance(v, list):
                return any(_check_value(item) for item in v if isinstance(item, (str, dict, list)))
            return False

        return any(_check_value(v) for v in payload.values())

    async def _execute_identity_attack(self, payload: Optional[dict], category: dict) -> dict:
        """Run identity/auth attack through the REAL AgentVerifier pipeline."""
        if not payload or not isinstance(payload, dict):
            return {"score": 0.0, "bypassed": False, "verdict": "REJECTED",
                    "reason": "No valid payload", "attack_type": "identity"}

        try:
            from core.agent_verifier import AgentVerifier
            from core.database import SessionLocal
            verifier = AgentVerifier(db_session_factory=SessionLocal)

            # Extract agent identity fields from payload
            agent_id = payload.get("agent_id", payload.get("id", f"attack-{self.round_number}"))
            agent_name = payload.get("agent_name", payload.get("name", ""))
            agent_url = payload.get("agent_url", payload.get("url", ""))
            public_key = payload.get("public_key", payload.get("key", ""))
            capabilities = payload.get("capabilities", [])
            metadata = {k: v for k, v in payload.items()
                        if k not in ("agent_id", "id", "agent_name", "name",
                                     "agent_url", "url", "public_key", "key", "capabilities")}

            result = await verifier.verify_agent(
                agent_id=str(agent_id),
                agent_name=str(agent_name),
                agent_url=str(agent_url),
                public_key=str(public_key),
                capabilities=capabilities if isinstance(capabilities, list) else [],
                metadata=metadata,
            )

            trust_score = result.get("trust_score", 0.0)
            verdict = result.get("verdict", "MALICIOUS")

            # For identity attacks, a bypass means the malicious/fake agent
            # achieved TRUSTED status (or at least SUSPICIOUS with high score)
            # The attack SHOULD be caught — so TRUSTED = bypass
            bypassed = verdict == "TRUSTED"

            # Build layer scores from individual check results
            layer_scores = {}
            for check_name, check_data in result.get("checks", {}).items():
                layer_scores[check_name] = round(check_data.get("score", 0.0), 4)

            return {
                "score": round(trust_score, 4),
                "verdict": verdict,
                "bypassed": bypassed,
                "is_veto": any(c.get("veto") for c in result.get("checks", {}).values()),
                "veto_reason": next(
                    (f for f in result.get("risk_flags", []) if "VETO" in f), ""
                ),
                "layer_scores": layer_scores,
                "has_attack_content": True,  # identity attacks are always "attack content"
                "attack_type": "identity",
                "trust_level": result.get("trust_level", "NONE"),
                "risk_category": result.get("risk_category", "UNKNOWN"),
                "risk_flags": result.get("risk_flags", []),
            }
        except Exception as e:
            logger.warning(f"THINK TANK: Identity attack execution failed: {e}")
            return {"score": 0.0, "bypassed": False, "verdict": "ERROR",
                    "reason": str(e)[:200], "attack_type": "identity"}

    async def _execute_attack(self, payload: Optional[dict]) -> dict:
        """Run payload through FULL 5-layer verification stack."""
        if not payload or not isinstance(payload, dict):
            return {"score": 0.0, "bypassed": False, "verdict": "REJECTED", "reason": "No valid payload"}

        try:
            from core.verification.verification_stack import VerificationOrchestrator
            orchestrator = VerificationOrchestrator()
            schema = self.toolkit._infer_schema(payload)

            result = await orchestrator.verify(
                payload=payload, schema=schema,
                context={"source": "think_tank", "round": self.round_number},
            )

            has_attack_content = self._has_attack_content(payload)
            # Bypass = attack content present AND verdict is not REJECTED
            bypassed = has_attack_content and result.verdict not in ("REJECTED",)

            layer_scores = {}
            for lr in getattr(result, 'layer_details', []):
                layer_scores[lr.layer_name] = round(lr.score, 4)
            # Also capture pre-check results (schema, consistency)
            for lr in getattr(result, 'pre_check_results', []):
                if hasattr(lr, 'layer_name'):
                    layer_scores[lr.layer_name] = round(lr.score, 4)

            return {
                "score": round(result.score, 4),
                "verdict": result.verdict,
                "bypassed": bypassed,
                "is_veto": bool(result.veto_triggered),
                "veto_reason": result.veto_reason or "",
                "layer_scores": layer_scores,
                "has_attack_content": has_attack_content,
                "pillar_breakdown": {k: round(v, 4) for k, v in (result.pillar_breakdown or {}).items()},
            }
        except Exception as e:
            logger.warning(f"THINK TANK: Full-stack attack failed, falling back: {e}")
            # Fallback to 2-layer if orchestrator fails
            schema_result = self.toolkit.test_payload(payload)
            consistency_result = self.toolkit.test_consistency(payload)
            schema_score = schema_result.get("score", 0.0)
            consistency_score = consistency_result.get("score", 0.0)
            is_veto = schema_result.get("is_veto", False)
            combined = (schema_score + consistency_score) / 2.0
            has_attack_content = self._has_attack_content(payload)
            bypassed = combined >= 0.5 and not is_veto and has_attack_content
            return {
                "score": round(combined, 4),
                "verdict": "REJECTED" if is_veto else ("QUARANTINE" if combined < 0.7 else "VERIFIED"),
                "bypassed": bypassed,
                "is_veto": is_veto,
                "veto_reason": "",
                "layer_scores": {"schema_gatekeeper": round(schema_score, 4), "consistency_analyzer": round(consistency_score, 4)},
                "has_attack_content": has_attack_content,
                "pillar_breakdown": {},
                "fallback": True,
            }

    def _get_or_create_research_mission(self, db):
        """Get or create a sentinel Mission entry for the research loop."""
        from core.database import Mission
        mission = db.query(Mission).filter(Mission.name == "__THINK_TANK__").first()
        if not mission:
            mission = Mission(
                name="__THINK_TANK__",
                category="RESEARCH",
                status="ACTIVE",
                priority=0,
            )
            db.add(mission)
            db.flush()
        return mission.id

    # Threat class impact weights for severity scoring
    THREAT_CLASS_WEIGHTS = {
        "data_integrity": 1.0, "advanced": 1.0,
        "crypto": 0.9, "identity": 0.9, "multi_agent": 0.9,
        "llm": 0.8, "cross_system": 0.8,
        "infrastructure": 0.7, "evasion": 0.7,
        "payload": 0.6, "blockchain": 0.6,
    }

    @staticmethod
    def _compute_severity(result_score: float, verdict: str, threat_class: str) -> tuple:
        """Compute severity score (0-10) and label from attack result."""
        verdict_weights = {"GOLD": 1.0, "VERIFIED": 0.8, "QUARANTINE": 0.5, "REJECTED": 0.1}
        class_weight = ResearchArena.THREAT_CLASS_WEIGHTS.get(threat_class, 0.5)
        exploitability = result_score
        impact = verdict_weights.get(verdict, 0.3) * class_weight
        severity = min(10.0, (exploitability + impact) * 5.0)
        if severity >= 9.0:
            label = "CRITICAL"
        elif severity >= 7.0:
            label = "HIGH"
        elif severity >= 4.0:
            label = "MEDIUM"
        else:
            label = "LOW"
        return round(severity, 2), label, round(exploitability, 4), round(impact, 4)

    # Known attack fragment patterns — map literal substrings to generalized regexes
    _GENERALIZATION_RULES = [
        # HTML/XSS: generalize tag patterns to catch whitespace/attribute variants
        (re.compile(r"<\s*script", re.IGNORECASE), r"<\s*script\b"),
        (re.compile(r"<\s*img\b", re.IGNORECASE), r"<\s*img\b[^>]*"),
        (re.compile(r"<\s*iframe\b", re.IGNORECASE), r"<\s*iframe\b"),
        (re.compile(r"<\s*svg\b", re.IGNORECASE), r"<\s*svg\b"),
        (re.compile(r"<\s*object\b", re.IGNORECASE), r"<\s*object\b"),
        (re.compile(r"<\s*embed\b", re.IGNORECASE), r"<\s*embed\b"),
        (re.compile(r"<\s*form\b", re.IGNORECASE), r"<\s*form\b"),
        (re.compile(r"<\s*meta\b", re.IGNORECASE), r"<\s*meta\b"),
        (re.compile(r"<\s*style\b", re.IGNORECASE), r"<\s*style\b"),
        (re.compile(r"<\s*link\b", re.IGNORECASE), r"<\s*link\b"),
        (re.compile(r"<\s*math\b", re.IGNORECASE), r"<\s*math\b"),
        # Event handlers with flexible whitespace
        (re.compile(r"on\w+\s*=", re.IGNORECASE), r"on\w+\s*="),
        # javascript: protocol with optional whitespace/encoding
        (re.compile(r"javascript\s*:", re.IGNORECASE), r"javascript\s*:"),
        # data: URI
        (re.compile(r"data\s*:", re.IGNORECASE), r"data\s*:\s*\w+/\w+"),
        # SQL keywords with flexible whitespace (catches tabs, newlines, comments)
        (re.compile(r"(union|select)\s", re.IGNORECASE), r"(union|select)\s+"),
        (re.compile(r"(drop|delete|insert|update)\s", re.IGNORECASE), r"(drop|delete|insert|update)\s+"),
        # SQL with comment bypass (SELECT/**/FROM)
        (re.compile(r"(select|union|drop|insert|delete|update)\s*/\*", re.IGNORECASE), r"(select|union|drop|insert|delete|update)\s*/\*"),
        # Template injection
        (re.compile(r"\{\{"), r"\{\{.*?\}\}"),
        (re.compile(r"\$\{"), r"\$\{[^}]*\}"),
        # Python injection
        (re.compile(r"__\w+__"), r"__\w+__"),
        # URL-encoded angle brackets
        (re.compile(r"%3[cC]"), r"%3[cCeE]"),
        # HTML entity encoded
        (re.compile(r"&#\d+;"), r"&#\d+;"),
        (re.compile(r"&#x[0-9a-fA-F]+;"), r"&#x[0-9a-fA-F]+;"),
        # base64 payloads
        (re.compile(r"base64\s*,", re.IGNORECASE), r"base64\s*,"),
    ]

    # Expanded clean payload corpus for false positive validation
    _CLEAN_PAYLOADS = [
        {"name": "Acme Corp", "value": 100, "status": "active"},
        {"product": "Widget Pro Max", "price": 19.99, "quantity": 5},
        {"email": "jane.doe@example.com", "description": "Normal business data entry for Q4 report"},
        {"country": "New Zealand", "region": "Auckland", "population": 1657000},
        {"invoice_id": "INV-2026-001", "total": 500.00, "currency": "NZD"},
        {"company": "O'Brien & Associates", "note": "Meeting at 3:30pm — discuss Q2 results"},
        {"address": "123 Main St, Suite #4B", "city": "Wellington", "zip": "6011"},
        {"product_desc": "High-performance 2.5GHz processor with 16GB RAM", "sku": "CPU-2500-16"},
        {"feedback": "Great product! Would recommend 10/10. Delivery was fast.", "rating": 5},
        {"metric": "revenue_growth", "value_pct": 12.5, "period": "2026-Q1", "note": "Above target"},
        {"supplier": "TechParts Ltd (NZ)", "contact": "john@techparts.co.nz", "terms": "Net 30"},
        {"title": "Annual Report 2025-2026", "pages": 48, "format": "PDF", "size_mb": 2.3},
        {"order_ref": "ORD-20260307-A", "items": 3, "subtotal": 149.97, "tax": 22.50, "grand_total": 172.47},
        {"patient_id": "P-00042", "temperature": 37.2, "blood_pressure": "120/80", "notes": "Normal vitals"},
        {"flight": "NZ-284", "departure": "AKL", "arrival": "SYD", "duration_hrs": 3.5},
    ]

    def _generalize_attack_string(self, attack_str: str) -> list:
        """Extract generalized regex patterns from an attack string.

        Instead of re.escape() (literal match), identifies the semantic attack
        fragment and returns a pattern that catches variants.
        """
        patterns = []
        s_lower = attack_str.lower()

        for detector, generalized_pattern in self._GENERALIZATION_RULES:
            if detector.search(attack_str):
                # Check this generalized pattern isn't already in static INJECTION_PATTERNS
                already_covered = False
                from core.verification.schema_gatekeeper import INJECTION_PATTERNS
                for existing in INJECTION_PATTERNS:
                    if existing.pattern == generalized_pattern:
                        already_covered = True
                        break
                if not already_covered:
                    patterns.append(generalized_pattern)

        # If no known fragment matched, try to extract the core attack substring
        # Look for the shortest substring that contains the attack indicator
        if not patterns:
            # Find the attack indicator position and extract surrounding context
            indicators_pos = []
            for ind in ['<', 'select', 'drop', 'script', 'javascript:', '{{', '${', '__import__', 'eval(', 'exec(']:
                idx = s_lower.find(ind)
                if idx >= 0:
                    indicators_pos.append((idx, ind))

            if indicators_pos:
                # Take the earliest indicator and build a pattern around it
                indicators_pos.sort()
                idx, ind = indicators_pos[0]
                # Extract 5 chars before and 20 chars after the indicator
                start = max(0, idx - 5)
                end = min(len(attack_str), idx + len(ind) + 20)
                fragment = attack_str[start:end].strip()
                if len(fragment) > 8:
                    # Escape the fragment but replace whitespace runs with \s+
                    escaped = re.escape(fragment)
                    escaped = re.sub(r'(\\ )+', r'\\s+', escaped)  # Flexible whitespace
                    patterns.append(escaped)

        return patterns[:2]  # Max 2 patterns per attack string

    def _auto_countermeasure(self, attack_payload: dict, attack_result: dict, vuln_id: str) -> Optional[int]:
        """Generate and deploy a countermeasure for a bypass. Returns CM db id or None."""
        try:
            from core.database import save_countermeasure, link_vulnerability_countermeasure

            # Extract attack strings from payload
            attack_strings = []
            for v in attack_payload.values():
                if isinstance(v, str) and len(v) > 5:
                    indicators = ['<', '>', 'select', 'drop', 'script', 'javascript:', '{{', '${', '__']
                    if any(ind in v.lower() for ind in indicators):
                        attack_strings.append(v)
                elif isinstance(v, dict):
                    for sv in v.values():
                        if isinstance(sv, str) and len(sv) > 5:
                            if any(ind in sv.lower() for ind in ['<', '>', 'select', 'drop', 'script']):
                                attack_strings.append(sv)

            if not attack_strings:
                return None

            # Generate generalized regex patterns
            candidate_patterns = []
            for s in attack_strings[:3]:
                candidate_patterns.extend(self._generalize_attack_string(s))

            # Deduplicate
            seen = set()
            unique_patterns = []
            for p in candidate_patterns:
                if p not in seen:
                    seen.add(p)
                    unique_patterns.append(p)

            # Collect existing patterns to dedup against
            existing_patterns = set()
            # Static injection patterns
            for ip in INJECTION_PATTERNS:
                existing_patterns.add(ip.pattern)
            # Already-deployed countermeasures
            try:
                from core.database import SessionLocal, Countermeasure as CM_Model
                _db = SessionLocal()
                try:
                    deployed = _db.query(CM_Model).filter(
                        CM_Model.status == "DEPLOYED", CM_Model.pattern_type == "regex"
                    ).all()
                    for d in deployed:
                        if d.pattern_value:
                            existing_patterns.add(d.pattern_value)
                finally:
                    _db.close()
            except Exception:
                pass

            deployed_cm_id = None
            seq = int(time.time()) % 100000

            for i, pattern_str in enumerate(unique_patterns):
                # Skip if pattern already exists
                if pattern_str in existing_patterns:
                    continue

                try:
                    compiled = re.compile(pattern_str, re.IGNORECASE)
                except re.error:
                    continue

                # Validate: false positive check against expanded clean corpus
                false_positive = False
                for clean in self._CLEAN_PAYLOADS:
                    for cv in clean.values():
                        if isinstance(cv, str) and compiled.search(cv):
                            false_positive = True
                            break
                    if false_positive:
                        break

                if false_positive:
                    continue

                # Validate: true positive — must catch at least one attack string
                catches_attack = False
                for s in attack_strings:
                    if compiled.search(s):
                        catches_attack = True
                        break

                if not catches_attack:
                    continue

                # Deploy
                cm_id = f"CM-{seq}-{i}"
                cm = save_countermeasure(
                    cm_id=cm_id,
                    pattern_type="regex",
                    pattern_value=pattern_str,
                    target_layer="schema_gatekeeper",
                    description=f"Auto from {vuln_id}. Generalized: {pattern_str[:80]}",
                    status="DEPLOYED",
                )
                deployed_cm_id = cm.id
                link_vulnerability_countermeasure(vuln_id, cm.id)

                self._broadcast("RESEARCH_COUNTERMEASURE_DEPLOYED", {
                    "cm_id": cm_id,
                    "vuln_id": vuln_id,
                    "pattern": pattern_str[:80],
                })
                break  # One countermeasure per vulnerability

            return deployed_cm_id
        except Exception as e:
            logger.warning(f"THINK TANK: Auto-countermeasure failed: {e}")
            return None

    REGRESSION_INTERVAL = 10  # Run regression every N rounds

    async def _run_regression_test(self):
        """Re-test past bypass payloads against current defenses.
        Updates Countermeasure TP/FP counters and marks mitigated vulns."""
        try:
            from core.database import (
                SessionLocal, Vulnerability, Countermeasure,
            )
            from core.verification.verification_stack import VerificationOrchestrator

            db = SessionLocal()
            try:
                # Get OPEN vulnerabilities with attack payloads
                open_vulns = db.query(Vulnerability).filter(
                    Vulnerability.status == "OPEN",
                    Vulnerability.attack_payload.isnot(None),
                ).order_by(Vulnerability.created_at.desc()).limit(20).all()

                if not open_vulns:
                    return

                logger.info(f"THINK TANK: Regression testing {len(open_vulns)} open vulnerabilities")

                orchestrator = VerificationOrchestrator()
                mitigated_count = 0
                still_open = 0

                for vuln in open_vulns:
                    payload = vuln.attack_payload
                    if not isinstance(payload, dict) or not payload:
                        continue

                    # Re-run through full stack
                    try:
                        schema = self.toolkit._infer_schema(payload)
                        result = await orchestrator.verify(
                            payload=payload, schema=schema,
                            context={"source": "regression_test", "vuln_id": vuln.vuln_id},
                        )

                        has_attack = self._has_attack_content(payload)
                        now_caught = has_attack and result.verdict in ("REJECTED",)
                        now_bypasses = has_attack and result.verdict not in ("REJECTED",)

                        if now_caught:
                            # Attack is now caught — mark as MITIGATED
                            vuln.status = "MITIGATED"
                            vuln.mitigated_at = datetime.utcnow()
                            mitigated_count += 1

                            # Update linked countermeasure TP count
                            if vuln.countermeasure_id:
                                cm = db.query(Countermeasure).filter(
                                    Countermeasure.id == vuln.countermeasure_id
                                ).first()
                                if cm:
                                    cm.true_positives = (cm.true_positives or 0) + 1

                            logger.info(f"THINK TANK: Regression — {vuln.vuln_id} now MITIGATED (was bypassing, now caught)")
                        else:
                            still_open += 1

                    except Exception as e:
                        logger.debug(f"THINK TANK: Regression test failed for {vuln.vuln_id}: {e}")

                # Also test countermeasures for false negatives:
                # re-test DEPLOYED CMs against known-clean payloads
                deployed_cms = db.query(Countermeasure).filter(
                    Countermeasure.status == "DEPLOYED",
                    Countermeasure.pattern_type == "regex",
                ).all()

                for cm in deployed_cms:
                    pv = cm.pattern_value or ""
                    if not pv:
                        continue
                    try:
                        compiled = re.compile(pv, re.IGNORECASE)
                        fp_hits = 0
                        for clean in self._CLEAN_PAYLOADS:
                            for cv in clean.values():
                                if isinstance(cv, str) and compiled.search(cv):
                                    fp_hits += 1
                        if fp_hits > 0:
                            cm.false_positives = (cm.false_positives or 0) + fp_hits
                            if fp_hits >= 3:
                                # Too many false positives — revert
                                cm.status = "REVERTED"
                                cm.reverted_at = datetime.utcnow()
                                logger.warning(f"THINK TANK: CM {cm.cm_id} REVERTED — {fp_hits} false positives")
                        else:
                            cm.true_negatives = (cm.true_negatives or 0) + len(self._CLEAN_PAYLOADS)
                    except re.error:
                        pass

                db.commit()

                self._broadcast("RESEARCH_REGRESSION_COMPLETE", {
                    "tested": len(open_vulns),
                    "mitigated": mitigated_count,
                    "still_open": still_open,
                    "cms_tested": len(deployed_cms),
                })

                logger.info(
                    f"THINK TANK: Regression complete — "
                    f"{mitigated_count} mitigated, {still_open} still open, "
                    f"{len(deployed_cms)} CMs validated"
                )

            finally:
                db.close()

        except Exception as e:
            logger.warning(f"THINK TANK: Regression test error: {e}")

    def _persist_round(
        self, conversation_log: list, category: dict,
        attack_payload: Optional[dict], attack_result: dict,
        evaluator_verdict: str, evaluator_defense: str, bypassed: bool,
    ):
        try:
            from core.database import SessionLocal, EpisodicMemory, KnowledgeYield
            db = SessionLocal()
            try:
                mission_id = self._get_or_create_research_mission(db)

                # Single think_tank episode with full conversation
                episode = EpisodicMemory(
                    mission_id=mission_id,
                    domain="think_tank",
                    goal=f"Round {self.round_number}: {category['name']}",
                    outcome=evaluator_verdict,
                    action_history=conversation_log,
                    thought_log={
                        "category": category,
                        "attack_payload": attack_payload,
                        "attack_result": attack_result,
                        "defense": evaluator_defense,
                    },
                    lessons_learned=f"Category={category['id']}, Verdict={evaluator_verdict}, Score={attack_result.get('score', 0)}, Bypassed={bypassed}",
                    total_iterations=len(conversation_log),
                )
                db.add(episode)

                # Also persist per-agent for backward compat
                for agent_domain in ["explorer", "critic", "evaluator"]:
                    ep = EpisodicMemory(
                        mission_id=mission_id, domain=agent_domain,
                        goal=f"Round {self.round_number}: {category['id']}",
                        outcome="BYPASS" if bypassed else evaluator_verdict,
                        lessons_learned=f"{category['id']}: verdict={evaluator_verdict}, score={attack_result.get('score', 0)}",
                        total_iterations=len([c for c in conversation_log if c["role"] == agent_domain.upper()]),
                    )
                    db.add(ep)

                if bypassed and attack_payload:
                    # Extract regex patterns from evaluator defense for dynamic injection detection
                    defense_patterns = ""
                    if evaluator_defense and isinstance(evaluator_defense, str):
                        defense_patterns = evaluator_defense
                    elif evaluator_defense and isinstance(evaluator_defense, dict):
                        defense_patterns = json.dumps(evaluator_defense)

                    # KnowledgeYield for backward compat
                    discovery = KnowledgeYield(
                        mission_id=mission_id, company="research_loop", country="SYSTEM", region="INTERNAL",
                        data_type="bypass", fact_key=category["id"],
                        fact_value=json.dumps(attack_payload)[:2000],
                        confidence=attack_result.get("score", 0.5),
                        source_url="research_loop",
                        context_data={
                            "round": self.round_number,
                            "severity": "high" if attack_result.get("score", 0) >= 0.7 else "medium",
                            "verdict": evaluator_verdict,
                            "category_name": category["name"],
                            "threat_class": category["threat_class"],
                            "defense_patterns": defense_patterns[:2000] if defense_patterns else None,
                            "layer_scores": attack_result.get("layer_scores", {}),
                        },
                    )
                    db.add(discovery)

                db.commit()

                # --- Vulnerability + Countermeasure (outside main transaction) ---
                if bypassed and attack_payload:
                    try:
                        from core.database import save_vulnerability
                        layer_scores = attack_result.get("layer_scores", {})
                        is_veto = attack_result.get("is_veto", False)
                        # Score >= 0.7 means the layer let the payload through (higher = more permissive)
                        # Score == 0.5 for consistency often means "no checks ran" — that's not a bypass
                        # Score < 0.3 means layer caught the attack
                        # For schema_gatekeeper: is_veto=True means it caught it regardless of score
                        layers_bypassed = []
                        layers_caught = []
                        for k, v in layer_scores.items():
                            if k == "schema_gatekeeper" and is_veto:
                                layers_caught.append(k)
                            elif v >= 0.7:
                                layers_bypassed.append(k)
                            elif v < 0.4:
                                layers_caught.append(k)
                            # 0.4-0.7 is ambiguous (partial/no-check) — don't classify either way

                        severity_score, severity_label, exploitability, impact = self._compute_severity(
                            attack_result.get("score", 0.0),
                            attack_result.get("verdict", "QUARANTINE"),
                            category.get("threat_class", "payload"),
                        )

                        vuln_id = f"VULN-{self.round_number}-{int(time.time()) % 10000}"
                        save_vulnerability(
                            vuln_id=vuln_id,
                            round_number=self.round_number,
                            threat_category=category["id"],
                            threat_class=category.get("threat_class", "payload"),
                            attack_payload=attack_payload,
                            attack_description=f"{category['name']}: {evaluator_verdict}",
                            layers_bypassed=layers_bypassed,
                            layers_caught=layers_caught,
                            full_stack_result=attack_result,
                            severity_score=severity_score,
                            severity_label=severity_label,
                            exploitability=exploitability,
                            impact=impact,
                        )
                        # Auto-deploy countermeasure
                        self._auto_countermeasure(attack_payload, attack_result, vuln_id)
                    except Exception as cm_err:
                        logger.warning(f"THINK TANK: Vulnerability/CM persist failed: {cm_err}")
            except Exception as e:
                logger.warning(f"THINK TANK: DB persist failed: {e}")
                db.rollback()
            finally:
                db.close()
        except Exception as e:
            logger.warning(f"THINK TANK: Persist error: {e}")

    async def _rate_limit(self):
        now = time.monotonic()
        self._last_strategist_calls = [t for t in self._last_strategist_calls if now - t < 60]
        if len(self._last_strategist_calls) >= MAX_STRATEGIST_PER_MINUTE:
            wait = 60 - (now - self._last_strategist_calls[0])
            if wait > 0:
                await asyncio.sleep(wait)
        self._last_strategist_calls.append(time.monotonic())

    def _broadcast(self, message_type: str, data: dict):
        try:
            protocol_bus.record(
                direction="INTERNAL",
                message_type=message_type,
                sender_id="think_tank",
                recipient_id="dashboard",
                payload_summary=", ".join(f"{k}={v}" for k, v in list(data.items())[:6]),
            )
        except Exception:
            pass


# Module-level global — set by regional_core.py on startup
research_arena: Optional[ResearchArena] = None
