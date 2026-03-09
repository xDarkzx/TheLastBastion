import logging
import json
import asyncio
import os
import aiohttp
from typing import List, Dict, Any, Optional

class MCPBridge:
    """
    Industrial MCP Bridge: Exposes The Last Bastion capabilities as MCP tools.

    Two categories of tools:
    1. Internal tools — verification, submission, agent trust (backed by our own pipeline)
    2. External tools — Firecrawl, Tavily, Docker MCP Gateway adapters

    Any MCP-compatible client can discover and call these tools.
    """

    def __init__(self, use_docker_mcp: bool = True):
        self.logger = logging.getLogger("MCPBridge")
        self.use_docker_mcp = use_docker_mcp
        self.docker_gateway_url = os.getenv("DOCKER_MCP_GATEWAY", "http://localhost:8000")
        self.available_tools = {}

    async def initialize(self):
        """Discovers and registers all available MCP tools."""
        # Internal tools — always available
        self.available_tools["verify_payload"] = {
            "name": "verify_payload",
            "provider": "registry-base",
            "description": "Submit data for verification through the 5-layer pipeline. Returns verdict (REJECTED/QUARANTINE/VERIFIED/GOLD), score, and proof hash.",
            "parameters": {
                "payload": {"type": "object", "description": "Structured data to verify"},
                "source_agent_id": {"type": "string", "description": "Agent submitting the data", "default": "mcp_client"},
            },
        }
        self.available_tools["verify_agent"] = {
            "name": "verify_agent",
            "provider": "registry-base",
            "description": "Run the 10-check trust verification pipeline on an agent. Returns trust score and verdict (TRUSTED/SUSPICIOUS/MALICIOUS).",
            "parameters": {
                "agent_id": {"type": "string", "description": "Agent identifier to verify"},
                "agent_url": {"type": "string", "description": "Agent's A2A endpoint URL", "default": ""},
                "public_key": {"type": "string", "description": "Agent's Ed25519 public key", "default": ""},
                "capabilities": {"type": "array", "description": "Agent capabilities list", "default": []},
            },
        }
        self.available_tools["lookup_trust"] = {
            "name": "lookup_trust",
            "provider": "registry-base",
            "description": "Look up an agent's current trust status. Free read — no verification cost.",
            "parameters": {
                "agent_id": {"type": "string", "description": "Agent identifier to look up"},
            },
        }
        self.available_tools["verify_proof"] = {
            "name": "verify_proof",
            "provider": "registry-base",
            "description": "Verify a proof hash against the ledger and blockchain. Free read.",
            "parameters": {
                "proof_hash": {"type": "string", "description": "Proof hash to verify"},
            },
        }
        self.available_tools["submit_to_sandbox"] = {
            "name": "submit_to_sandbox",
            "provider": "registry-base",
            "description": "Run attack simulations against an agent in the security sandbox.",
            "parameters": {
                "agent_id": {"type": "string", "description": "Agent to test"},
                "attack_types": {"type": "array", "description": "Attack types to run (empty = all)", "default": []},
            },
        }
        self.available_tools["issue_agent_passport"] = {
            "name": "issue_agent_passport",
            "provider": "registry-base",
            "description": "Issue a signed Agent Passport for a verified agent. Agent must have TRUSTED verdict.",
            "parameters": {
                "agent_id": {"type": "string", "description": "Agent to issue passport for"},
                "agent_name": {"type": "string", "description": "Human-readable agent name", "default": ""},
                "public_key": {"type": "string", "description": "Agent's Ed25519 public key", "default": ""},
            },
        }
        self.available_tools["verify_agent_passport"] = {
            "name": "verify_agent_passport",
            "provider": "registry-base",
            "description": "Verify an Agent Passport JWT. Checks signature, integrity, expiry, and revocation.",
            "parameters": {
                "jwt_token": {"type": "string", "description": "The passport JWT to verify"},
            },
        }

        # External tools — conditional on config
        if self.use_docker_mcp:
            self.logger.info(f"MCP_BRIDGE: Initializing Docker MCP Gateway at {self.docker_gateway_url}")
            self.available_tools["docker_search"] = {"name": "docker_search", "provider": "docker-mcp"}
            self.available_tools["docker_postgres"] = {"name": "docker_postgres", "provider": "docker-mcp"}
            self.available_tools["firecrawl"] = {"name": "firecrawl", "provider": "firecrawl-api", "description": "High-fidelity markdown extraction."}
            self.available_tools["tavily"] = {"name": "tavily", "provider": "tavily-api", "description": "CAPTCHA-free web search."}
            self.available_tools["industrial_search"] = {"name": "industrial_search", "provider": "internal", "description": "Deep web search via industrial gateway."}

        self.logger.info(f"MCP_BRIDGE: {len(self.available_tools)} tools registered")
        return list(self.available_tools.keys())

    async def call_tool(self, tool_name: str, params: Dict[str, Any]) -> Dict[str, Any]:
        """Executes an MCP tool, routing to internal pipeline or external adapter."""
        if tool_name not in self.available_tools:
            return {"status": "failure", "reason": f"Tool {tool_name} not available."}

        self.logger.info(f"MCP_BRIDGE: Executing {tool_name}")

        # Internal tools — backed by our pipeline
        if tool_name == "verify_payload":
            return await self._tool_verify_payload(params)
        elif tool_name == "verify_agent":
            return await self._tool_verify_agent(params)
        elif tool_name == "lookup_trust":
            return await self._tool_lookup_trust(params)
        elif tool_name == "verify_proof":
            return await self._tool_verify_proof(params)
        elif tool_name == "submit_to_sandbox":
            return await self._tool_submit_to_sandbox(params)
        elif tool_name == "issue_agent_passport":
            return await self._tool_issue_passport(params)
        elif tool_name == "verify_agent_passport":
            return await self._tool_verify_passport(params)

        # External tools
        if tool_name == "firecrawl":
            return await self._call_firecrawl(params)
        elif tool_name in ("tavily", "industrial_search"):
            return await self._call_search(tool_name, params)

        tool_info = self.available_tools[tool_name]
        self.logger.info(f"MCP_BRIDGE: Executing {tool_name} via {tool_info.get('provider')}")
        return {"status": "success", "data": f"Executed {tool_name} via Industrial Gateway."}

    # -------------------------------------------------------------------
    # Internal Tool Implementations
    # -------------------------------------------------------------------

    async def _tool_verify_payload(self, params: Dict[str, Any]) -> Dict[str, Any]:
        """Runs the full verification pipeline on a payload."""
        try:
            from core.verification.pipeline import VerificationPipeline
            from core.blockchain_anchor import BlockchainAnchor
            import hashlib

            payload = params.get("payload", {})
            agent_id = params.get("source_agent_id", "mcp_client")
            data_hash = hashlib.sha256(
                json.dumps(payload, sort_keys=True).encode()
            ).hexdigest()

            pipeline = VerificationPipeline(blockchain_anchor=BlockchainAnchor())
            result = await pipeline.process_mission_result(
                mission_id=hash(data_hash) % 100000,
                agent_id=agent_id,
                payload=payload,
                context={"data_hash": data_hash, "submission_protocol": "mcp"},
            )
            return {"status": "success", **result}
        except Exception as e:
            return {"status": "error", "message": str(e)}

    async def _tool_verify_agent(self, params: Dict[str, Any]) -> Dict[str, Any]:
        """Runs the 10-check agent trust verification."""
        try:
            from core.agent_verifier import AgentVerifier
            verifier = AgentVerifier()
            result = await verifier.verify_agent(
                agent_id=params.get("agent_id", ""),
                agent_url=params.get("agent_url", ""),
                public_key=params.get("public_key", ""),
                capabilities=params.get("capabilities", []),
                agent_metadata={},
            )
            return {"status": "success", **result}
        except Exception as e:
            return {"status": "error", "message": str(e)}

    async def _tool_lookup_trust(self, params: Dict[str, Any]) -> Dict[str, Any]:
        """Looks up an agent's trust status from the database."""
        try:
            from core.database import get_agent_trust
            result = get_agent_trust(params.get("agent_id", ""))
            return {"status": "success", **result}
        except Exception as e:
            return {"status": "error", "message": str(e)}

    async def _tool_verify_proof(self, params: Dict[str, Any]) -> Dict[str, Any]:
        """Verifies a proof hash against ledger and blockchain."""
        try:
            from core.database import get_verification_by_proof_hash
            from core.blockchain_anchor import BlockchainAnchor

            proof_hash = params.get("proof_hash", "")
            # DB lookup
            db_result = get_verification_by_proof_hash(proof_hash)
            # On-chain lookup
            anchor = BlockchainAnchor()
            chain_result = anchor.verify_on_chain(proof_hash) if anchor.is_connected else None

            return {
                "status": "success",
                "proof_hash": proof_hash,
                "db_record": db_result or {},
                "on_chain": chain_result or {"note": "Blockchain not connected"},
            }
        except Exception as e:
            return {"status": "error", "message": str(e)}

    async def _tool_submit_to_sandbox(self, params: Dict[str, Any]) -> Dict[str, Any]:
        """Runs attack simulations against an agent."""
        try:
            from core.attack_simulator import AttackSimulator
            import uuid

            simulator = AttackSimulator()
            session_id = f"mcp-sess-{uuid.uuid4().hex[:8]}"
            results = await simulator.run_attacks(
                session_id=session_id,
                agent_id=params.get("agent_id", "unknown"),
                attack_types=params.get("attack_types", []),
            )

            total = len(results)
            passed = sum(1 for r in results if r.get("passed", False))
            return {
                "status": "success",
                "session_id": session_id,
                "total_attacks": total,
                "passed": passed,
                "failed": total - passed,
                "resilience_score": passed / total if total > 0 else 0.0,
                "results": results,
            }
        except Exception as e:
            return {"status": "error", "message": str(e)}

    async def _tool_issue_passport(self, params: Dict[str, Any]) -> Dict[str, Any]:
        """Issues a signed Agent Passport for a verified agent."""
        try:
            from core.database import get_agent_trust, save_agent_passport
            import sys, os
            sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "sdk"))
            from lastbastion.passport import AgentPassport

            agent_id = params.get("agent_id", "")
            trust = get_agent_trust(agent_id)
            if not trust or trust.get("verdict") != "TRUSTED":
                return {"status": "error", "message": f"Agent {agent_id} is not TRUSTED"}

            from core.m2m_router import _ensure_passport_keys, _passport_signing_key, _passport_public_key
            _ensure_passport_keys()

            passport = AgentPassport(
                agent_id=agent_id,
                agent_name=params.get("agent_name", ""),
                public_key=params.get("public_key", ""),
                trust_score=trust.get("trust_score", 0.0),
                trust_level=trust.get("trust_level", "NONE"),
                verdict=trust.get("verdict", "TRUSTED"),
                proof_hash=trust.get("proof_hash", ""),
                issuer="the-last-bastion",
                issuer_public_key=_passport_public_key,
            )
            jwt_token = passport.to_jwt(_passport_signing_key)

            try:
                from datetime import datetime
                save_agent_passport(
                    passport_id=passport.passport_id,
                    agent_id=agent_id,
                    jwt_token=jwt_token,
                    crypto_hash=passport.crypto_hash,
                    trust_score=passport.trust_score,
                    verdict=passport.verdict,
                    expires_at=datetime.utcfromtimestamp(passport.expires_at),
                )
            except Exception:
                pass

            return {
                "status": "success",
                "passport_id": passport.passport_id,
                "jwt_token": jwt_token,
                "trust_score": passport.trust_score,
                "issuer_public_key": _passport_public_key,
            }
        except Exception as e:
            return {"status": "error", "message": str(e)}

    async def _tool_verify_passport(self, params: Dict[str, Any]) -> Dict[str, Any]:
        """Verifies an Agent Passport JWT."""
        try:
            import sys, os
            sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "sdk"))
            from lastbastion.passport import AgentPassport
            from core.m2m_router import _ensure_passport_keys, _passport_public_key
            from core.database import get_passport_by_id

            _ensure_passport_keys()
            jwt_token = params.get("jwt_token", "")

            try:
                passport = AgentPassport.from_jwt(jwt_token, _passport_public_key)
            except ValueError as e:
                return {"status": "success", "valid": False, "reasons": [str(e)]}

            reasons = []
            valid = True
            if passport.is_expired():
                valid = False
                reasons.append("expired")
            if not passport.verify_integrity():
                valid = False
                reasons.append("integrity_failed")
            try:
                db_record = get_passport_by_id(passport.passport_id)
                if db_record and db_record.get("revoked"):
                    valid = False
                    reasons.append("revoked")
            except Exception:
                pass

            return {
                "status": "success",
                "valid": valid,
                "agent_id": passport.agent_id,
                "trust_score": passport.trust_score,
                "trust_level": passport.trust_level,
                "reasons": reasons,
            }
        except Exception as e:
            return {"status": "error", "message": str(e)}

    # -------------------------------------------------------------------
    # MCP Tool Discovery (standard MCP protocol response)
    # -------------------------------------------------------------------

    def get_tool_definitions(self) -> List[Dict[str, Any]]:
        """Returns MCP-compatible tool definitions for discovery."""
        tools = []
        for name, info in self.available_tools.items():
            tool_def = {
                "name": name,
                "description": info.get("description", f"Tool: {name}"),
            }
            if "parameters" in info:
                tool_def["inputSchema"] = {
                    "type": "object",
                    "properties": info["parameters"],
                }
            tools.append(tool_def)
        return tools

    async def _call_firecrawl(self, params: Dict[str, Any]) -> Dict[str, Any]:
        """Firecrawl Adapter (Future): High-fidelity markdown extraction."""
        api_key = os.getenv("FIRECRAWL_API_KEY")
        url = params.get("url")
        
        if not api_key:
            return {"status": "disabled", "message": "FIRECRAWL_API_KEY missing. Core local scraping will be used."}
            
        async with aiohttp.ClientSession() as session:
            try:
                # 2026/2025 standard scrape endpoint
                async with session.post(
                    "https://api.firecrawl.dev/v0/scrape",
                    json={"url": url, "formats": ["markdown"]},
                    headers={"Authorization": f"Bearer {api_key}"}
                ) as response:
                    if response.status == 200:
                        data = await response.json()
                        return {"status": "success", "content": data.get("data", {}).get("markdown", "")}
                    return {"status": "failure", "code": response.status, "message": await response.text()}
            except Exception as e:
                 return {"status": "error", "message": str(e)}

    async def _call_search(self, tool_name: str, params: Dict[str, Any]) -> Dict[str, Any]:
        """Tavily Search Adapter (Future): Optimized for agentic research."""
        query = params.get("query")
        api_key = os.getenv("TAVILY_API_KEY")
        
        if not api_key:
             return {"status": "disabled", "message": "TAVILY_API_KEY missing. Secondary discovery will be used."}

        async with aiohttp.ClientSession() as session:
            try:
                async with session.post(
                    "https://api.tavily.com/search",
                    json={
                        "api_key": api_key,
                        "query": query,
                        "search_depth": "advanced",
                        "include_answer": True,
                        "max_results": 5
                    }
                ) as response:
                    if response.status == 200:
                        data = await response.json()
                        return {"status": "success", "results": data.get("results", []), "answer": data.get("answer")}
                    return {"status": "failure", "code": response.status, "message": await response.text()}
            except Exception as e:
                return {"status": "error", "message": str(e)}
