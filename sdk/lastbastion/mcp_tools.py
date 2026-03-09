"""
Last Bastion MCP Tools — mount these in any MCP-compatible AI agent.

Usage:
    from lastbastion.mcp_tools import create_lastbastion_mcp

    mcp = create_lastbastion_mcp(
        base_url="https://api.thelastbastion.io",
    )

    # Mount in your MCP server — agents can now call these tools
"""

from typing import Any, Dict, Optional


def create_lastbastion_mcp(
    api_key: str = "",
    base_url: str = "http://localhost:8000",
) -> Any:
    """
    Create an MCP server with Last Bastion verification tools.

    Tools exposed:
    - get_verified: Submit yourself for verification, receive a passport
    - verify_payload: Check data (PDF, JSON, etc.) for fraud through 5-layer pipeline
    - check_agent_trust: Look up another agent's trust score
    - verify_passport: Verify an Agent Passport JWT
    """
    try:
        from mcp.server.fastmcp import FastMCP
    except ImportError:
        raise ImportError(
            "MCP mode requires the 'mcp' package. "
            "Install with: pip install lastbastion[mcp]"
        )

    mcp = FastMCP("Last Bastion Agent Security")

    @mcp.tool()
    async def get_verified(
        agent_id: str,
        agent_name: str = "",
        public_key: str = "",
        private_key: str = "",
        agent_url: str = "",
        capabilities: str = "",
    ) -> Dict[str, Any]:
        """
        Submit yourself for trust verification by The Last Bastion.
        Runs a 10-check pipeline (identity, crypto, behavioral, anti-Sybil, etc.).
        If you pass, you receive a signed Agent Passport — cryptographic proof
        that you are a legitimate agent.

        If no keypair is provided, one is generated automatically.

        Args:
            agent_id: Your unique agent identifier
            agent_name: Human-readable name
            public_key: Your Ed25519 public key (hex). Generated if empty.
            private_key: Your Ed25519 private key (hex). Generated if empty.
            agent_url: Your A2A endpoint URL
            capabilities: Comma-separated list of capabilities
        """
        from lastbastion import LastBastionClient

        caps = [c.strip() for c in capabilities.split(",") if c.strip()]
        async with LastBastionClient(api_key=api_key, base_url=base_url) as client:
            try:
                result = await client.register_and_verify(
                    agent_id=agent_id,
                    agent_name=agent_name,
                    public_key=public_key,
                    private_key=private_key,
                    agent_url=agent_url,
                    capabilities=caps,
                )
                return {"status": "success", **result}
            except Exception as e:
                return {"status": "error", "message": str(e)}

    @mcp.tool()
    async def verify_payload(
        payload_json: str,
        source_agent_id: str = "mcp_agent",
    ) -> Dict[str, Any]:
        """
        Submit data for fraud verification through The Last Bastion's 5-layer pipeline.
        Checks schema, consistency, forensic integrity, logic triangulation, and attestation.
        Returns a verdict: REJECTED, QUARANTINE, VERIFIED, or GOLD.

        Args:
            payload_json: JSON string of the data to verify
            source_agent_id: Your agent ID
        """
        import json as _json
        from lastbastion import LastBastionClient

        try:
            payload = _json.loads(payload_json)
        except (ValueError, TypeError):
            return {"status": "error", "message": "Invalid JSON payload"}

        async with LastBastionClient(api_key=api_key, base_url=base_url) as client:
            try:
                result = await client.submit_payload(
                    payload=payload,
                    source_agent_id=source_agent_id,
                )
                return {"status": "success", **result}
            except Exception as e:
                return {"status": "error", "message": str(e)}

    @mcp.tool()
    async def check_agent_trust(agent_id: str) -> Dict[str, Any]:
        """
        Look up another agent's trust status on The Last Bastion.
        Free read — does not trigger verification. Returns trust score,
        level, verdict, risk flags, and proof hash.

        Args:
            agent_id: The agent to look up
        """
        from lastbastion import LastBastionClient

        async with LastBastionClient(api_key=api_key, base_url=base_url) as client:
            try:
                result = await client.get_trust_status(agent_id)
                return {"status": "success", **result}
            except Exception as e:
                return {"status": "error", "message": str(e)}

    @mcp.tool()
    async def generate_passport(
        clean: bool = True,
        defect_type: str = "",
        agent_name: str = "",
        output_dir: str = ".",
    ) -> Dict[str, Any]:
        """
        Generate an Agent Passport file for the Border Police demo.

        Clean passports pass all 10 verification checks.
        Bad passports deliberately fail specific checks (educational).

        Args:
            clean: True for a valid passport, False for a deliberately broken one
            defect_type: If clean=False, one of: tampered, expired, injected, wrong_key, sybil
            agent_name: Human-readable name for the agent
            output_dir: Directory to save passport files
        """
        import os
        from lastbastion.passport_generator import (
            generate_passport_file,
            generate_bad_passport_file,
        )

        try:
            if clean:
                path = os.path.join(output_dir, "agent.passport")
                result = generate_passport_file(output_path=path, agent_name=agent_name)
                return {"status": "success", "type": "clean", **result}
            else:
                if not defect_type:
                    defect_type = "tampered"
                path = os.path.join(output_dir, f"bad_{defect_type}.passport")
                result = generate_bad_passport_file(
                    output_path=path, defect_type=defect_type, agent_name=agent_name,
                )
                return {"status": "success", "type": "bad", **result}
        except Exception as e:
            return {"status": "error", "message": str(e)}

    @mcp.tool()
    async def verify_passport(jwt_token: str) -> Dict[str, Any]:
        """
        Verify an Agent Passport JWT. Checks signature, integrity, expiry,
        and revocation status against The Last Bastion server.

        Args:
            jwt_token: The passport JWT to verify
        """
        from lastbastion import LastBastionClient

        async with LastBastionClient(api_key=api_key, base_url=base_url) as client:
            try:
                result = await client.verify_passport(jwt_token)
                return {"status": "success", **result}
            except Exception as e:
                return {"status": "error", "message": str(e)}

    return mcp
