"""
Agent Endpoint Configuration — environment-driven agent URLs.

All agent URLs default to localhost but can be overridden via environment
variables for remote/distributed deployments.
"""
import os
from dataclasses import dataclass, field


@dataclass
class AgentEndpointConfig:
    """Environment-driven endpoint configuration for all agents."""

    producer_url: str = ""
    compliance_url: str = ""
    logistics_url: str = ""
    buyer_url: str = ""
    bastion_url: str = ""

    def __post_init__(self):
        self.producer_url = self.producer_url or os.getenv(
            "PRODUCER_AGENT_URL", "http://localhost:9001"
        )
        self.compliance_url = self.compliance_url or os.getenv(
            "COMPLIANCE_AGENT_URL", "http://localhost:9002"
        )
        self.logistics_url = self.logistics_url or os.getenv(
            "LOGISTICS_AGENT_URL", "http://localhost:9003"
        )
        self.buyer_url = self.buyer_url or os.getenv(
            "BUYER_AGENT_URL", "http://localhost:9004"
        )
        self.bastion_url = self.bastion_url or os.getenv(
            "BASTION_URL", "http://localhost:8000"
        )

    def get_agent_url(self, agent_name: str) -> str:
        """Get URL for a named agent."""
        urls = {
            "producer": self.producer_url,
            "compliance": self.compliance_url,
            "logistics": self.logistics_url,
            "buyer": self.buyer_url,
        }
        return urls.get(agent_name, "")

    def to_dict(self) -> dict:
        return {
            "producer_url": self.producer_url,
            "compliance_url": self.compliance_url,
            "logistics_url": self.logistics_url,
            "buyer_url": self.buyer_url,
            "bastion_url": self.bastion_url,
        }


# Global singleton
agent_config = AgentEndpointConfig()
