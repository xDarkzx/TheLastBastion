"""
The Last Bastion M2M Protocol Layer.

This package implements the Agent Communication Protocol (ACP v1.0)
for machine-to-machine communication.

Modules:
    agent_protocol  — Message types, envelope, agent identity
    auth            — Signing, API keys, replay protection, RBAC
    registry        — Agent registration, service catalog, discovery
    quotation       — Pricing, credits, metering

Usage:
    from protocols.agent_protocol import ProtocolMessage, MessageType
    from protocols.auth import M2MAuthenticator, sign_message
    from protocols.registry import AgentRegistry
    from protocols.quotation import QuotationEngine
"""
from protocols.agent_protocol import (
    AgentIdentity,
    AgentRole,
    MessageType,
    ProtocolMessage,
    PROTOCOL_VERSION,
)
from protocols.auth import M2MAuthenticator, sign_message
from protocols.registry import AgentRegistry
from protocols.quotation import QuotationEngine

__all__ = [
    "AgentIdentity",
    "AgentRole",
    "MessageType",
    "ProtocolMessage",
    "PROTOCOL_VERSION",
    "M2MAuthenticator",
    "sign_message",
    "AgentRegistry",
    "QuotationEngine",
]
