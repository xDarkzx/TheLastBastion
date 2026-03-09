"""
Agent Registry & Service Discovery.

The phone book for the M2M ecosystem:
- External agents register with The Last Bastion
- The Last Bastion advertises its own services
- Agents discover each other by capability tags
- Health monitoring tracks agent availability
- Reputation scoring rewards reliable agents

Service Catalog:
    The Last Bastion exposes services like:
    - "data-extraction" — scrape and extract structured data
    - "document-verification" — forensic + logic verification
    - "market-intelligence" — NZ energy/insurance price comparison
    - "attestation" — provenance proof for physical documents
"""
import logging
from collections import defaultdict
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from typing import Any, Dict, List, Optional, Set

from protocols.agent_protocol import AgentIdentity, AgentRole

logger = logging.getLogger("AgentRegistry")


@dataclass
class ServiceListing:
    """
    A service offered by The Last Bastion or a registered agent.

    External agents can also register services they offer,
    enabling two-way discovery.
    """
    service_id: str                     # Unique ID (e.g., "svc-data-extraction")
    provider_id: str                    # Agent ID of the provider
    name: str                           # Human-readable name
    description: str
    tags: List[str] = field(default_factory=list)  # Searchable tags
    input_schema: Dict[str, Any] = field(default_factory=dict)  # Expected input format
    output_schema: Dict[str, Any] = field(default_factory=dict)  # Output format
    pricing_model: str = "per_request"  # per_request, per_field, per_byte, subscription
    base_price_credits: float = 1.0     # Base price in credits
    regions: List[str] = field(default_factory=list)  # Supported regions
    is_active: bool = True
    created_at: str = ""
    metadata: Dict[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:
        if not self.created_at:
            self.created_at = datetime.utcnow().isoformat()

    def matches_query(
        self, tags: Optional[List[str]] = None, region: Optional[str] = None
    ) -> bool:
        """Checks if this service matches a discovery query."""
        if not self.is_active:
            return False
        if tags:
            if not any(t in self.tags for t in tags):
                return False
        if region:
            if self.regions and region not in self.regions:
                return False
        return True


# The Last Bastion's own services — what we offer to the world
REGISTRY_BASE_SERVICES: List[Dict[str, Any]] = [
    {
        "service_id": "svc-data-extraction",
        "name": "Intelligent Data Extraction",
        "description": (
            "Autonomous web scraping and data extraction using "
            "browser agents. Handles anti-bot, CAPTCHAs, dynamic content."
        ),
        "tags": ["data-extraction", "scraping", "web", "automation"],
        "input_schema": {"goal": "str", "target_url": "str (optional)"},
        "output_schema": {"data": "dict", "verification_score": "float"},
        "pricing_model": "per_request",
        "base_price_credits": 5.0,
        "regions": ["nz", "au", "us", "uk", "global"],
    },
    {
        "service_id": "svc-document-verification",
        "name": "Multi-Modal Document Verification",
        "description": (
            "Forensic integrity analysis, logic triangulation, "
            "and attestation verification. Returns REJECTED/QUARANTINE/"
            "VERIFIED/GOLD verdict with proof hash."
        ),
        "tags": ["verification", "forensic", "document", "proof"],
        "input_schema": {
            "payload": "dict",
            "attachments": "list[bytes] (optional)",
            "attestation_bundle": "AttestationBundle (optional)",
        },
        "output_schema": {
            "verdict": "str", "score": "float",
            "proof_hash": "str", "evidence_chain": "list",
        },
        "pricing_model": "per_request",
        "base_price_credits": 3.0,
        "regions": ["global"],
    },
    {
        "service_id": "svc-market-intelligence",
        "name": "Market Intelligence & Comparison",
        "description": (
            "Real-time pricing data for energy, insurance, and "
            "other markets. Scraped, verified, and compared."
        ),
        "tags": ["market", "energy", "insurance", "pricing", "comparison"],
        "input_schema": {"category": "str", "region": "str"},
        "output_schema": {
            "providers": "list[dict]", "best_deal": "dict",
            "freshness_hours": "float",
        },
        "pricing_model": "per_request",
        "base_price_credits": 2.0,
        "regions": ["nz", "au"],
    },
    {
        "service_id": "svc-attestation-proof",
        "name": "Physical Document Attestation",
        "description": (
            "Proves a physical document existed at a specific "
            "location and time. GPS, depth map, device fingerprint."
        ),
        "tags": ["attestation", "proof", "provenance", "gps", "physical"],
        "input_schema": {
            "file_bytes": "bytes",
            "gps": "(lat, lon)",
            "depth_variance": "float (optional)",
        },
        "output_schema": {
            "provenance_hash": "str",
            "attestation_score": "float",
        },
        "pricing_model": "per_request",
        "base_price_credits": 4.0,
        "regions": ["global"],
    },
]


class AgentRegistry:
    """
    Central registry for agent identity and service discovery.

    Manages:
    - Agent registration and identity storage
    - Service catalog (our services + external agent services)
    - Discovery queries (find services by tags/region)
    - Agent health monitoring
    - Reputation tracking
    """

    # Agents not seen for this long are marked stale
    STALE_THRESHOLD_HOURS = 24

    def __init__(self) -> None:
        self._agents: Dict[str, AgentIdentity] = {}
        self._services: Dict[str, ServiceListing] = {}
        self._agent_services: Dict[str, List[str]] = defaultdict(list)  # agent_id -> service_ids
        self._stats = {
            "total_agents": 0,
            "active_agents": 0,
            "total_services": 0,
            "queries_served": 0,
        }

        # Register The Last Bastion's own services
        self._register_registry_base_services()

    def register_agent(
        self, identity: AgentIdentity
    ) -> Dict[str, Any]:
        """
        Registers a new agent or updates an existing one.

        Returns registration confirmation with assigned capabilities.
        """
        is_new = identity.agent_id not in self._agents
        self._agents[identity.agent_id] = identity

        if is_new:
            self._stats["total_agents"] += 1
            self._stats["active_agents"] += 1

        logger.info(
            f"{'Registered' if is_new else 'Updated'} agent: "
            f"{identity.agent_id} (role={identity.role.value}, "
            f"capabilities={identity.capabilities})"
        )

        return {
            "status": "registered" if is_new else "updated",
            "agent_id": identity.agent_id,
            "role": identity.role.value,
            "available_services": len(self._services),
            "protocol_version": "1.0.0",
        }

    def deregister_agent(self, agent_id: str) -> bool:
        """Removes an agent from the registry."""
        if agent_id not in self._agents:
            return False

        # Remove their services too
        for svc_id in self._agent_services.get(agent_id, []):
            if svc_id in self._services:
                del self._services[svc_id]
                self._stats["total_services"] -= 1

        del self._agents[agent_id]
        self._stats["total_agents"] -= 1
        self._stats["active_agents"] -= 1

        logger.info(f"Deregistered agent: {agent_id}")
        return True

    def register_service(
        self, agent_id: str, listing: ServiceListing
    ) -> bool:
        """
        Registers a service offered by an agent.

        Only registered agents can offer services.
        """
        if agent_id not in self._agents:
            logger.warning(f"Cannot register service: agent {agent_id} not registered")
            return False

        listing.provider_id = agent_id
        self._services[listing.service_id] = listing
        self._agent_services[agent_id].append(listing.service_id)
        self._stats["total_services"] += 1

        logger.info(
            f"Service registered: {listing.name} "
            f"(id={listing.service_id}, provider={agent_id})"
        )
        return True

    def discover_services(
        self,
        tags: Optional[List[str]] = None,
        region: Optional[str] = None,
        provider_id: Optional[str] = None,
    ) -> List[Dict[str, Any]]:
        """
        Discovers available services matching the query.

        Args:
            tags: Filter by capability tags (e.g., ["energy", "nz"])
            region: Filter by supported region
            provider_id: Filter by specific provider

        Returns: List of matching service listings
        """
        self._stats["queries_served"] += 1

        results = []
        for svc in self._services.values():
            if not svc.is_active:
                continue
            if provider_id and svc.provider_id != provider_id:
                continue
            if svc.matches_query(tags=tags, region=region):
                results.append({
                    "service_id": svc.service_id,
                    "name": svc.name,
                    "description": svc.description,
                    "tags": svc.tags,
                    "pricing_model": svc.pricing_model,
                    "base_price_credits": svc.base_price_credits,
                    "regions": svc.regions,
                    "provider_id": svc.provider_id,
                })

        logger.info(
            f"DISCOVER: tags={tags}, region={region} -> "
            f"{len(results)} services found"
        )
        return results

    def get_agent(self, agent_id: str) -> Optional[AgentIdentity]:
        """Returns an agent's identity if registered."""
        return self._agents.get(agent_id)

    def update_reputation(
        self, agent_id: str, delta: float
    ) -> Optional[float]:
        """
        Adjusts an agent's reputation score.

        Positive delta -> reward (successful task, good data)
        Negative delta -> penalty (bad data, replay attempt)

        Score is clamped to [0.0, 1.0].
        """
        agent = self._agents.get(agent_id)
        if not agent:
            return None

        old_score = agent.reputation_score
        agent.reputation_score = max(0.0, min(1.0, old_score + delta))

        logger.info(
            f"REPUTATION: {agent_id} {old_score:.2f} -> "
            f"{agent.reputation_score:.2f} (delta={delta:+.2f})"
        )
        return agent.reputation_score

    def get_stale_agents(self) -> List[str]:
        """Returns agent IDs that haven't been seen recently."""
        cutoff = (
            datetime.utcnow() - timedelta(hours=self.STALE_THRESHOLD_HOURS)
        ).isoformat()

        stale = []
        for agent_id, agent in self._agents.items():
            if agent.last_seen and agent.last_seen < cutoff:
                stale.append(agent_id)
        return stale

    @property
    def stats(self) -> Dict[str, int]:
        """Returns registry statistics."""
        return dict(self._stats)

    def _register_registry_base_services(self) -> None:
        """Registers The Last Bastion's built-in services."""
        for svc_data in REGISTRY_BASE_SERVICES:
            listing = ServiceListing(
                service_id=svc_data["service_id"],
                provider_id="registry-base",
                name=svc_data["name"],
                description=svc_data["description"],
                tags=svc_data["tags"],
                input_schema=svc_data.get("input_schema", {}),
                output_schema=svc_data.get("output_schema", {}),
                pricing_model=svc_data.get("pricing_model", "per_request"),
                base_price_credits=svc_data.get("base_price_credits", 1.0),
                regions=svc_data.get("regions", []),
            )
            self._services[listing.service_id] = listing
            self._stats["total_services"] += 1

        logger.info(
            f"Registered {len(REGISTRY_BASE_SERVICES)} Last Bastion services"
        )
