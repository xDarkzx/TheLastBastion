"""Last Bastion — Border Police for Agent Ecosystems."""

from lastbastion._version import __version__
from lastbastion.client import LastBastionClient
from lastbastion.passport import AgentPassport, PassportVerifier
from lastbastion.exceptions import (
    LastBastionError,
    AuthenticationError,
    RateLimitError,
    NotFoundError,
    ValidationError,
    PassportError,
    GatewayDeniedError,
)

__all__ = [
    "__version__",
    "LastBastionClient",
    "AgentPassport",
    "PassportVerifier",
    "LastBastionError",
    "AuthenticationError",
    "RateLimitError",
    "NotFoundError",
    "ValidationError",
    "PassportError",
    "GatewayDeniedError",
]

# Gateway import is deferred — requires starlette
def LastBastionGateway(*args, **kwargs):
    from lastbastion.gateway import LastBastionGateway as _GW
    return _GW(*args, **kwargs)
