"""Custom exceptions for the Last Bastion SDK."""


class LastBastionError(Exception):
    """Base exception for all SDK errors."""
    def __init__(self, message: str, status_code: int = None, detail: dict = None):
        self.message = message
        self.status_code = status_code
        self.detail = detail or {}
        super().__init__(message)


class AuthenticationError(LastBastionError):
    """API key invalid, expired, or revoked."""
    pass


class RateLimitError(LastBastionError):
    """Rate limit exceeded."""
    pass


class NotFoundError(LastBastionError):
    """Resource not found."""
    pass


class ValidationError(LastBastionError):
    """Request validation failed."""
    pass


class PassportError(LastBastionError):
    """Passport verification or issuance failed."""
    pass


class GatewayDeniedError(LastBastionError):
    """Agent denied entry by the gateway."""
    pass
