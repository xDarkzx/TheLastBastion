"""Custom exceptions for the Last Bastion SDK."""


class RegistryBaseError(Exception):
    """Base exception for all SDK errors."""
    def __init__(self, message: str, status_code: int = None, detail: dict = None):
        self.message = message
        self.status_code = status_code
        self.detail = detail or {}
        super().__init__(message)


class AuthenticationError(RegistryBaseError):
    """API key invalid, expired, or revoked."""
    pass


class RateLimitError(RegistryBaseError):
    """Rate limit exceeded."""
    pass


class NotFoundError(RegistryBaseError):
    """Resource not found."""
    pass


class ValidationError(RegistryBaseError):
    """Request validation failed."""
    pass
