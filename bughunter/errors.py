from __future__ import annotations


class BughunterError(Exception):
    """Base class for expected, user-facing errors."""


class PolicyError(BughunterError):
    """The policy file is missing, malformed, or unsafe."""


class AuthorizationError(BughunterError):
    """The policy does not prove authorization to test the target."""


class PolicyDenied(BughunterError):
    """A specific action was blocked by the policy gate."""

    def __init__(self, reason: str, *, url: str | None = None, host: str | None = None):
        self.reason = reason
        self.url = url
        self.host = host
        target = f" ({url})" if url else (f" ({host})" if host else "")
        super().__init__(f"{reason}{target}")
