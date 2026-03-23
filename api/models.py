"""JSON-facing auth flow models used by browser and API surfaces.

These models keep auth flow state transportable without depending on FastAPI or
Airflow response classes. Browser routes and JSON routes can therefore render
from the same normalized result objects.
"""

from __future__ import annotations

from dataclasses import asdict, dataclass


@dataclass(frozen=True, slots=True)
class ProviderMethodState:
    """Describe whether a configured authentication method is currently usable."""

    identifier: str
    label: str
    enabled: bool

    def to_dict(self) -> dict[str, object]:
        """Return a JSON-safe representation of the method state."""
        return asdict(self)


@dataclass(frozen=True, slots=True)
class ProviderReadinessPayload:
    """Describe browser sign-in readiness for the configured providers."""

    auth_config_broken: bool
    environment_label: str
    support_contact: str
    methods: tuple[ProviderMethodState, ...]

    def to_dict(self) -> dict[str, object]:
        """Return a JSON-safe representation of the readiness payload."""
        return {
            "auth_config_broken": self.auth_config_broken,
            "environment_label": self.environment_label,
            "support_contact": self.support_contact,
            "methods": [method.to_dict() for method in self.methods],
        }


@dataclass(frozen=True, slots=True)
class LoginStatusPayload:
    """Describe the normalized login-status state shown to browser users."""

    level: str
    title: str
    message: str
    error: str | None
    status_value: str | None
    reference: str | None
    method: str | None
    stage: str | None
    roles: tuple[str, ...]
    retry_after: int
    next_url: str | None
    auto_redirect_seconds: int
    environment_label: str

    def to_dict(self) -> dict[str, object]:
        """Return a JSON-safe representation of the login-status payload."""
        return {
            "level": self.level,
            "title": self.title,
            "message": self.message,
            "error": self.error,
            "status_value": self.status_value,
            "reference": self.reference,
            "method": self.method,
            "stage": self.stage,
            "roles": list(self.roles),
            "retry_after": self.retry_after,
            "next_url": self.next_url,
            "auto_redirect_seconds": self.auto_redirect_seconds,
            "environment_label": self.environment_label,
        }


@dataclass(frozen=True, slots=True)
class OAuthCallbackStatePayload:
    """Describe normalized Entra callback request state for diagnostics."""

    next_url: str
    state_supplied: bool
    code_supplied: bool
    callback_error: str | None
    callback_error_description: str | None
    cookies_present: tuple[str, ...]

    def to_dict(self) -> dict[str, object]:
        """Return a JSON-safe representation of the callback-state payload."""
        return {
            "next_url": self.next_url,
            "state_supplied": self.state_supplied,
            "code_supplied": self.code_supplied,
            "callback_error": self.callback_error,
            "callback_error_description": self.callback_error_description,
            "cookies_present": list(self.cookies_present),
        }


@dataclass(frozen=True, slots=True)
class LogoutStatePayload:
    """Describe the logout redirect target and cookie cleanup scope."""

    login_url: str
    status_value: str
    transient_cookie_names: tuple[str, ...]

    def to_dict(self) -> dict[str, object]:
        """Return a JSON-safe representation of the logout payload."""
        return {
            "login_url": self.login_url,
            "status_value": self.status_value,
            "transient_cookie_names": list(self.transient_cookie_names),
        }


@dataclass(frozen=True, slots=True)
class TokenIssueResult:
    """Describe a successfully issued API or CLI token."""

    access_token: str
    expiration_key: str
    auth_backend: str = "ldap"

    def to_dict(self) -> dict[str, object]:
        """Return a JSON-safe representation of the token result."""
        return {
            "access_token": self.access_token,
            "expiration_key": self.expiration_key,
            "auth_backend": self.auth_backend,
        }
