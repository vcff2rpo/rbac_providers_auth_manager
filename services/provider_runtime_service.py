"""Provider lifecycle, rate limiting, and config-refresh helpers."""

from __future__ import annotations

from typing import Any

from rbac_providers_auth_manager.core.exceptions import OptionalProviderDependencyError
from rbac_providers_auth_manager.core.logging_utils import configure_logging, get_logger
from rbac_providers_auth_manager.providers.entra_provider import EntraAuthProvider
from rbac_providers_auth_manager.providers.ldap_provider import LdapAuthProvider
from rbac_providers_auth_manager.authorization.rbac import RbacPolicy
from rbac_providers_auth_manager.runtime.rate_limit_backends import build_rate_limiter

log = get_logger("auth_manager")


class ProviderRuntimeService:
    """Own provider construction, runtime refresh, and rate-limit state."""

    def __init__(self, manager: Any) -> None:
        self.manager = manager

    @staticmethod
    def build_ldap_client(cfg: Any) -> Any | None:
        """Create an LDAP client lazily and degrade cleanly when extras are missing."""
        if cfg.ldap is None:
            return None
        from rbac_providers_auth_manager.providers.ldap_client import LdapClient

        return LdapClient(cfg.ldap)

    @staticmethod
    def build_entra_client(cfg: Any) -> Any | None:
        """Create an Entra client lazily and degrade cleanly when extras are missing."""
        if cfg.entra_id is None:
            return None
        from rbac_providers_auth_manager.providers.entra_client import EntraIdClient

        return EntraIdClient(cfg.entra_id)

    def initialize_provider_clients(
        self, cfg: Any
    ) -> tuple[Any | None, Any | None, list[str]]:
        """Build provider clients and collect non-fatal dependency/load errors."""
        provider_errors: list[str] = []

        ldap_client = None
        if cfg.ldap is not None:
            try:
                ldap_client = self.build_ldap_client(cfg)
            except OptionalProviderDependencyError as exc:
                provider_errors.append(str(exc))
                self.manager._audit_service.log_flow_event(
                    event="auth.provider.disabled",
                    level="warning",
                    provider="ldap",
                    reason=str(exc),
                )

        entra_client = None
        if cfg.entra_id is not None:
            try:
                entra_client = self.build_entra_client(cfg)
            except OptionalProviderDependencyError as exc:
                provider_errors.append(str(exc))
                self.manager._audit_service.log_flow_event(
                    event="auth.provider.disabled",
                    level="warning",
                    provider="entra",
                    reason=str(exc),
                )

        return ldap_client, entra_client, provider_errors

    def configure_rate_limiters(self, cfg: Any) -> None:
        """Create rate limiter backends for LDAP and OAuth flows."""
        common_kwargs = {
            "backend_name": cfg.security.rate_limit_backend,
            "redis_url": cfg.security.redis_url,
            "redis_prefix": cfg.security.redis_prefix,
        }

        self.manager._ldap_rate_limiter = build_rate_limiter(
            scope="ldap",
            max_events=cfg.security.ldap_max_failures,
            window_seconds=cfg.security.ldap_failure_window_seconds,
            lockout_seconds=cfg.security.ldap_lockout_seconds,
            **common_kwargs,
        )
        self.manager._oauth_rate_limiter = build_rate_limiter(
            scope="oauth",
            max_events=cfg.security.oauth_max_starts,
            window_seconds=cfg.security.oauth_window_seconds,
            lockout_seconds=cfg.security.oauth_lockout_seconds,
            **common_kwargs,
        )

    def check_ldap_rate_limit(
        self, *, username: str, request: Any | None
    ) -> tuple[bool, int]:
        """Return whether the LDAP login attempt is allowed."""
        if self.manager._ldap_rate_limiter is None:
            return True, 0
        key = self.manager._limit_key(
            "ldap", username, self.manager._client_ip(request)
        )
        decision = self.manager._ldap_rate_limiter.check(key=key)
        return decision.allowed, decision.retry_after_seconds

    def record_ldap_failure(self, *, username: str, request: Any | None) -> int:
        """Record a failed LDAP login attempt and return any retry-after value."""
        if self.manager._ldap_rate_limiter is None:
            return 0
        key = self.manager._limit_key(
            "ldap", username, self.manager._client_ip(request)
        )
        decision = self.manager._ldap_rate_limiter.record_event(key=key)
        return 0 if decision.allowed else decision.retry_after_seconds

    def clear_ldap_failures(self, *, username: str, request: Any | None) -> None:
        """Clear rate-limit state after a successful LDAP login."""
        if self.manager._ldap_rate_limiter is None:
            return
        key = self.manager._limit_key(
            "ldap", username, self.manager._client_ip(request)
        )
        self.manager._ldap_rate_limiter.reset(key=key)

    def check_oauth_rate_limit(self, *, request: Any | None) -> tuple[bool, int]:
        """Return whether the OAuth/SSO start attempt is allowed."""
        if self.manager._oauth_rate_limiter is None:
            return True, 0
        key = self.manager._limit_key(
            "oauth", "entra", self.manager._client_ip(request)
        )
        decision = self.manager._oauth_rate_limiter.check(key=key)
        return decision.allowed, decision.retry_after_seconds

    def record_oauth_start(self, *, request: Any | None) -> int:
        """Record an OAuth login start and return any retry-after value."""
        if self.manager._oauth_rate_limiter is None:
            return 0
        key = self.manager._limit_key(
            "oauth", "entra", self.manager._client_ip(request)
        )
        decision = self.manager._oauth_rate_limiter.record_event(key=key)
        return 0 if decision.allowed else decision.retry_after_seconds

    def refresh_if_needed(self) -> None:
        """Refresh providers, policy, and logging when config changes on disk."""
        cfg = self.manager._cfg_loader.get_config()
        configure_logging(cfg.general.log_level)

        previous_error = self.manager._config_error_message
        ldap_client, entra_client, provider_errors = self.initialize_provider_clients(
            cfg
        )

        new_ldap_provider = LdapAuthProvider(self.manager, ldap_client)
        new_entra_provider = EntraAuthProvider(self.manager, entra_client)
        enabled_methods = [
            name
            for name, enabled in (
                ("ldap", new_ldap_provider.is_enabled()),
                ("entra_id", new_entra_provider.is_enabled()),
            )
            if enabled
        ]
        if provider_errors and not enabled_methods:
            new_config_error = " | ".join(provider_errors)
        else:
            new_config_error = None

        self.manager._ldap_provider = new_ldap_provider
        self.manager._entra_provider = new_entra_provider
        self.manager._policy = RbacPolicy(cfg)
        self.manager._provider_load_errors = provider_errors
        self.manager._config_error_message = new_config_error

        self.configure_rate_limiters(cfg)
        self.manager._log_runtime_capability_report(cfg)

        if new_config_error:
            log.error(
                "Auth manager remains in degraded mode after reload: %s",
                new_config_error,
            )
        elif previous_error:
            log.info(
                "Auth manager recovered from degraded mode; methods=%s", enabled_methods
            )
