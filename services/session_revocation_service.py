"""Session revocation helpers for security-sensitive config reloads."""

from __future__ import annotations

import json
from dataclasses import asdict, is_dataclass
from typing import Any

from rbac_providers_auth_manager.core.logging_utils import get_logger
from rbac_providers_auth_manager.runtime.session_revocation_backends import (
    build_session_revocation_store,
)

log = get_logger("session_revocation")


class SessionRevocationService:
    """Manage revocation epochs and JWT freshness checks.

    The service implements a monotonic authz epoch. New JWTs include the current
    epoch and tokens issued before a sensitive configuration reload are rejected
    on their next request.
    """

    def __init__(self, manager: Any) -> None:
        self.manager = manager
        self._store = None
        self._store_signature: tuple[bool, str, str | None, str] | None = None

    def _store_config_signature(self) -> tuple[bool, str, str | None, str]:
        cfg = self.manager._cfg_loader.get_config()
        return (
            bool(cfg.security.enable_session_revocation_on_sensitive_reload),
            (cfg.security.session_revocation_backend or "memory").strip().lower(),
            cfg.security.session_revocation_redis_url,
            (
                cfg.security.session_revocation_redis_prefix
                or "airflow_auth_revocation"
            ).strip(),
        )

    def _get_store(self):
        cfg = self.manager._cfg_loader.get_config()
        signature = self._store_config_signature()
        if not cfg.security.enable_session_revocation_on_sensitive_reload:
            self._store = None
            self._store_signature = signature
            return None
        if self._store_signature == signature and self._store is not None:
            return self._store
        try:
            self._store = build_session_revocation_store(
                backend_name=cfg.security.session_revocation_backend,
                redis_url=cfg.security.session_revocation_redis_url,
                redis_prefix=cfg.security.session_revocation_redis_prefix,
            )
            self._store_signature = signature
            return self._store
        except Exception as exc:  # noqa: BLE001
            log.warning(
                "Session revocation backend %s unavailable; falling back to memory (%s)",
                cfg.security.session_revocation_backend,
                str(exc) or "session_revocation_backend_error",
            )
            self._store = build_session_revocation_store(
                backend_name="memory",
                redis_url=None,
                redis_prefix=cfg.security.session_revocation_redis_prefix,
            )
            self._store_signature = (signature[0], "memory", None, signature[3])
            if getattr(self.manager, "_audit_service", None) is not None:
                self.manager._audit_service.log_flow_event(
                    event="auth.session_revocation.backend_fallback",
                    level="warning",
                    requested_backend=cfg.security.session_revocation_backend,
                    fallback_backend="memory",
                    reason=str(exc) or "session_revocation_backend_error",
                )
            return self._store

    def current_epoch(self) -> int:
        """Return the current cluster-wide revocation epoch."""
        store = self._get_store()
        if store is None:
            return 0
        return max(0, int(store.get_epoch()))

    def token_claims_for_new_session(self) -> dict[str, int]:
        """Return JWT claims added to newly issued sessions."""
        cfg = self.manager._cfg_loader.get_config()
        if not cfg.security.enable_session_revocation_on_sensitive_reload:
            return {}
        return {"authz_epoch": self.current_epoch()}

    def validate_token_claims(self, token: dict[str, Any]) -> tuple[bool, int, int]:
        """Return whether the token is still current for the active revocation epoch."""
        cfg = self.manager._cfg_loader.get_config()
        if not cfg.security.enable_session_revocation_on_sensitive_reload:
            return True, 0, 0
        current_epoch = self.current_epoch()
        raw_epoch = token.get("authz_epoch", 0)
        try:
            token_epoch = int(raw_epoch)
        except (TypeError, ValueError):
            token_epoch = 0
        return token_epoch >= current_epoch, token_epoch, current_epoch

    def bump_epoch(self, *, reason: str, details: dict[str, Any] | None = None) -> int:
        """Invalidate previously issued sessions by incrementing the revocation epoch."""
        store = self._get_store()
        if store is None:
            return 0
        new_epoch = max(0, int(store.bump_epoch()))
        payload = {
            "event": "auth.session_revocation.bumped",
            "level": "warning",
            "reason": reason,
            "new_epoch": new_epoch,
        }
        if details:
            payload.update(details)
        if getattr(self.manager, "_audit_service", None) is not None:
            self.manager._audit_service.log_flow_event(**payload)
        log.warning(
            "Session revocation epoch bumped to %s reason=%s details=%s",
            new_epoch,
            reason,
            details or {},
        )
        return new_epoch

    @staticmethod
    def sensitive_reload_fingerprint(cfg: Any) -> str:
        """Return a deterministic fingerprint of security-sensitive auth policy state."""

        def _sorted_mapping(mapping: dict[str, set[str]]) -> list[list[str]]:
            return [
                [key, *sorted(str(value) for value in values)]
                for key, values in sorted(mapping.items())
            ]

        def _sorted_roles(mapping: dict[str, set[tuple[str, str]]]) -> list[list[str]]:
            normalized: list[list[str]] = []
            for role_name, permissions in sorted(mapping.items()):
                normalized.append(
                    [
                        role_name,
                        *sorted(
                            f"{action}:{resource}" for action, resource in permissions
                        ),
                    ]
                )
            return normalized

        def _sorted_role_filters(filters: dict[str, Any]) -> list[list[Any]]:
            normalized: list[list[Any]] = []
            for role_name, rule in sorted(filters.items()):
                if is_dataclass(rule) and not isinstance(rule, type):
                    payload = asdict(rule)
                else:
                    payload = dict(rule)
                normalized.append(
                    [
                        role_name,
                        sorted(str(item) for item in payload.get("dag_tags", ()) or ()),
                        sorted(
                            str(item) for item in payload.get("environments", ()) or ()
                        ),
                        sorted(
                            str(item)
                            for item in payload.get("resource_prefixes", ()) or ()
                        ),
                    ]
                )
            return normalized

        payload = {
            "strict_permissions": bool(cfg.general.strict_permissions),
            "deny_if_no_roles": bool(cfg.general.deny_if_no_roles),
            "auth_user_registration": bool(cfg.general.auth_user_registration),
            "auth_user_registration_role": str(
                cfg.general.auth_user_registration_role or ""
            ).strip(),
            "role_mapping": _sorted_mapping(cfg.role_mapping.dn_to_roles),
            "entra_role_mapping": _sorted_mapping(
                cfg.entra_role_mapping.claim_value_to_roles
            ),
            "roles": _sorted_roles(cfg.roles.role_to_permissions),
            "role_filters": _sorted_role_filters(cfg.role_filters.role_to_filters),
        }
        return json.dumps(payload, sort_keys=True, separators=(",", ":"))
