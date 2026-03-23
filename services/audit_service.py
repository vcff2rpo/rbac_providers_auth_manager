"""Structured audit helpers for authentication and role-mapping flows.

The service keeps auth-related logging vocabulary in one place so route and
mapping code can emit consistent operator-facing events without duplicating
string formats throughout the plugin. Audit entries are emitted as structured
JSON and also attached to log records through ``extra`` fields so downstream log
pipelines can extract stable metadata without reparsing free-form messages.
"""

from __future__ import annotations

import json
import secrets
from datetime import datetime, UTC
from typing import Any

from rbac_providers_auth_manager.core.logging_utils import get_logger
from rbac_providers_auth_manager.services.audit_schema import (
    AUDIT_EVENT_REGISTRY,
    AUDIT_SCHEMA_VERSION,
    canonical_audit_event_name,
)

log = get_logger("audit")


class AuditService:
    """Create UI references and structured auth audit log entries."""

    @staticmethod
    def make_ui_reference() -> str:
        """Return a short correlation token safe to expose in the UI."""
        return secrets.token_urlsafe(6).replace("-", "").replace("_", "").upper()[:10]

    @staticmethod
    def _infer_surface(event: str) -> str | None:
        """Infer the execution surface from the event namespace."""
        if event.startswith("ui."):
            return "ui"
        if event.startswith("api."):
            return "api"
        return None

    @staticmethod
    def _infer_outcome(event: str) -> str | None:
        """Infer the event outcome from the trailing event token."""
        suffix = (event or "").rsplit(".", 1)[-1]
        outcomes = {
            "blocked",
            "failure",
            "rejected",
            "started",
            "success",
            "throttled",
            "fallback",
            "disabled",
            "empty",
            "dropped",
            "hits",
        }
        if suffix in outcomes:
            return suffix
        return None

    @staticmethod
    def _registry_status(event: str) -> str:
        """Return whether the canonical event is documented in the registry."""
        return "registered" if event in AUDIT_EVENT_REGISTRY else "unregistered"

    @staticmethod
    def _clean_fields(**fields: Any) -> dict[str, Any]:
        """Drop null values while keeping ``False`` and zero-like values intact."""
        return {key: value for key, value in fields.items() if value is not None}

    @classmethod
    def _build_payload(cls, *, event: str, level: str, **fields: Any) -> dict[str, Any]:
        """Build the final structured payload emitted into logs."""
        canonical_event = canonical_audit_event_name(event)
        payload = {
            "timestamp": datetime.now(UTC).isoformat(),
            "schema_version": AUDIT_SCHEMA_VERSION,
            "event": canonical_event,
            "severity": (level or "info").lower(),
            **cls._clean_fields(
                legacy_event=event if canonical_event != event else None,
                registry_status=cls._registry_status(canonical_event),
                surface=cls._infer_surface(canonical_event),
                outcome=cls._infer_outcome(canonical_event),
                **fields,
            ),
        }
        return payload

    @classmethod
    def _emit(cls, *, event: str, level: str = "info", **fields: Any) -> None:
        """Emit a structured audit log entry as one JSON object."""
        payload = cls._build_payload(event=event, level=level, **fields)
        level_name = (level or "info").lower()
        log_method = getattr(log, level_name, log.info)
        message = json.dumps(payload, sort_keys=True, default=str)
        log_method(
            message,
            extra={
                "audit_event": True,
                "audit_event_name": payload["event"],
                "audit_schema_version": payload["schema_version"],
                "audit_payload": payload,
            },
        )

    def log_flow_event(self, *, event: str, level: str = "info", **fields: Any) -> None:
        """Emit a structured audit event for login/logout/browser flow actions."""
        self._emit(event=event, level=level, **fields)

    def log_role_mapping_empty(
        self,
        *,
        provider: str,
        principal: str,
        subject: str,
        ip_address: str,
        external_values_count: int,
        mapped_values_count: int,
        strict_permissions: bool,
        deny_if_no_roles: bool,
    ) -> None:
        """Log that authentication succeeded but no Airflow role was mapped."""
        self._emit(
            event="auth.role_mapping.empty",
            provider=provider.lower(),
            principal=principal,
            subject=subject,
            ip_address=ip_address,
            external_values_count=external_values_count,
            mapped_values_count=mapped_values_count,
            strict_permissions=strict_permissions,
            deny_if_no_roles=deny_if_no_roles,
        )

    def log_provider_success(
        self,
        *,
        provider: str,
        principal: str,
        subject: str,
        ip_address: str,
        roles: list[str] | tuple[str, ...],
        external_values_count: int,
        mapped_values_count: int,
        strict_permissions: bool,
        surface: str | None = None,
    ) -> None:
        """Log a successful provider authentication and role-assignment result."""
        event = "auth.login.success"
        if surface:
            event = f"{surface.lower()}.auth.login.success"
        self._emit(
            event=event,
            provider=provider.lower(),
            principal=principal,
            subject=subject,
            ip_address=ip_address,
            roles=list(roles),
            external_values_count=external_values_count,
            mapped_values_count=mapped_values_count,
            strict_permissions=strict_permissions,
        )

    def log_dropped_roles(
        self,
        *,
        provider: str,
        principal: str,
        dropped_roles: list[str] | tuple[str, ...],
        strict_mode: bool,
    ) -> None:
        """Log roles that were ignored because they were undefined in strict mode."""
        if not dropped_roles:
            return
        self._emit(
            event="auth.role_mapping.dropped",
            provider=provider.lower(),
            principal=principal,
            dropped_roles=list(dropped_roles),
            strict_mode=strict_mode,
        )

    def log_mapping_hits(
        self,
        *,
        provider: str,
        principal: str,
        mapping_hits: list[tuple[str, list[str] | tuple[str, ...]]]
        | tuple[tuple[str, list[str] | tuple[str, ...]], ...],
    ) -> None:
        """Log resolved external-value to Airflow-role mapping hits at debug level."""
        self._emit(
            event="auth.role_mapping.hits",
            level="debug",
            provider=provider.lower(),
            principal=principal,
            mapping_hits=[
                (external_value, list(mapped_roles))
                for external_value, mapped_roles in mapping_hits
            ],
        )

    def log_token_issue(
        self,
        *,
        mode: str,
        principal: str | None,
        ip_address: str,
        outcome: str,
        detail: str | None = None,
    ) -> None:
        """Emit a structured audit event for API or CLI token issuance."""
        level = "info" if outcome == "success" else "warning"
        event = f"api.auth.token.{outcome}"
        self._emit(
            event=event,
            level=level,
            mode=(mode or "api").lower(),
            principal=principal,
            ip_address=ip_address,
            detail=detail,
        )
