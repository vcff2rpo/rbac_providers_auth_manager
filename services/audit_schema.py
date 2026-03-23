"""Canonical audit event schema metadata.

The registry documents the stable event namespace emitted by the auth manager.
It is intentionally small and additive so downstream operators can build SIEM
parsers against a versioned schema instead of inferring field meaning from
free-form log payloads.
"""

from __future__ import annotations

AUDIT_SCHEMA_VERSION = 1

AUDIT_EVENT_REGISTRY: dict[str, dict[str, object]] = {
    "ui.auth.login.blocked": {
        "description": "Browser login was blocked before credential verification.",
        "required_fields": ("timestamp", "schema_version", "event", "severity"),
    },
    "ui.auth.login.failure": {
        "description": "Browser login failed during credential verification.",
        "required_fields": (
            "timestamp",
            "schema_version",
            "event",
            "severity",
            "provider",
        ),
    },
    "ui.auth.login.success": {
        "description": "Browser login succeeded and roles were assigned.",
        "required_fields": (
            "timestamp",
            "schema_version",
            "event",
            "severity",
            "provider",
            "roles",
        ),
    },
    "ui.auth.oauth_login.started": {
        "description": "OAuth browser redirect flow was started.",
        "required_fields": (
            "timestamp",
            "schema_version",
            "event",
            "severity",
            "provider",
        ),
    },
    "ui.auth.oauth_login.blocked": {
        "description": "OAuth browser login was blocked before redirect.",
        "required_fields": (
            "timestamp",
            "schema_version",
            "event",
            "severity",
            "provider",
        ),
    },
    "ui.auth.oauth_login.failure": {
        "description": "OAuth browser login failed before callback completion.",
        "required_fields": (
            "timestamp",
            "schema_version",
            "event",
            "severity",
            "provider",
        ),
    },
    "ui.auth.oauth_login.throttled": {
        "description": "OAuth browser login was throttled by rate limiting.",
        "required_fields": (
            "timestamp",
            "schema_version",
            "event",
            "severity",
            "provider",
            "retry_after",
        ),
    },
    "ui.auth.oauth_callback.failure": {
        "description": "OAuth callback failed while exchanging or validating tokens.",
        "required_fields": (
            "timestamp",
            "schema_version",
            "event",
            "severity",
            "provider",
        ),
    },
    "ui.auth.oauth_callback.rejected": {
        "description": "OAuth callback was rejected for state or validation reasons.",
        "required_fields": (
            "timestamp",
            "schema_version",
            "event",
            "severity",
            "provider",
        ),
    },
    "api.auth.token.success": {
        "description": "API or CLI token issuance succeeded.",
        "required_fields": ("timestamp", "schema_version", "event", "severity", "mode"),
    },
    "api.auth.token.failure": {
        "description": "API or CLI token issuance failed.",
        "required_fields": ("timestamp", "schema_version", "event", "severity", "mode"),
    },
    "auth.role_mapping.empty": {
        "description": "Authentication succeeded but no Airflow roles were mapped.",
        "required_fields": (
            "timestamp",
            "schema_version",
            "event",
            "severity",
            "provider",
        ),
    },
    "auth.role_mapping.dropped": {
        "description": "Mapped roles were dropped due to strict-role filtering.",
        "required_fields": (
            "timestamp",
            "schema_version",
            "event",
            "severity",
            "provider",
        ),
    },
    "auth.role_mapping.hits": {
        "description": "External identity values were mapped to Airflow roles.",
        "required_fields": (
            "timestamp",
            "schema_version",
            "event",
            "severity",
            "provider",
        ),
    },
}

AUDIT_EVENT_ALIASES: dict[str, str] = {
    "auth.browser_login.blocked": "ui.auth.login.blocked",
    "auth.browser_login.failure": "ui.auth.login.failure",
    "auth.oauth_login.blocked": "ui.auth.oauth_login.blocked",
    "auth.oauth_login.failure": "ui.auth.oauth_login.failure",
    "auth.oauth_login.started": "ui.auth.oauth_login.started",
    "auth.oauth_login.throttled": "ui.auth.oauth_login.throttled",
    "auth.oauth_callback.failure": "ui.auth.oauth_callback.failure",
    "auth.oauth_callback.rejected": "ui.auth.oauth_callback.rejected",
}


def canonical_audit_event_name(event: str) -> str:
    """Return the canonical event name for a legacy or current audit event."""
    normalized = (event or "").strip()
    if not normalized:
        return "auth.unknown"
    return AUDIT_EVENT_ALIASES.get(normalized, normalized)
