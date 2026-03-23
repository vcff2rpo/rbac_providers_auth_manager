"""Section-oriented parsers for general runtime configuration."""

from __future__ import annotations

import configparser
import logging

from rbac_providers_auth_manager.config_runtime.models import (
    EXPECTED_PLUGIN_FAMILY,
    SUPPORTED_SCHEMA_VERSION,
    GeneralConfig,
    JwtCookieConfig,
    MetaConfig,
    SecurityConfig,
    UiConfig,
)
from rbac_providers_auth_manager.config_runtime.parse_helpers import (
    get_any,
    get_bool,
    get_int,
    section_aliases,
)
from rbac_providers_auth_manager.core.util import parse_csv

log = logging.getLogger(__name__)


def parse_meta(parser: configparser.ConfigParser) -> MetaConfig:
    """Parse schema metadata and validate the declared plugin family/version."""
    section = "meta"
    section_present = parser.has_section(section)

    raw_schema_version = get_any(
        parser,
        [section],
        ["schema_version"],
        str(SUPPORTED_SCHEMA_VERSION),
    ) or str(SUPPORTED_SCHEMA_VERSION)
    try:
        schema_version = int(raw_schema_version)
    except ValueError as exc:
        raise ValueError(
            f"Invalid meta.schema_version: {raw_schema_version!r}"
        ) from exc

    if schema_version != SUPPORTED_SCHEMA_VERSION:
        raise ValueError(
            "Unsupported permissions.ini schema version: "
            f"{schema_version}; expected {SUPPORTED_SCHEMA_VERSION}"
        )

    plugin_family = (
        get_any(
            parser,
            [section],
            ["plugin_family"],
            EXPECTED_PLUGIN_FAMILY,
        )
        or EXPECTED_PLUGIN_FAMILY
    ).strip()
    if plugin_family != EXPECTED_PLUGIN_FAMILY:
        raise ValueError(
            "Unsupported meta.plugin_family: "
            f"{plugin_family!r}; expected {EXPECTED_PLUGIN_FAMILY!r}"
        )

    return MetaConfig(
        schema_version=schema_version,
        plugin_family=plugin_family,
        section_present=section_present,
    )


def parse_general(parser: configparser.ConfigParser) -> GeneralConfig:
    """Parse the ``[general]`` section."""
    sections = section_aliases("general")

    strict_permissions = get_bool(parser, sections, ["strict_permissions"], True)
    deny_if_no_roles = get_bool(parser, sections, ["deny_if_no_roles"], True)
    auth_user_registration = get_bool(
        parser, sections, ["auth_user_registration"], False
    )
    auth_user_registration_role = (
        get_any(parser, sections, ["auth_user_registration_role"], "Public") or "Public"
    ).strip()

    return GeneralConfig(
        config_reload_seconds=get_int(parser, sections, ["config_reload_seconds"], 5),
        strict_permissions=strict_permissions,
        log_level=get_any(parser, sections, ["log_level"], "INFO") or "INFO",
        deny_if_no_roles=deny_if_no_roles,
        trusted_proxies=tuple(
            parse_csv(get_any(parser, sections, ["trusted_proxies"], "") or "")
        ),
        auth_user_registration=auth_user_registration,
        auth_user_registration_role=auth_user_registration_role,
        enable_ldap=get_bool(parser, sections, ["enable_ldap"], True),
        enable_entra_id=get_bool(parser, sections, ["enable_entra_id"], False),
    )


def parse_security(parser: configparser.ConfigParser) -> SecurityConfig:
    """Parse the optional ``[security]`` section."""
    sections = ["security"]
    return SecurityConfig(
        allow_plaintext_secrets=get_bool(
            parser, sections, ["allow_plaintext_secrets"], False
        ),
        sensitive_debug_logging=get_bool(
            parser, sections, ["sensitive_debug_logging"], False
        ),
        allow_insecure_ldap_tls=get_bool(
            parser, sections, ["allow_insecure_ldap_tls"], False
        ),
        rate_limit_backend=(
            get_any(parser, sections, ["rate_limit_backend"], "memory") or "memory"
        )
        .strip()
        .lower(),
        redis_url=get_any(parser, sections, ["redis_url"], None),
        redis_prefix=(
            get_any(parser, sections, ["redis_prefix"], "airflow_auth")
            or "airflow_auth"
        ).strip(),
        auth_state_backend=(
            get_any(parser, sections, ["auth_state_backend"], "cookie") or "cookie"
        )
        .strip()
        .lower(),
        auth_state_redis_url=get_any(parser, sections, ["auth_state_redis_url"], None),
        auth_state_redis_prefix=(
            get_any(parser, sections, ["auth_state_redis_prefix"], "airflow_auth_state")
            or "airflow_auth_state"
        ).strip(),
        auth_state_ttl_seconds=get_int(
            parser, sections, ["auth_state_ttl_seconds"], 600
        ),
        enable_session_revocation_on_sensitive_reload=get_bool(
            parser, sections, ["enable_session_revocation_on_sensitive_reload"], True
        ),
        session_revocation_backend=(
            get_any(parser, sections, ["session_revocation_backend"], "memory")
            or "memory"
        )
        .strip()
        .lower(),
        session_revocation_redis_url=get_any(
            parser, sections, ["session_revocation_redis_url"], None
        ),
        session_revocation_redis_prefix=(
            get_any(
                parser,
                sections,
                ["session_revocation_redis_prefix"],
                "airflow_auth_revocation",
            )
            or "airflow_auth_revocation"
        ).strip(),
        enable_ldap_rate_limit=get_bool(
            parser, sections, ["enable_ldap_rate_limit"], True
        ),
        ldap_max_failures=get_int(parser, sections, ["ldap_max_failures"], 5),
        ldap_failure_window_seconds=get_int(
            parser, sections, ["ldap_failure_window_seconds"], 300
        ),
        ldap_lockout_seconds=get_int(parser, sections, ["ldap_lockout_seconds"], 900),
        enable_oauth_rate_limit=get_bool(
            parser, sections, ["enable_oauth_rate_limit"], True
        ),
        oauth_max_starts=get_int(parser, sections, ["oauth_max_starts"], 30),
        oauth_window_seconds=get_int(parser, sections, ["oauth_window_seconds"], 300),
        oauth_lockout_seconds=get_int(parser, sections, ["oauth_lockout_seconds"], 300),
        enable_pkce=get_bool(parser, sections, ["enable_pkce"], True),
        allow_graph_group_fallback=get_bool(
            parser, sections, ["allow_graph_group_fallback"], False
        ),
    )


def parse_ui(parser: configparser.ConfigParser) -> UiConfig:
    """Parse login-page UI presentation settings."""
    sections = ["ui"]
    return UiConfig(
        enable_rich_login_status=get_bool(
            parser, sections, ["enable_rich_login_status"], True
        ),
        show_environment=get_bool(parser, sections, ["show_environment"], True),
        show_mapped_roles=get_bool(parser, sections, ["show_mapped_roles"], True),
        show_reference_id=get_bool(parser, sections, ["show_reference_id"], True),
        show_auth_method=get_bool(parser, sections, ["show_auth_method"], True),
        compact_status_details_line=get_bool(
            parser, sections, ["compact_status_details_line"], True
        ),
        compact_success_status_line=get_bool(
            parser, sections, ["compact_success_status_line"], True
        ),
        title_ready=get_any(parser, sections, ["title_ready"], "Sign in") or "Sign in",
        title_success=get_any(parser, sections, ["title_success"], "Access granted")
        or "Access granted",
        title_failure=get_any(parser, sections, ["title_failure"], "Sign-in failed")
        or "Sign-in failed",
        title_no_roles=(
            get_any(parser, sections, ["title_no_roles"], "No Airflow access assigned")
            or "No Airflow access assigned"
        ),
        ldap_method_label=(
            get_any(parser, sections, ["ldap_method_label"], "LDAP Sign-In")
            or "LDAP Sign-In"
        ),
        entra_method_label=(
            get_any(parser, sections, ["entra_method_label"], "Microsoft Sign-In")
            or "Microsoft Sign-In"
        ),
        ldap_ready_text=(
            get_any(
                parser,
                sections,
                ["ldap_ready_text"],
                "Use your enterprise username and password.",
            )
            or "Use your enterprise username and password."
        ),
        ldap_success_text=(
            get_any(
                parser,
                sections,
                ["ldap_success_text"],
                "Your credentials were accepted and Airflow access was assigned.",
            )
            or "Your credentials were accepted and Airflow access was assigned."
        ),
        ldap_no_roles_text=(
            get_any(
                parser,
                sections,
                ["ldap_no_roles_text"],
                "Your credentials were accepted, but no Airflow role is mapped to your account.",
            )
            or "Your credentials were accepted, but no Airflow role is mapped to your account."
        ),
        entra_ready_text=(
            get_any(
                parser,
                sections,
                ["entra_ready_text"],
                "Use Microsoft Sign-In for enterprise SSO.",
            )
            or "Use Microsoft Sign-In for enterprise SSO."
        ),
        entra_progress_text=(
            get_any(
                parser,
                sections,
                ["entra_progress_text"],
                "Completing Microsoft sign-in.",
            )
            or "Completing Microsoft sign-in."
        ),
        entra_success_text=(
            get_any(
                parser,
                sections,
                ["entra_success_text"],
                "Microsoft authentication succeeded and Airflow access was assigned.",
            )
            or "Microsoft authentication succeeded and Airflow access was assigned."
        ),
        entra_no_roles_text=(
            get_any(
                parser,
                sections,
                ["entra_no_roles_text"],
                "Microsoft authentication succeeded, but no Airflow role is mapped to your account.",
            )
            or "Microsoft authentication succeeded, but no Airflow role is mapped to your account."
        ),
    )


def parse_jwt_cookie(parser: configparser.ConfigParser) -> JwtCookieConfig:
    """Parse the JWT token cookie settings."""
    sections = section_aliases("jwt_cookie")

    cookie_samesite = (
        (get_any(parser, sections, ["cookie_samesite", "samesite"], "lax") or "lax")
        .lower()
        .strip()
    )
    if cookie_samesite not in {"lax", "strict", "none"}:
        log.warning("Invalid jwt.cookie_samesite=%r; forcing 'lax'", cookie_samesite)
        cookie_samesite = "lax"

    cookie_path = get_any(parser, sections, ["cookie_path", "path"], "/") or "/"
    cookie_domain = get_any(parser, sections, ["cookie_domain", "domain"], None)

    raw_secure = (
        (get_any(parser, sections, ["cookie_secure", "secure"], "auto") or "auto")
        .lower()
        .strip()
    )
    if raw_secure in {"auto", ""}:
        cookie_secure: bool | None = None
    else:
        cookie_secure = get_bool(parser, sections, ["cookie_secure", "secure"], True)

    cookie_httponly = get_bool(parser, sections, ["cookie_httponly", "httponly"], True)
    if not cookie_httponly:
        log.warning(
            "jwt.cookie_httponly=false is not supported for Airflow 3.1.1+; forcing it to true"
        )
        cookie_httponly = True

    return JwtCookieConfig(
        cookie_httponly=cookie_httponly,
        cookie_samesite=cookie_samesite,
        cookie_path=cookie_path,
        cookie_domain=cookie_domain or None,
        cookie_secure=cookie_secure,
    )
