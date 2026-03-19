"""Typed configuration models for the auth-manager runtime.

This module keeps the data model separate from parsing and diagnostics so the
rest of the plugin can import configuration types without pulling in the full
configuration loader implementation.
"""

from __future__ import annotations

from dataclasses import dataclass

from rbac_providers_auth_manager.authorization.policy_models import RoleFilterRule

SUPPORTED_SCHEMA_VERSION = 1
EXPECTED_PLUGIN_FAMILY = "rbac_providers_auth_manager"


@dataclass(frozen=True, slots=True)
class GeneralConfig:
    """General auth-manager settings loaded from ``permissions.ini``."""

    config_reload_seconds: int = 5
    strict_permissions: bool = True
    log_level: str = "INFO"
    deny_if_no_roles: bool = True
    trusted_proxies: tuple[str, ...] = ()
    auth_user_registration: bool = False
    auth_user_registration_role: str = "Public"
    enable_ldap: bool = True
    enable_entra_id: bool = False


@dataclass(frozen=True, slots=True)
class SecurityConfig:
    """Security-hardening settings loaded from ``permissions.ini``."""

    allow_plaintext_secrets: bool = False
    sensitive_debug_logging: bool = False
    allow_insecure_ldap_tls: bool = False

    rate_limit_backend: str = "memory"
    redis_url: str | None = None
    redis_prefix: str = "airflow_auth"

    auth_state_backend: str = "cookie"
    auth_state_redis_url: str | None = None
    auth_state_redis_prefix: str = "airflow_auth_state"
    auth_state_ttl_seconds: int = 600

    enable_ldap_rate_limit: bool = True
    ldap_max_failures: int = 5
    ldap_failure_window_seconds: int = 300
    ldap_lockout_seconds: int = 900

    enable_oauth_rate_limit: bool = True
    oauth_max_starts: int = 30
    oauth_window_seconds: int = 300
    oauth_lockout_seconds: int = 300

    enable_pkce: bool = True
    allow_graph_group_fallback: bool = False


@dataclass(frozen=True, slots=True)
class JwtCookieConfig:
    """Cookie transport settings for login/logout token exchange."""

    cookie_httponly: bool
    cookie_samesite: str
    cookie_path: str
    cookie_domain: str | None
    cookie_secure: bool | None


@dataclass(frozen=True, slots=True)
class LdapConfig:
    """LDAP provider settings for direct-bind or search-bind authentication."""

    enabled: bool
    uri: str
    bind_dn: str | None
    bind_password: str | None
    user_base_dn: str | None
    user_filter: str
    group_attribute: str
    username_dn_format: str | None
    search_base: str | None

    start_tls: bool
    allow_self_signed: bool
    tls_ca_cert_file: str | None
    tls_require_cert: str

    resolve_nested_groups: bool
    nested_groups_base_dn: str | None
    nested_group_match_rule: str | None

    connect_timeout_seconds: int
    network_timeout_seconds: int
    operation_timeout_seconds: int
    search_time_limit_seconds: int
    size_limit: int
    chase_referrals: bool

    username_pattern: str | None
    username_max_length: int

    attr_uid: str
    attr_username: str
    attr_first_name: str
    attr_last_name: str
    attr_email: str


@dataclass(frozen=True, slots=True)
class EntraIdConfig:
    """Azure Entra ID / OAuth2 SSO configuration."""

    enabled: bool
    tenant_id: str
    client_id: str
    client_secret: str

    provider_name: str
    button_text: str
    icon: str

    scope: tuple[str, ...]
    roles_claim_key: str
    verify_signature: bool
    allowed_audiences: tuple[str, ...]
    http_timeout_seconds: int
    http_max_retries: int
    http_retry_backoff_seconds: int

    metadata_url: str | None
    authorize_url: str | None
    access_token_url: str | None
    jwks_uri: str | None
    issuer: str | None

    username_claim: str
    email_claim: str
    first_name_claim: str
    last_name_claim: str
    display_name_claim: str

    graph_fetch_groups_on_overage: bool
    graph_memberof_url: str

    enable_pkce: bool
    clock_skew_seconds: int
    allowed_oidc_hosts: tuple[str, ...]


@dataclass(frozen=True, slots=True)
class RoleMappingConfig:
    """LDAP DN -> Airflow role mapping."""

    dn_to_roles: dict[str, set[str]]


@dataclass(frozen=True, slots=True)
class EntraRoleMappingConfig:
    """Azure claim value -> Airflow role mapping."""

    claim_value_to_roles: dict[str, set[str]]


@dataclass(frozen=True, slots=True)
class RolesConfig:
    """RBAC permissions keyed by Airflow role name."""

    role_to_permissions: dict[str, set[tuple[str, str]]]


@dataclass(frozen=True, slots=True)
class RoleFiltersConfig:
    """Optional scoped role filters keyed by Airflow role name."""

    role_to_filters: dict[str, RoleFilterRule]


@dataclass(frozen=True, slots=True)
class UiConfig:
    """Login-page presentation settings loaded from ``permissions.ini``."""

    enable_rich_login_status: bool = True
    show_environment: bool = True
    show_mapped_roles: bool = True
    show_reference_id: bool = True
    show_auth_method: bool = True
    compact_status_details_line: bool = True
    compact_success_status_line: bool = True

    title_ready: str = "Sign in"
    title_success: str = "Access granted"
    title_failure: str = "Sign-in failed"
    title_no_roles: str = "No Airflow access assigned"

    ldap_method_label: str = "LDAP Sign-In"
    entra_method_label: str = "Microsoft Sign-In"

    ldap_ready_text: str = "Use your enterprise username and password."
    ldap_success_text: str = (
        "Your credentials were accepted and Airflow access was assigned."
    )
    ldap_no_roles_text: str = (
        "Your credentials were accepted, but no Airflow role is mapped to your account."
    )

    entra_ready_text: str = "Use Microsoft Sign-In for enterprise SSO."
    entra_progress_text: str = "Completing Microsoft sign-in."
    entra_success_text: str = (
        "Microsoft authentication succeeded and Airflow access was assigned."
    )
    entra_no_roles_text: str = "Microsoft authentication succeeded, but no Airflow role is mapped to your account."


@dataclass(frozen=True, slots=True)
class MetaConfig:
    """Schema metadata declared by ``permissions.ini``."""

    schema_version: int = SUPPORTED_SCHEMA_VERSION
    plugin_family: str = EXPECTED_PLUGIN_FAMILY
    section_present: bool = False


@dataclass(frozen=True, slots=True)
class ConfigAdvisory:
    """A non-fatal configuration diagnostic emitted for operators."""

    severity: str
    code: str
    message: str


@dataclass(frozen=True, slots=True)
class AuthConfigValidation:
    """Validation results for provider-level configuration."""

    ldap_errors: tuple[str, ...] = ()
    entra_errors: tuple[str, ...] = ()

    @property
    def has_errors(self) -> bool:
        return bool(self.ldap_errors or self.entra_errors)


@dataclass(frozen=True, slots=True)
class AuthConfig:
    """Fully parsed configuration container for the auth manager."""

    meta: MetaConfig
    general: GeneralConfig
    security: SecurityConfig
    jwt_cookie: JwtCookieConfig
    ldap: LdapConfig | None
    entra_id: EntraIdConfig | None
    role_mapping: RoleMappingConfig
    entra_role_mapping: EntraRoleMappingConfig
    roles: RolesConfig
    role_filters: RoleFiltersConfig = RoleFiltersConfig(role_to_filters={})
    ui: UiConfig = UiConfig()
    validation: AuthConfigValidation = AuthConfigValidation()
    advisories: tuple[ConfigAdvisory, ...] = ()
