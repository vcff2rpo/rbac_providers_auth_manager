"""Provider-specific configuration parsers and validators."""

from __future__ import annotations

import configparser
import logging

from rbac_providers_auth_manager.config_runtime.models import (
    EntraIdConfig,
    LdapConfig,
    SecurityConfig,
)
from rbac_providers_auth_manager.config_runtime.parse_helpers import (
    get_any,
    get_bool,
    get_int,
    has_any_section,
    section_aliases,
)
from rbac_providers_auth_manager.runtime.security import resolve_secret_reference
from rbac_providers_auth_manager.core.util import parse_csv

log = logging.getLogger(__name__)


def parse_ldap(
    parser: configparser.ConfigParser,
    *,
    enabled: bool,
    security: SecurityConfig,
) -> LdapConfig | None:
    """Parse the LDAP provider section.

    The provider is considered enabled only when either:
    - the global mode enables LDAP and the section exists, or
    - the section explicitly sets ``enabled = true``.

    Mandatory-value validation is performed later so one invalid provider
    can be disabled while another valid provider still starts.
    """
    sections = section_aliases("ldap")
    section_present = has_any_section(parser, sections)
    ldap_enabled = get_bool(
        parser, sections, ["enabled"], enabled if section_present else False
    )
    if not ldap_enabled:
        return None

    uri = get_any(parser, sections, ["uri", "server_uri"], "") or ""
    username_dn_format = get_any(parser, sections, ["username_dn_format"], None)
    search_base = get_any(
        parser, sections, ["search_base", "user_base_dn", "base_dn"], None
    )
    user_base_dn = (
        get_any(parser, sections, ["user_base_dn", "base_dn"], None) or search_base
    )

    default_filter = (
        "(|(sAMAccountName={username})"
        "(userPrincipalName={username})"
        "(cn={username})"
        "(mail={username}))"
    )
    user_filter = (
        get_any(parser, sections, ["user_filter"], default_filter) or default_filter
    )

    group_attribute = (
        get_any(parser, sections, ["group_attribute", "group_attr"], "memberOf")
        or "memberOf"
    )
    attr_uid = get_any(parser, sections, ["attr_uid", "uid_attr"], "uid") or "uid"
    attr_username = (
        get_any(parser, sections, ["attr_username", "username_attr"], "sAMAccountName")
        or "sAMAccountName"
    )
    attr_first_name = (
        get_any(parser, sections, ["attr_first_name", "first_name_attr"], "givenName")
        or "givenName"
    )
    attr_last_name = (
        get_any(parser, sections, ["attr_last_name", "last_name_attr"], "sn") or "sn"
    )
    attr_email = (
        get_any(parser, sections, ["attr_email", "email_attr"], "mail") or "mail"
    )

    start_tls = get_bool(parser, sections, ["start_tls"], False)
    allow_self_signed = get_bool(parser, sections, ["allow_self_signed"], False)
    if allow_self_signed and not security.allow_insecure_ldap_tls:
        raise ValueError(
            "LDAP config error: allow_self_signed=true requires [security] allow_insecure_ldap_tls = true"
        )

    tls_require_cert = (
        (get_any(parser, sections, ["tls_require_cert"], None) or "").strip().lower()
    )
    if not tls_require_cert:
        tls_require_cert = "allow" if allow_self_signed else "demand"
    if allow_self_signed and tls_require_cert in {"demand", "hard"}:
        log.warning(
            "allow_self_signed=true overrides tls_require_cert=%s -> allow",
            tls_require_cert,
        )
        tls_require_cert = "allow"

    bind_password_ref = get_any(parser, sections, ["bind_password"], None)
    bind_password_resolution = (
        resolve_secret_reference(
            bind_password_ref,
            allow_plaintext=security.allow_plaintext_secrets,
        )
        if bind_password_ref
        else None
    )

    return LdapConfig(
        enabled=True,
        uri=uri,
        bind_dn=get_any(parser, sections, ["bind_dn"], None),
        bind_password=bind_password_resolution.value
        if bind_password_resolution
        else None,
        user_base_dn=user_base_dn,
        user_filter=user_filter,
        group_attribute=group_attribute,
        username_dn_format=username_dn_format,
        search_base=search_base,
        start_tls=start_tls,
        allow_self_signed=allow_self_signed,
        tls_ca_cert_file=get_any(
            parser, sections, ["tls_ca_cert_file", "ca_cert_file"], None
        ),
        tls_require_cert=tls_require_cert,
        resolve_nested_groups=get_bool(
            parser, sections, ["resolve_nested_groups"], False
        ),
        nested_groups_base_dn=get_any(
            parser, sections, ["nested_groups_base_dn"], None
        ),
        nested_group_match_rule=get_any(
            parser, sections, ["nested_group_match_rule"], "1.2.840.113556.1.4.1941"
        ),
        connect_timeout_seconds=get_int(
            parser, sections, ["connect_timeout_seconds"], 5
        ),
        network_timeout_seconds=get_int(
            parser, sections, ["network_timeout_seconds"], 5
        ),
        operation_timeout_seconds=get_int(
            parser,
            sections,
            ["operation_timeout_seconds"],
            get_int(parser, sections, ["network_timeout_seconds"], 5),
        ),
        search_time_limit_seconds=get_int(
            parser, sections, ["search_time_limit_seconds", "search_timeout_seconds"], 5
        ),
        size_limit=get_int(parser, sections, ["size_limit"], 0),
        chase_referrals=get_bool(parser, sections, ["chase_referrals"], False),
        username_pattern=get_any(
            parser, sections, ["username_pattern"], r"^[A-Za-z0-9._-]{1,128}$"
        ),
        username_max_length=get_int(parser, sections, ["username_max_length"], 128),
        attr_uid=attr_uid,
        attr_username=attr_username,
        attr_first_name=attr_first_name,
        attr_last_name=attr_last_name,
        attr_email=attr_email,
    )


def parse_entra_id(
    parser: configparser.ConfigParser,
    *,
    enabled: bool,
    security: SecurityConfig,
) -> EntraIdConfig | None:
    """Parse the Azure Entra ID provider section.

    Mandatory-value validation is performed later so one invalid provider
    can be disabled while another valid provider still starts.
    """
    sections = section_aliases("entra_id")
    section_present = has_any_section(parser, sections)
    entra_enabled = get_bool(
        parser, sections, ["enabled"], enabled if section_present else False
    )
    if not entra_enabled:
        return None

    tenant_id = get_any(parser, sections, ["tenant_id"], "") or ""
    client_id = get_any(parser, sections, ["client_id"], "") or ""

    client_secret_ref = get_any(parser, sections, ["client_secret"], "") or ""
    client_secret = ""  # nosec B105 - populated from config/secret reference at runtime
    if client_secret_ref:
        resolved_secret = resolve_secret_reference(
            client_secret_ref,
            allow_plaintext=security.allow_plaintext_secrets,
        )
        client_secret = resolved_secret.value if resolved_secret is not None else ""

    provider_name = (
        get_any(parser, sections, ["provider_name", "name"], "azure") or "azure"
    )
    button_text = (
        get_any(parser, sections, ["button_text"], "Sign in with Microsoft")
        or "Sign in with Microsoft"
    )
    icon = get_any(parser, sections, ["icon"], "fa-windows") or "fa-windows"

    scope = tuple(
        parse_csv(
            (
                get_any(
                    parser, sections, ["scope", "scopes"], "openid,email,profile,groups"
                )
                or "openid,email,profile,groups"
            ).replace(" ", ",")
        )
    )

    roles_claim_key = (
        get_any(parser, sections, ["roles_claim_key"], "groups") or "groups"
    ).strip()
    verify_signature = get_bool(parser, sections, ["verify_signature"], True)

    allowed_audiences_raw = parse_csv(
        get_any(parser, sections, ["allowed_audiences"], client_id) or client_id
    )
    allowed_audiences = tuple(
        allowed_audiences_raw or ([client_id] if client_id else [])
    )

    graph_fetch_groups_on_overage = get_bool(
        parser, sections, ["graph_fetch_groups_on_overage"], False
    )
    if graph_fetch_groups_on_overage and not security.allow_graph_group_fallback:
        raise ValueError(
            "Entra config error: graph_fetch_groups_on_overage=true requires "
            "[security] allow_graph_group_fallback = true"
        )

    metadata_url = get_any(parser, sections, ["metadata_url"], None)
    if not metadata_url and tenant_id:
        metadata_url = f"https://login.microsoftonline.com/{tenant_id}/v2.0/.well-known/openid-configuration"

    return EntraIdConfig(
        enabled=True,
        tenant_id=tenant_id,
        client_id=client_id,
        client_secret=client_secret,
        provider_name=provider_name,
        button_text=button_text,
        icon=icon,
        scope=scope,
        roles_claim_key=roles_claim_key,
        verify_signature=verify_signature,
        allowed_audiences=allowed_audiences,
        http_timeout_seconds=get_int(parser, sections, ["http_timeout_seconds"], 10),
        http_max_retries=get_int(parser, sections, ["http_max_retries"], 2),
        http_retry_backoff_seconds=get_int(
            parser, sections, ["http_retry_backoff_seconds"], 1
        ),
        metadata_url=metadata_url,
        authorize_url=get_any(parser, sections, ["authorize_url"], None),
        access_token_url=get_any(parser, sections, ["access_token_url"], None),
        jwks_uri=get_any(parser, sections, ["jwks_uri"], None),
        issuer=get_any(parser, sections, ["issuer"], None),
        username_claim=get_any(
            parser, sections, ["username_claim"], "preferred_username"
        )
        or "preferred_username",
        email_claim=get_any(parser, sections, ["email_claim"], "email") or "email",
        first_name_claim=get_any(parser, sections, ["first_name_claim"], "given_name")
        or "given_name",
        last_name_claim=get_any(parser, sections, ["last_name_claim"], "family_name")
        or "family_name",
        display_name_claim=get_any(parser, sections, ["display_name_claim"], "name")
        or "name",
        graph_fetch_groups_on_overage=graph_fetch_groups_on_overage,
        graph_memberof_url=get_any(
            parser,
            sections,
            ["graph_memberof_url"],
            "https://graph.microsoft.com/v1.0/me/transitiveMemberOf?$select=id,displayName",
        )
        or "https://graph.microsoft.com/v1.0/me/transitiveMemberOf?$select=id,displayName",
        enable_pkce=security.enable_pkce,
        clock_skew_seconds=get_int(parser, sections, ["clock_skew_seconds"], 120),
        allowed_oidc_hosts=tuple(
            parse_csv(
                get_any(
                    parser,
                    sections,
                    ["allowed_oidc_hosts"],
                    "login.microsoftonline.com,graph.microsoft.com",
                )
                or "login.microsoftonline.com,graph.microsoft.com"
            )
        ),
    )


def validate_ldap_config(
    ldap_cfg: LdapConfig | None,
) -> tuple[LdapConfig | None, tuple[str, ...]]:
    """Validate mandatory LDAP settings when LDAP is enabled."""
    if ldap_cfg is None:
        return None, ()

    errors: list[str] = []
    if not (ldap_cfg.uri or "").strip():
        errors.append("LDAP is enabled but server_uri/uri is missing.")
    if not (ldap_cfg.username_dn_format or "").strip():
        errors.append("LDAP is enabled but username_dn_format is missing.")
    if not (ldap_cfg.search_base or "").strip():
        errors.append("LDAP is enabled but search_base is missing.")

    if errors:
        return None, tuple(errors)
    return ldap_cfg, ()


def validate_entra_config(
    entra_cfg: EntraIdConfig | None,
) -> tuple[EntraIdConfig | None, tuple[str, ...]]:
    """Validate mandatory Entra ID settings when Entra ID is enabled."""
    if entra_cfg is None:
        return None, ()

    errors: list[str] = []
    if not (entra_cfg.tenant_id or "").strip():
        errors.append("Entra ID is enabled but tenant_id is missing.")
    if not (entra_cfg.client_id or "").strip():
        errors.append("Entra ID is enabled but client_id is missing.")
    if not (entra_cfg.client_secret or "").strip():
        errors.append("Entra ID is enabled but client_secret is missing.")
    if (entra_cfg.roles_claim_key or "").strip() not in {"groups", "roles"}:
        errors.append("Entra ID roles_claim_key must be 'groups' or 'roles'.")
    if "openid" not in {item.strip().lower() for item in entra_cfg.scope}:
        errors.append("Entra ID scope must include 'openid'.")
    if not entra_cfg.allowed_oidc_hosts:
        errors.append("Entra ID allowed_oidc_hosts is empty.")

    if errors:
        return None, tuple(errors)
    return entra_cfg, ()
