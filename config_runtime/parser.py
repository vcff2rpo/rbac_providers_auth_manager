"""Top-level configuration loading orchestration for the auth-manager runtime."""

from __future__ import annotations

import configparser
import logging
from pathlib import Path

from rbac_providers_auth_manager.config_runtime.advisories import (
    collect_config_advisories,
)
from rbac_providers_auth_manager.config_runtime.mapping_parsers import (
    parse_entra_role_mapping,
    parse_role_filters,
    parse_role_mapping_raw,
    parse_roles,
)
from rbac_providers_auth_manager.config_runtime.models import (
    AuthConfig,
    AuthConfigValidation,
)
from rbac_providers_auth_manager.config_runtime.provider_parsers import (
    parse_entra_id,
    parse_ldap,
    validate_entra_config,
    validate_ldap_config,
)
from rbac_providers_auth_manager.config_runtime.section_parsers import (
    parse_general,
    parse_jwt_cookie,
    parse_meta,
    parse_security,
    parse_ui,
)
from rbac_providers_auth_manager.runtime.security import verify_hmac_integrity

log = logging.getLogger(__name__)


def load_config(ini_path: Path) -> AuthConfig:
    """Load and validate the full auth-manager configuration."""
    verify_hmac_integrity(ini_path)

    parser = configparser.ConfigParser(interpolation=None, strict=False)
    parser.read(ini_path)

    meta = parse_meta(parser)
    general = parse_general(parser)
    security = parse_security(parser)
    if security.rate_limit_backend not in {"memory", "in_memory", "local", "redis"}:
        raise ValueError(
            f"Unsupported security.rate_limit_backend: {security.rate_limit_backend}"
        )
    if (
        security.rate_limit_backend == "redis"
        and not (security.redis_url or "").strip()
    ):
        raise ValueError(
            "security.rate_limit_backend=redis requires security.redis_url to be set"
        )
    jwt_cookie = parse_jwt_cookie(parser)
    ui = parse_ui(parser)

    parsed_ldap_cfg = parse_ldap(parser, enabled=general.enable_ldap, security=security)
    parsed_entra_cfg = parse_entra_id(
        parser, enabled=general.enable_entra_id, security=security
    )

    ldap_cfg, ldap_errors = validate_ldap_config(parsed_ldap_cfg)
    entra_cfg, entra_errors = validate_entra_config(parsed_entra_cfg)

    validation = AuthConfigValidation(
        ldap_errors=ldap_errors,
        entra_errors=entra_errors,
    )

    if ldap_errors:
        log.warning(
            "LDAP provider disabled due to config validation errors: %s",
            list(ldap_errors),
        )
    if entra_errors:
        log.warning(
            "Entra ID provider disabled due to config validation errors: %s",
            list(entra_errors),
        )

    if ldap_cfg is None and entra_cfg is None:
        combined = list(ldap_errors) + list(entra_errors)
        if not combined:
            combined.append(
                "At least one authentication provider must be enabled: LDAP or Azure Entra ID"
            )
        raise ValueError(" | ".join(combined))

    role_mapping = parse_role_mapping_raw(ini_path)
    entra_role_mapping = parse_entra_role_mapping(parser)
    roles = parse_roles(parser)
    role_filters = parse_role_filters(parser)

    undefined_role_filters = sorted(
        set(role_filters.role_to_filters.keys()) - set(roles.role_to_permissions.keys())
    )
    if undefined_role_filters:
        log.warning(
            "Ignoring role_filters sections for undefined roles: %s",
            undefined_role_filters,
        )

    cfg = AuthConfig(
        meta=meta,
        general=general,
        security=security,
        jwt_cookie=jwt_cookie,
        ldap=ldap_cfg,
        entra_id=entra_cfg,
        role_mapping=role_mapping,
        entra_role_mapping=entra_role_mapping,
        roles=roles,
        role_filters=role_filters,
        ui=ui,
        validation=validation,
    )

    advisories = collect_config_advisories(cfg)
    cfg = AuthConfig(
        meta=cfg.meta,
        general=cfg.general,
        security=cfg.security,
        jwt_cookie=cfg.jwt_cookie,
        ldap=cfg.ldap,
        entra_id=cfg.entra_id,
        role_mapping=cfg.role_mapping,
        entra_role_mapping=cfg.entra_role_mapping,
        roles=cfg.roles,
        role_filters=cfg.role_filters,
        ui=cfg.ui,
        validation=cfg.validation,
        advisories=advisories,
    )

    for advisory in advisories:
        log.warning("Config advisory [%s]: %s", advisory.code, advisory.message)

    return cfg
