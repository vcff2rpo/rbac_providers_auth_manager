"""Role, mapping, and scoped-filter parsing for ``permissions.ini``."""

from __future__ import annotations

import configparser
import re
from pathlib import Path

from rbac_providers_auth_manager.config_runtime.models import (
    EntraRoleMappingConfig,
    RoleFiltersConfig,
    RoleMappingConfig,
    RolesConfig,
)
from rbac_providers_auth_manager.config_runtime.parse_helpers import (
    looks_like_dn,
    normalize_claim_value,
)
from rbac_providers_auth_manager.authorization.policy_models import RoleFilterRule
from rbac_providers_auth_manager.authorization.rbac import normalize_resource
from rbac_providers_auth_manager.authorization.vocabulary import normalize_action
from rbac_providers_auth_manager.core.util import canonicalize_dn, parse_csv


def parse_roles(parser: configparser.ConfigParser) -> RolesConfig:
    """Parse all ``[role:*]`` sections into normalized permission pairs."""
    role_to_permissions: dict[str, set[tuple[str, str]]] = {}

    for section in parser.sections():
        if not section.lower().startswith("role:"):
            continue

        role_name = section.split(":", 1)[1].strip()
        permissions: set[tuple[str, str]] = set()

        for key, raw_value in parser.items(section):
            action = normalize_action(key)
            for resource in parse_csv(raw_value):
                permissions.add((action, normalize_resource(resource)))

        role_to_permissions[role_name] = permissions

    return RolesConfig(role_to_permissions=role_to_permissions)


def parse_role_mapping_raw(ini_path: Path) -> RoleMappingConfig:
    """Parse ``[role_mapping]`` from raw INI text.

    This parser supports both of these styles because LDAP DNs contain commas
    and equals signs, which makes ordinary ``ConfigParser`` usage awkward.

    Supported forms
    ---------------
    Legacy:
        <DN> = <Role>

    Recommended:
        <Role> = <DN1> | <DN2>
    """
    dn_to_roles: dict[str, set[str]] = {}
    if not ini_path.exists():
        return RoleMappingConfig(dn_to_roles=dn_to_roles)

    in_role_mapping = False
    for raw_line in ini_path.read_text(encoding="utf-8", errors="replace").splitlines():
        line = raw_line.strip()
        if not line or line.startswith(";") or line.startswith("#"):
            continue

        if line.startswith("[") and line.endswith("]"):
            in_role_mapping = line[1:-1].strip().lower() == "role_mapping"
            continue

        if not in_role_mapping:
            continue

        line = re.split(r"\s[;#]", line, maxsplit=1)[0].strip()
        if not line or "=" not in line:
            continue

        delimiter = re.search(r"\s=\s", line)
        if delimiter:
            key = line[: delimiter.start()].strip()
            value = line[delimiter.end() :].strip()
        else:
            key, value = (part.strip() for part in line.rsplit("=", 1))

        if not key or not value:
            continue

        key_is_dn = looks_like_dn(key)
        value_is_dn = looks_like_dn(value)

        if key_is_dn and not value_is_dn:
            dn_parts = [key]
            role_parts = [
                item.strip() for item in re.split(r"\s*\|\s*", value) if item.strip()
            ]
        elif value_is_dn and not key_is_dn:
            role_parts = [key]
            dn_parts = [
                item.strip() for item in re.split(r"\s*\|\s*", value) if item.strip()
            ]
        else:
            dn_parts = [key]
            role_parts = [value]

        for dn in dn_parts:
            canonical_dn = canonicalize_dn(dn)
            if not canonical_dn:
                continue
            for role in role_parts:
                dn_to_roles.setdefault(canonical_dn, set()).add(role)

    return RoleMappingConfig(dn_to_roles=dn_to_roles)


def parse_entra_role_mapping(
    parser: configparser.ConfigParser,
) -> EntraRoleMappingConfig:
    """Parse the ``[entra_role_mapping]`` section.

    Mapping keys are matched case-insensitively against the Entra claim selected
    by ``roles_claim_key``.
    """
    mapping: dict[str, set[str]] = {}
    section = "entra_role_mapping"
    if not parser.has_section(section):
        return EntraRoleMappingConfig(claim_value_to_roles=mapping)

    for key, raw_value in parser.items(section):
        normalized_key = normalize_claim_value(key)
        if not normalized_key:
            continue

        roles = {item.strip() for item in parse_csv(raw_value) if item.strip()}
        if roles:
            mapping[normalized_key] = roles

    return EntraRoleMappingConfig(claim_value_to_roles=mapping)


def parse_role_filters(parser: configparser.ConfigParser) -> RoleFiltersConfig:
    """Parse optional ``[role_filters:<role>]`` sections.

    These sections extend the classic role/action/resource model with optional
    scoped filters that can be applied when runtime resource metadata is
    available. Unspecified fields leave the role behavior unchanged.
    """
    role_to_filters: dict[str, RoleFilterRule] = {}

    for section in parser.sections():
        if not section.lower().startswith("role_filters:"):
            continue

        role_name = section.split(":", 1)[1].strip()
        if not role_name:
            continue

        dag_tags = tuple(
            item.casefold()
            for item in parse_csv(parser.get(section, "dag_tags", fallback=""))
            if item
        )
        environments = tuple(
            item.casefold()
            for item in parse_csv(parser.get(section, "environments", fallback=""))
            if item
        )
        resource_prefixes = tuple(
            item.strip()
            for item in parse_csv(parser.get(section, "resource_prefixes", fallback=""))
            if item.strip()
        )

        rule = RoleFilterRule(
            dag_tags=tuple(sorted(set(dag_tags))),
            environments=tuple(sorted(set(environments))),
            resource_prefixes=tuple(sorted(set(resource_prefixes))),
        )
        if rule.has_constraints:
            role_to_filters[role_name] = rule

    return RoleFiltersConfig(role_to_filters=role_to_filters)
