from __future__ import annotations

import importlib
import json
import platform
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Final, Sequence

from rbac_providers_auth_manager.authorization import vocabulary as vocab
from rbac_providers_auth_manager.authorization.compat_matrix import (
    build_non_admin_compatibility_matrix,
    evaluate_non_admin_role_consistency,
)
from rbac_providers_auth_manager.authorization.rbac import RbacPolicy
from rbac_providers_auth_manager.authorization.resource_contracts import (
    contract_permissions_by_role,
)
from rbac_providers_auth_manager.config_runtime.models import (
    AuthConfig,
    AuthConfigValidation,
    EntraRoleMappingConfig,
    GeneralConfig,
    JwtCookieConfig,
    MetaConfig,
    RoleFiltersConfig,
    RoleMappingConfig,
    RolesConfig,
    SecurityConfig,
    UiConfig,
)

ROLE_ORDER: Final[tuple[str, ...]] = ("Viewer", "User", "Op", "Admin")
OFFICIAL_CONSTANT_MODULES: Final[tuple[str, ...]] = (
    "airflow.providers.fab.www.security.permissions",
    "airflow.providers.fab.auth_manager.security_manager.override",
    "airflow.security.permissions",
)
EXCLUDED_DB_BACKED_RESOURCES: Final[frozenset[str]] = frozenset(
    {
        "Action",
        "Actions",
        "Password",
        "Passwords",
        "Permission",
        "Permissions",
        "Permission View",
        "Permission Views",
        "Resource Permission",
        "Resource Permissions",
        "Role",
        "Roles",
        "Security",
        "User",
        "Users",
        "User Stats Chart",
        "View Menu",
        "View Menus",
    }
)
SUPPORTED_ACTIONS: Final[frozenset[str]] = frozenset(
    value
    for name, value in vars(vocab).items()
    if name.startswith("ACTION_") and isinstance(value, str)
)
SUPPORTED_RESOURCES: Final[frozenset[str]] = frozenset(
    value
    for name, value in vars(vocab).items()
    if name.startswith("RESOURCE_")
    and isinstance(value, str)
    and not name.endswith("_PREFIX")
)


@dataclass(frozen=True, slots=True)
class SupportGap:
    role: str
    action: str
    resource: str
    normalized_action: str
    normalized_resource: str
    reason: str


@dataclass(frozen=True, slots=True)
class SupportReport:
    official_permission_counts: dict[str, int]
    supported_permission_counts: dict[str, int]
    official_permissions_by_role: dict[str, tuple[dict[str, str], ...]]
    plugin_contract_permissions_by_role: dict[str, tuple[dict[str, str], ...]]
    supported_official_permissions_by_role: dict[str, tuple[dict[str, str], ...]]
    unsupported_official_permissions_by_role: dict[str, tuple[dict[str, str], ...]]
    plugin_extra_permissions_by_role: dict[str, tuple[dict[str, str], ...]]
    official_action_constants: tuple[str, ...]
    official_resource_constants: tuple[str, ...]
    plugin_action_constants: tuple[str, ...]
    plugin_resource_constants: tuple[str, ...]
    missing_action_constants_in_plugin: tuple[str, ...]
    extra_action_constants_in_plugin: tuple[str, ...]
    missing_resource_constants_in_plugin: tuple[str, ...]
    extra_resource_constants_in_plugin: tuple[str, ...]
    contract_advisories: tuple[dict[str, str], ...]
    compatibility_matrix: tuple[dict[str, object], ...]
    unsupported_permissions: tuple[SupportGap, ...]

    @property
    def has_blocking_gaps(self) -> bool:
        return bool(self.unsupported_permissions)

    def as_dict(self) -> dict[str, object]:
        return {
            "official_permission_counts": self.official_permission_counts,
            "supported_permission_counts": self.supported_permission_counts,
            "official_permissions_by_role": {
                key: list(value)
                for key, value in self.official_permissions_by_role.items()
            },
            "plugin_contract_permissions_by_role": {
                key: list(value)
                for key, value in self.plugin_contract_permissions_by_role.items()
            },
            "supported_official_permissions_by_role": {
                key: list(value)
                for key, value in self.supported_official_permissions_by_role.items()
            },
            "unsupported_official_permissions_by_role": {
                key: list(value)
                for key, value in self.unsupported_official_permissions_by_role.items()
            },
            "plugin_extra_permissions_by_role": {
                key: list(value)
                for key, value in self.plugin_extra_permissions_by_role.items()
            },
            "official_action_constants": list(self.official_action_constants),
            "official_resource_constants": list(self.official_resource_constants),
            "plugin_action_constants": list(self.plugin_action_constants),
            "plugin_resource_constants": list(self.plugin_resource_constants),
            "missing_action_constants_in_plugin": list(
                self.missing_action_constants_in_plugin
            ),
            "extra_action_constants_in_plugin": list(
                self.extra_action_constants_in_plugin
            ),
            "missing_resource_constants_in_plugin": list(
                self.missing_resource_constants_in_plugin
            ),
            "extra_resource_constants_in_plugin": list(
                self.extra_resource_constants_in_plugin
            ),
            "contract_advisories": list(self.contract_advisories),
            "compatibility_matrix": list(self.compatibility_matrix),
            "unsupported_permissions": [
                asdict(item) for item in self.unsupported_permissions
            ],
        }


def _normalize_permissions(
    permissions: set[tuple[str, str]] | frozenset[tuple[str, str]],
) -> tuple[dict[str, str], ...]:
    normalized = {
        (vocab.normalize_action(str(action)), vocab.normalize_resource(str(resource)))
        for action, resource in permissions
        if not _is_db_backed_resource(str(resource))
    }
    return tuple(
        {"action": action, "resource": resource}
        for action, resource in sorted(normalized)
    )


def provider_role_permissions() -> dict[str, frozenset[tuple[str, str]]]:
    importlib.import_module("airflow")
    provider_mod = importlib.import_module(
        "airflow.providers.fab.auth_manager.security_manager.override"
    )
    manager_cls = provider_mod.FabAirflowSecurityManagerOverride
    return {
        "Viewer": frozenset(manager_cls.VIEWER_PERMISSIONS),
        "User": frozenset(
            set(manager_cls.VIEWER_PERMISSIONS) | set(manager_cls.USER_PERMISSIONS)
        ),
        "Op": frozenset(
            set(manager_cls.VIEWER_PERMISSIONS)
            | set(manager_cls.USER_PERMISSIONS)
            | set(manager_cls.OP_PERMISSIONS)
        ),
        "Admin": frozenset(
            set(manager_cls.VIEWER_PERMISSIONS)
            | set(manager_cls.USER_PERMISSIONS)
            | set(manager_cls.OP_PERMISSIONS)
            | set(manager_cls.ADMIN_PERMISSIONS)
        ),
    }


def _is_db_backed_resource(resource: str) -> bool:
    normalized = vocab.normalize_resource(resource)
    return (
        resource in EXCLUDED_DB_BACKED_RESOURCES
        or normalized in EXCLUDED_DB_BACKED_RESOURCES
    )


def _filtered_official_permissions(
    permissions_by_role: dict[str, frozenset[tuple[str, str]]],
) -> dict[str, frozenset[tuple[str, str]]]:
    filtered: dict[str, frozenset[tuple[str, str]]] = {}
    for role_name, permissions in permissions_by_role.items():
        filtered[role_name] = frozenset(
            (
                vocab.normalize_action(str(action)),
                vocab.normalize_resource(str(resource)),
            )
            for action, resource in permissions
            if not _is_db_backed_resource(str(resource))
        )
    return filtered


def _plugin_contract_permissions() -> dict[str, frozenset[tuple[str, str]]]:
    contract_permissions = contract_permissions_by_role()
    return {
        role_name: frozenset(
            (
                vocab.normalize_action(action),
                vocab.normalize_resource(resource),
            )
            for action, resource in permissions
        )
        for role_name, permissions in contract_permissions.items()
    }


def _build_synthetic_config(
    permissions_by_role: dict[str, frozenset[tuple[str, str]]],
) -> AuthConfig:
    role_to_permissions = {
        role_name: set(permissions_by_role.get(role_name, frozenset()))
        for role_name in ROLE_ORDER
    }
    return AuthConfig(
        meta=MetaConfig(),
        general=GeneralConfig(),
        security=SecurityConfig(),
        jwt_cookie=JwtCookieConfig(
            cookie_httponly=True,
            cookie_samesite="Lax",
            cookie_path="/",
            cookie_domain=None,
            cookie_secure=None,
        ),
        ldap=None,
        entra_id=None,
        role_mapping=RoleMappingConfig(dn_to_roles={}),
        entra_role_mapping=EntraRoleMappingConfig(claim_value_to_roles={}),
        roles=RolesConfig(role_to_permissions=role_to_permissions),
        role_filters=RoleFiltersConfig(role_to_filters={}),
        ui=UiConfig(),
        validation=AuthConfigValidation(),
        advisories=(),
    )


def _collect_official_constants() -> tuple[tuple[str, ...], tuple[str, ...]]:
    actions: set[str] = set()
    resources: set[str] = set()
    for module_name in OFFICIAL_CONSTANT_MODULES:
        module = importlib.import_module(module_name)
        for name, value in vars(module).items():
            if not isinstance(value, str):
                continue
            if name.startswith("ACTION_"):
                actions.add(vocab.normalize_action(value))
            elif name.startswith("RESOURCE_") and not name.endswith("_PREFIX"):
                normalized = vocab.normalize_resource(value)
                if not _is_db_backed_resource(normalized):
                    resources.add(normalized)
    return tuple(sorted(actions)), tuple(sorted(resources))


def _table(
    lines: list[str], headers: Sequence[str], rows: Sequence[Sequence[str]]
) -> None:
    lines.append("| " + " | ".join(headers) + " |")
    lines.append("| " + " | ".join("---" for _ in headers) + " |")
    if rows:
        for row in rows:
            lines.append("| " + " | ".join(row) + " |")
    else:
        lines.append("| " + " | ".join("-" for _ in headers) + " |")


def _permission_rows(items: tuple[dict[str, str], ...]) -> list[tuple[str, str]]:
    return [(item["action"], item["resource"]) for item in items]


def _constant_rows(items: Sequence[str]) -> list[tuple[str]]:
    return [(item,) for item in items]


def build_support_report() -> SupportReport:
    official = _filtered_official_permissions(provider_role_permissions())
    synthetic_cfg = _build_synthetic_config(official)
    policy = RbacPolicy(synthetic_cfg)
    plugin_contract = _plugin_contract_permissions()
    official_actions, official_resources = _collect_official_constants()
    plugin_actions = tuple(sorted(SUPPORTED_ACTIONS))
    plugin_resources = tuple(sorted(SUPPORTED_RESOURCES))

    unsupported: list[SupportGap] = []
    official_counts: dict[str, int] = {}
    supported_counts: dict[str, int] = {}
    official_by_role: dict[str, tuple[dict[str, str], ...]] = {}
    plugin_by_role: dict[str, tuple[dict[str, str], ...]] = {}
    supported_by_role: dict[str, tuple[dict[str, str], ...]] = {}
    unsupported_by_role: dict[str, tuple[dict[str, str], ...]] = {}
    extra_by_role: dict[str, tuple[dict[str, str], ...]] = {}

    for role_name in ROLE_ORDER:
        official_permissions = official.get(role_name, frozenset())
        plugin_permissions = plugin_contract.get(role_name, frozenset())
        official_counts[role_name] = len(official_permissions)
        official_by_role[role_name] = _normalize_permissions(official_permissions)
        plugin_by_role[role_name] = _normalize_permissions(plugin_permissions)

        supported_permissions: set[tuple[str, str]] = set()
        unsupported_permissions: set[tuple[str, str]] = set()
        for action, resource in sorted(official_permissions):
            normalized_action = vocab.normalize_action(action)
            normalized_resource = vocab.normalize_resource(resource)
            if normalized_action not in SUPPORTED_ACTIONS:
                unsupported.append(
                    SupportGap(
                        role=role_name,
                        action=action,
                        resource=resource,
                        normalized_action=normalized_action,
                        normalized_resource=normalized_resource,
                        reason="unknown_action",
                    )
                )
                unsupported_permissions.add((normalized_action, normalized_resource))
                continue
            if normalized_resource not in SUPPORTED_RESOURCES:
                unsupported.append(
                    SupportGap(
                        role=role_name,
                        action=action,
                        resource=resource,
                        normalized_action=normalized_action,
                        normalized_resource=normalized_resource,
                        reason="unknown_resource",
                    )
                )
                unsupported_permissions.add((normalized_action, normalized_resource))
                continue
            if not policy.is_allowed(
                roles=(role_name,),
                action=normalized_action,
                resource=normalized_resource,
            ):
                unsupported.append(
                    SupportGap(
                        role=role_name,
                        action=action,
                        resource=resource,
                        normalized_action=normalized_action,
                        normalized_resource=normalized_resource,
                        reason="policy_engine_rejected_official_permission",
                    )
                )
                unsupported_permissions.add((normalized_action, normalized_resource))
                continue
            supported_permissions.add((normalized_action, normalized_resource))

        supported_counts[role_name] = len(supported_permissions)
        supported_by_role[role_name] = _normalize_permissions(supported_permissions)
        unsupported_by_role[role_name] = _normalize_permissions(
            official_permissions - supported_permissions
        )
        extra_by_role[role_name] = _normalize_permissions(
            plugin_permissions - official_permissions
        )

    advisories = tuple(
        asdict(issue)
        for issue in evaluate_non_admin_role_consistency(
            _build_synthetic_config(plugin_contract)
        )
    )
    matrix = tuple(
        asdict(row)
        for row in build_non_admin_compatibility_matrix(
            _build_synthetic_config(plugin_contract)
        )
    )
    return SupportReport(
        official_permission_counts=official_counts,
        supported_permission_counts=supported_counts,
        official_permissions_by_role=official_by_role,
        plugin_contract_permissions_by_role=plugin_by_role,
        supported_official_permissions_by_role=supported_by_role,
        unsupported_official_permissions_by_role=unsupported_by_role,
        plugin_extra_permissions_by_role=extra_by_role,
        official_action_constants=official_actions,
        official_resource_constants=official_resources,
        plugin_action_constants=plugin_actions,
        plugin_resource_constants=plugin_resources,
        missing_action_constants_in_plugin=tuple(
            sorted(set(official_actions) - set(plugin_actions))
        ),
        extra_action_constants_in_plugin=tuple(
            sorted(set(plugin_actions) - set(official_actions))
        ),
        missing_resource_constants_in_plugin=tuple(
            sorted(set(official_resources) - set(plugin_resources))
        ),
        extra_resource_constants_in_plugin=tuple(
            sorted(set(plugin_resources) - set(official_resources))
        ),
        contract_advisories=advisories,
        compatibility_matrix=matrix,
        unsupported_permissions=tuple(unsupported),
    )


def _role_membership_map(
    permissions_by_role: dict[str, tuple[dict[str, str], ...]],
) -> dict[tuple[str, str], set[str]]:
    membership: dict[tuple[str, str], set[str]] = {}
    for role, items in permissions_by_role.items():
        for item in items:
            key = (item["resource"], item["action"])
            membership.setdefault(key, set()).add(role)
    return membership


def _roles_display(roles: set[str]) -> str:
    ordered = [role for role in ROLE_ORDER if role in roles]
    return ", ".join(ordered) if ordered else "-"


def _role_delta_summary(
    official_roles: set[str], plugin_roles: set[str]
) -> tuple[str, str, str]:
    missing_roles = {role for role in official_roles if role not in plugin_roles}
    extra_roles = {role for role in plugin_roles if role not in official_roles}
    if official_roles == plugin_roles:
        status = "exact-match"
        explanation = (
            "Plugin contract matches the official role surface for this permission."
        )
    elif official_roles and not plugin_roles:
        status = "official-only"
        explanation = "Official FAB exposes this permission, but the plugin contract does not currently grant it."
    elif plugin_roles and not official_roles:
        status = "plugin-only"
        explanation = "Plugin contract grants this permission beyond the official FAB role surface."
    else:
        status = "role-drift"
        explanation = "Permission exists on both sides, but the role progression differs and should be reviewed."
    delta_bits: list[str] = []
    if missing_roles:
        delta_bits.append(f"missing: {_roles_display(missing_roles)}")
    if extra_roles:
        delta_bits.append(f"additional: {_roles_display(extra_roles)}")
    return status, "; ".join(delta_bits) or "-", explanation


def _constant_comparison_rows(
    official: Sequence[str], plugin: Sequence[str]
) -> list[tuple[str, str, str, str]]:
    official_set = set(official)
    plugin_set = set(plugin)
    rows: list[tuple[str, str, str, str]] = []
    for item in sorted(official_set | plugin_set):
        in_official = item in official_set
        in_plugin = item in plugin_set
        if in_official and in_plugin:
            note = "shared constant"
        elif in_official:
            note = "official-only constant"
        else:
            note = "plugin-only constant"
        rows.append(
            (item, "yes" if in_official else "no", "yes" if in_plugin else "no", note)
        )
    return rows


def _permission_comparison_rows(
    report: SupportReport,
) -> list[tuple[str, str, str, str, str, str, str]]:
    official_map = _role_membership_map(report.official_permissions_by_role)
    plugin_map = _role_membership_map(report.plugin_contract_permissions_by_role)
    keys = sorted(set(official_map) | set(plugin_map))
    rows: list[tuple[str, str, str, str, str, str, str]] = []
    for resource, action in keys:
        official_roles = official_map.get((resource, action), set())
        plugin_roles = plugin_map.get((resource, action), set())
        status, delta, explanation = _role_delta_summary(official_roles, plugin_roles)
        rows.append(
            (
                resource,
                action,
                _roles_display(official_roles),
                _roles_display(plugin_roles),
                status,
                delta,
                explanation,
            )
        )
    return rows


def _compatibility_progression_rows(
    matrix: tuple[dict[str, object], ...],
) -> list[tuple[str, str, str, str, str, str, str]]:
    rows: list[tuple[str, str, str, str, str, str, str]] = []
    for item in sorted(
        matrix,
        key=lambda row: (str(row.get("resource", "")), str(row.get("action", ""))),
    ):
        role_status = {role: "-" for role in ROLE_ORDER}
        for role_name in ROLE_ORDER:
            if bool(item.get(f"{role_name.lower()}_has_access", False)):
                role_status[role_name] = "yes"
            else:
                role_status[role_name] = "no"
        rows.append(
            (
                str(item.get("resource", "-")),
                str(item.get("action", "-")),
                role_status["Viewer"],
                role_status["User"],
                role_status["Op"],
                role_status["Admin"],
                str(item.get("minimum_role", "-")),
            )
        )
    return rows


def render_support_markdown(report: SupportReport) -> str:
    airflow_mod = importlib.import_module("airflow")
    metadata_mod = importlib.import_module("importlib.metadata")

    lines = ["# FAB provider support validation", ""]
    lines.append(
        "This report compares the custom plugin RBAC contract against the official FAB provider permission surface using alphabetically sorted matrices so role drift is visible at a glance."
    )
    lines.extend(["", "## CI setup", ""])
    _table(
        lines,
        ("Field", "Value"),
        [
            ("Python", platform.python_version()),
            ("Airflow", airflow_mod.__version__),
            ("FAB provider", metadata_mod.version("apache-airflow-providers-fab")),
            ("Official constant sources", ", ".join(OFFICIAL_CONSTANT_MODULES)),
        ],
    )

    lines.extend(["", "## Role coverage overview", ""])
    _table(
        lines,
        (
            "Role",
            "Official permissions",
            "Plugin-supported official permissions",
            "Support %",
            "Official-only gaps",
            "Plugin-only additions",
        ),
        [
            (
                role,
                str(report.official_permission_counts.get(role, 0)),
                str(report.supported_permission_counts.get(role, 0)),
                (
                    f"{(100 * report.supported_permission_counts.get(role, 0) / report.official_permission_counts.get(role, 1)):.1f}%"
                    if report.official_permission_counts.get(role, 0)
                    else "100.0%"
                ),
                str(len(report.unsupported_official_permissions_by_role[role])),
                str(len(report.plugin_extra_permissions_by_role[role])),
            )
            for role in ROLE_ORDER
        ],
    )

    lines.extend(["", "## Action constant comparison matrix", ""])
    _table(
        lines,
        ("Action", "Official FAB", "Plugin vocabulary", "Interpretation"),
        _constant_comparison_rows(
            report.official_action_constants,
            report.plugin_action_constants,
        ),
    )

    lines.extend(["", "## Resource constant comparison matrix", ""])
    _table(
        lines,
        ("Resource", "Official FAB", "Plugin vocabulary", "Interpretation"),
        _constant_comparison_rows(
            report.official_resource_constants,
            report.plugin_resource_constants,
        ),
    )

    lines.extend(["", "## RBAC permission comparison matrix", ""])
    lines.append(
        "Rows are sorted by resource and action. The official and plugin role columns show cumulative role membership after normalization."
    )
    lines.append("")
    _table(
        lines,
        (
            "Resource",
            "Action",
            "Official roles",
            "Plugin roles",
            "Status",
            "Role delta",
            "Explanation",
        ),
        _permission_comparison_rows(report),
    )

    lines.extend(["", "## Non-admin role progression matrix", ""])
    lines.append(
        "This matrix shows the plugin's intended role ladder for normalized permissions after contract synthesis. It is sorted alphabetically to make drift review easier."
    )
    lines.append("")
    _table(
        lines,
        ("Resource", "Action", "Viewer", "User", "Op", "Admin", "Minimum role"),
        _compatibility_progression_rows(report.compatibility_matrix),
    )

    lines.extend(["", "## Contract advisories", ""])
    if report.contract_advisories:
        _table(
            lines,
            ("Role", "Resource", "Issue", "Severity"),
            [
                (
                    str(item.get("role", "-")),
                    str(item.get("resource", "-")),
                    str(item.get("issue", "-")),
                    str(item.get("severity", "-")),
                )
                for item in sorted(
                    report.contract_advisories,
                    key=lambda item: (
                        str(item.get("role", "")),
                        str(item.get("resource", "")),
                        str(item.get("issue", "")),
                    ),
                )
            ],
        )
    else:
        _table(lines, ("Role", "Resource", "Issue", "Severity"), [])

    lines.extend(["", "## Result interpretation", ""])
    lines.append(
        "- exact-match: official FAB and plugin contract expose the same role surface for the permission."
    )
    lines.append(
        "- official-only: official FAB exposes the permission, but the plugin contract does not currently grant it."
    )
    lines.append(
        "- plugin-only: plugin contract grants the permission even though it is not part of the official FAB surface."
    )
    lines.append(
        "- role-drift: both sides expose the permission, but the role ladder differs and should be reviewed before release."
    )
    return "\n".join(lines) + "\n"


def write_support_artifacts(*, artifact_dir: Path) -> SupportReport:
    artifact_dir.mkdir(parents=True, exist_ok=True)
    report = build_support_report()
    payload = report.as_dict()
    (artifact_dir / "fab-support-report.json").write_text(
        json.dumps(payload, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    markdown = render_support_markdown(report)
    (artifact_dir / "official-fab-permissions-support-summary.md").write_text(
        markdown,
        encoding="utf-8",
    )
    return report
