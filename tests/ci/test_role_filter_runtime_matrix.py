from __future__ import annotations

import pytest

from rbac_providers_auth_manager.authorization.policy_models import (
    AuthorizationContext,
    ResourceAttributes,
)
from rbac_providers_auth_manager.authorization.rbac import (
    ACTION_CAN_READ,
    RESOURCE_DAG,
    RbacPolicy,
)

from .permissions_fixture_loader import load_config_case


def _context(
    *,
    dag_id: str | None,
    tags: tuple[str, ...] = (),
    environments: tuple[str, ...] = (),
) -> AuthorizationContext:
    return AuthorizationContext(
        resource=ResourceAttributes(
            resource_id=dag_id,
            resource_type="dag",
            dag_tags=tags,
            environments=environments,
        )
    )


def test_role_filter_runtime_casefolded_tags_and_environments_allow_matching_context(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _, _, cfg = load_config_case("valid_role_filters_casefolded.ini", monkeypatch)
    policy = RbacPolicy(cfg)

    assert policy.is_allowed(
        roles=("ScopedCasefolded",),
        action=ACTION_CAN_READ,
        resource=RESOURCE_DAG,
        context=_context(
            dag_id="finance_daily",
            tags=("FINANCE",),
            environments=("PROD",),
        ),
    )


def test_role_filter_runtime_casefolded_tags_and_environments_block_non_matching_context(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _, _, cfg = load_config_case("valid_role_filters_casefolded.ini", monkeypatch)
    policy = RbacPolicy(cfg)

    assert (
        policy.is_allowed(
            roles=("ScopedCasefolded",),
            action=ACTION_CAN_READ,
            resource=RESOURCE_DAG,
            context=_context(
                dag_id="finance_daily",
                tags=("platform",),
                environments=("prod",),
            ),
        )
        is False
    )


def test_role_filter_runtime_prefix_rule_blocks_non_matching_resource_id(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _, _, cfg = load_config_case("valid_role_filters_casefolded.ini", monkeypatch)
    policy = RbacPolicy(cfg)

    assert (
        policy.is_allowed(
            roles=("ScopedCasefolded",),
            action=ACTION_CAN_READ,
            resource=RESOURCE_DAG,
            context=_context(
                dag_id="ops_daily",
                tags=("finance",),
                environments=("prod",),
            ),
        )
        is False
    )


def test_role_filter_runtime_keeps_role_active_when_context_is_missing(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _, _, cfg = load_config_case("valid_role_filters_casefolded.ini", monkeypatch)
    policy = RbacPolicy(cfg)

    assert policy.is_allowed(
        roles=("ScopedCasefolded",),
        action=ACTION_CAN_READ,
        resource=RESOURCE_DAG,
        context=None,
    )


def test_role_filter_runtime_combined_roles_allow_when_any_rule_matches(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _, _, cfg = load_config_case("valid_role_filters_multi_role.ini", monkeypatch)
    policy = RbacPolicy(cfg)

    finance_context = _context(
        dag_id="finance_margin",
        tags=("finance",),
        environments=("prod",),
    )
    ops_context = _context(
        dag_id="ops_failover",
        tags=("operations",),
        environments=("dr",),
    )
    blocked_context = _context(
        dag_id="hr_daily",
        tags=("hr",),
        environments=("dev",),
    )

    assert policy.is_allowed(
        roles=("ScopedFinance", "ScopedOps"),
        action=ACTION_CAN_READ,
        resource=RESOURCE_DAG,
        context=finance_context,
    )
    assert policy.is_allowed(
        roles=("ScopedFinance", "ScopedOps"),
        action=ACTION_CAN_READ,
        resource=RESOURCE_DAG,
        context=ops_context,
    )
    assert (
        policy.is_allowed(
            roles=("ScopedFinance", "ScopedOps"),
            action=ACTION_CAN_READ,
            resource=RESOURCE_DAG,
            context=blocked_context,
        )
        is False
    )


def test_role_filter_runtime_allowed_resources_respect_active_filtered_roles(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _, _, cfg = load_config_case("valid_role_filters_multi_role.ini", monkeypatch)
    policy = RbacPolicy(cfg)

    allowed = policy.allowed_resources_for_action(
        roles=("ScopedFinance", "ScopedOps"),
        action=ACTION_CAN_READ,
        context=_context(
            dag_id="finance_margin",
            tags=("finance",),
            environments=("prod",),
        ),
    )

    assert RESOURCE_DAG in allowed
