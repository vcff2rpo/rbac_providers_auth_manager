from __future__ import annotations

import pytest

from rbac_providers_auth_manager.core.exceptions import LdapAuthError
from rbac_providers_auth_manager.identity.mapper import IdentityMapper
from rbac_providers_auth_manager.identity.models import (
    ExternalIdentity,
    RoleMappingResult,
)

from ._identity_test_support import _FakeManager, build_identity_test_config


def test_identity_mapping_matrix_ldap_strict_mode_drops_undefined_roles() -> None:
    manager = _FakeManager(build_identity_test_config(strict_permissions=True))
    mapper = IdentityMapper(manager)

    result = mapper.map_ldap_identity(
        identity=ExternalIdentity(
            provider="ldap",
            user_id="u-1",
            username="alice",
            group_dns=("CN=Viewer,OU=Groups,DC=example,DC=com",),
        ),
        ip_address="127.0.0.1",
    )

    print("ldap_strict_result=", result)
    assert isinstance(result, RoleMappingResult)
    assert result.roles == ("Viewer",)
    assert result.dropped_roles == ("Ghost",)
    assert result.mapping_hits[0][0] == "cn=viewer,ou=groups,dc=example,dc=com"
    assert manager.debug_role_logs[-1] == ("alice", ["Viewer"])


def test_identity_mapping_matrix_ldap_fallback_role_when_no_groups_map() -> None:
    manager = _FakeManager(
        build_identity_test_config(
            strict_permissions=True,
            auth_user_registration=True,
            auth_user_registration_role="Public",
        )
    )
    mapper = IdentityMapper(manager)

    result = mapper.map_ldap_identity(
        identity=ExternalIdentity(
            provider="ldap",
            user_id="u-2",
            username="bob",
            group_dns=("CN=Missing,OU=Groups,DC=example,DC=com",),
        ),
        ip_address="127.0.0.1",
    )

    print("ldap_fallback_result=", result)
    assert result.roles == ("Public",)
    assert manager._audit_service.role_mapping_empty
    assert manager._audit_service.provider_success[-1]["roles"] == ["Public"]


def test_identity_mapping_matrix_entra_permissive_mode_keeps_unconfigured_roles() -> (
    None
):
    manager = _FakeManager(build_identity_test_config(strict_permissions=False))
    mapper = IdentityMapper(manager)

    result = mapper.map_entra_identity(
        identity=ExternalIdentity(
            provider="entra",
            user_id="oid-1",
            username="carol@example.com",
            claim_values=("viewer-group",),
        ),
        ip_address="127.0.0.1",
    )

    print("entra_permissive_result=", result)
    assert set(result.roles) == {"Ghost", "Viewer"}
    assert result.dropped_roles == ()
    assert manager.debug_role_logs[-1][0] == "carol@example.com"


def test_identity_mapping_matrix_entra_rejects_unmapped_identity_without_fallback() -> (
    None
):
    manager = _FakeManager(build_identity_test_config(strict_permissions=True))
    mapper = IdentityMapper(manager)

    with pytest.raises(LdapAuthError, match="No Airflow roles mapped"):
        mapper.map_entra_identity(
            identity=ExternalIdentity(
                provider="entra",
                user_id="oid-2",
                username="dave@example.com",
                claim_values=("unknown-group",),
            ),
            ip_address="127.0.0.1",
        )

    assert manager._audit_service.role_mapping_empty
    print("entra_empty_events=", manager._audit_service.role_mapping_empty)
