from __future__ import annotations

from rbac_providers_auth_manager.identity.mapper import IdentityMapper
from rbac_providers_auth_manager.identity.models import ExternalIdentity

from ._identity_test_support import _FakeManager, build_identity_test_config


def test_ldap_mapping_edge_matrix_deduplicates_roles_but_keeps_mapping_hit_history() -> (
    None
):
    manager = _FakeManager(build_identity_test_config(strict_permissions=True))
    mapper = IdentityMapper(manager)

    result = mapper.map_ldap_identity(
        identity=ExternalIdentity(
            provider="ldap",
            user_id="ldap-1",
            username="alice",
            group_dns=(
                "CN=Viewer,OU=Groups,DC=example,DC=com",
                "cn=viewer,ou=groups,dc=example,dc=com",
                "CN=Operator,OU=Groups,DC=example,DC=com",
            ),
        ),
        ip_address="127.0.0.1",
    )

    print("ldap_duplicate_group_result=", result)
    assert result.roles == ("Operator", "Viewer")
    assert result.dropped_roles == ("Ghost",)
    assert result.external_values_count == 3
    assert result.mapped_values_count == 3
    assert result.mapping_hits[0][0] == result.mapping_hits[1][0]
    assert result.mapping_hits[2][0] == "cn=operator,ou=groups,dc=example,dc=com"


def test_ldap_mapping_edge_matrix_ignores_blank_dns_and_drops_unknown_roles_in_strict_mode() -> (
    None
):
    manager = _FakeManager(
        build_identity_test_config(
            strict_permissions=True,
            dn_to_roles={
                "cn=power,ou=groups,dc=example,dc=com": {
                    "Operator",
                    "Viewer",
                    "Ghost",
                }
            },
        )
    )
    mapper = IdentityMapper(manager)

    result = mapper.map_ldap_identity(
        identity=ExternalIdentity(
            provider="ldap",
            user_id="ldap-2",
            username="bob",
            group_dns=("", "   ", "CN=Power,OU=Groups,DC=example,DC=com"),
        ),
        ip_address="127.0.0.1",
    )

    print("ldap_blank_and_drop_result=", result)
    assert result.roles == ("Operator", "Viewer")
    assert result.dropped_roles == ("Ghost",)
    assert result.external_values_count == 3
    assert result.mapped_values_count == 1
    assert result.mapping_hits == (
        ("cn=power,ou=groups,dc=example,dc=com", ("Ghost", "Operator", "Viewer")),
    )
