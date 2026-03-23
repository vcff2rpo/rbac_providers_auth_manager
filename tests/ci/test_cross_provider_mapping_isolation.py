from __future__ import annotations

from rbac_providers_auth_manager.identity.mapper import IdentityMapper
from rbac_providers_auth_manager.identity.models import ExternalIdentity

from ._identity_test_support import _FakeManager, build_identity_test_config


def test_cross_provider_mapping_isolation_ldap_ignores_entra_claim_values() -> None:
    manager = _FakeManager(
        build_identity_test_config(
            strict_permissions=True,
            dn_to_roles={"cn=viewer,ou=groups,dc=example,dc=com": {"Viewer"}},
            claim_value_to_roles={"viewer-group": {"Operator"}},
        )
    )
    mapper = IdentityMapper(manager)

    result = mapper.map_ldap_identity(
        identity=ExternalIdentity(
            provider="ldap",
            user_id="mixed-ldap",
            username="erin",
            group_dns=("CN=Viewer,OU=Groups,DC=example,DC=com",),
            claim_values=("viewer-group",),
        ),
        ip_address="127.0.0.1",
    )

    print("cross_provider_ldap_result=", result)
    assert result.roles == ("Viewer",)
    assert result.mapping_hits == (
        ("cn=viewer,ou=groups,dc=example,dc=com", ("Viewer",)),
    )


def test_cross_provider_mapping_isolation_entra_ignores_ldap_group_dns() -> None:
    manager = _FakeManager(
        build_identity_test_config(
            strict_permissions=True,
            dn_to_roles={"cn=viewer,ou=groups,dc=example,dc=com": {"Viewer"}},
            claim_value_to_roles={"viewer-group": {"Operator"}},
        )
    )
    mapper = IdentityMapper(manager)

    result = mapper.map_entra_identity(
        identity=ExternalIdentity(
            provider="entra",
            user_id="mixed-entra",
            username="frank@example.com",
            group_dns=("CN=Viewer,OU=Groups,DC=example,DC=com",),
            claim_values=("viewer-group",),
        ),
        ip_address="127.0.0.1",
    )

    print("cross_provider_entra_result=", result)
    assert result.roles == ("Operator",)
    assert result.mapping_hits == (("viewer-group", ("Operator",)),)
