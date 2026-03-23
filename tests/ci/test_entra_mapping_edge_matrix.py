from __future__ import annotations

from rbac_providers_auth_manager.identity.mapper import IdentityMapper
from rbac_providers_auth_manager.identity.models import ExternalIdentity

from ._identity_test_support import _FakeManager, build_identity_test_config


def test_entra_mapping_edge_matrix_normalizes_case_and_whitespace_per_claim() -> None:
    manager = _FakeManager(
        build_identity_test_config(
            strict_permissions=True,
            claim_value_to_roles={
                "viewer-group": {"Viewer"},
                "operator-group": {"Operator"},
            },
        )
    )
    mapper = IdentityMapper(manager)

    result = mapper.map_entra_identity(
        identity=ExternalIdentity(
            provider="entra",
            user_id="entra-1",
            username="carol@example.com",
            claim_values=(
                "  Viewer-Group  ",
                "viewer-group",
                "OPERATOR-GROUP",
            ),
        ),
        ip_address="127.0.0.1",
    )

    print("entra_normalization_result=", result)
    assert result.roles == ("Operator", "Viewer")
    assert result.dropped_roles == ()
    assert result.external_values_count == 3
    assert result.mapped_values_count == 3
    assert result.mapping_hits[0][0] == "viewer-group"
    assert result.mapping_hits[1][0] == "viewer-group"
    assert result.mapping_hits[2][0] == "operator-group"


def test_entra_mapping_edge_matrix_one_claim_can_map_to_many_roles_and_drop_unknowns() -> (
    None
):
    manager = _FakeManager(
        build_identity_test_config(
            strict_permissions=True,
            claim_value_to_roles={
                "power-user": {"Operator", "Viewer", "Ghost"},
            },
        )
    )
    mapper = IdentityMapper(manager)

    result = mapper.map_entra_identity(
        identity=ExternalIdentity(
            provider="entra",
            user_id="entra-2",
            username="dave@example.com",
            claim_values=("power-user",),
        ),
        ip_address="127.0.0.1",
    )

    print("entra_multi_role_result=", result)
    assert result.roles == ("Operator", "Viewer")
    assert result.dropped_roles == ("Ghost",)
    assert result.mapping_hits == (("power-user", ("Ghost", "Operator", "Viewer")),)
