from __future__ import annotations

import pytest


def test_auth_manager_import_under_airflow() -> None:
    pytest.importorskip("airflow")
    from rbac_providers_auth_manager.auth_manager import ItimLdapAuthManager

    assert ItimLdapAuthManager.__name__ == "ItimLdapAuthManager"
