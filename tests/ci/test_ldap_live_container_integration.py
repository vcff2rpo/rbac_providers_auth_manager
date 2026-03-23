from __future__ import annotations

import os

import pytest

from rbac_providers_auth_manager.config_runtime.models import LdapConfig
from rbac_providers_auth_manager.core.exceptions import LdapAuthError
from rbac_providers_auth_manager.providers.ldap_client import LdapClient

ldap = pytest.importorskip("ldap")


def _require_env(name: str, default: str | None = None) -> str:
    value = os.getenv(name, default)
    if value is None or value == "":
        pytest.skip(f"Missing required integration environment variable: {name}")
    return value


def _ldap_cfg() -> LdapConfig:
    return LdapConfig(
        enabled=True,
        uri=_require_env("LDAP_TEST_URI"),
        bind_dn=_require_env("LDAP_TEST_BIND_DN", "cn=admin,dc=example,dc=org"),
        bind_password=_require_env("LDAP_TEST_BIND_PASSWORD", "adminpassword"),
        user_base_dn=_require_env(
            "LDAP_TEST_USER_BASE_DN", "ou=users,dc=example,dc=org"
        ),
        user_filter=_require_env("LDAP_TEST_USER_FILTER", "(uid={username})"),
        group_attribute=os.getenv("LDAP_TEST_GROUP_ATTRIBUTE", "memberOf"),
        username_dn_format=None,
        search_base=_require_env("LDAP_TEST_SEARCH_BASE", "ou=users,dc=example,dc=org"),
        start_tls=False,
        allow_self_signed=False,
        tls_ca_cert_file=None,
        tls_require_cert="demand",
        resolve_nested_groups=False,
        nested_groups_base_dn=None,
        nested_group_match_rule=None,
        connect_timeout_seconds=5,
        network_timeout_seconds=5,
        operation_timeout_seconds=5,
        search_time_limit_seconds=5,
        size_limit=10,
        chase_referrals=False,
        username_pattern=r"^[A-Za-z0-9._-]+$",
        username_max_length=64,
        attr_uid="uid",
        attr_username="uid",
        attr_first_name="cn",
        attr_last_name="sn",
        attr_email="mail",
    )


def test_live_ldap_search_bind_authentication() -> None:
    client = LdapClient(_ldap_cfg())

    identity = client.authenticate(
        _require_env("LDAP_TEST_USERNAME", "user01"),
        _require_env("LDAP_TEST_PASSWORD", "bitnami1"),
    )

    assert identity.user_id
    assert identity.username == _require_env("LDAP_TEST_USERNAME", "user01")
    assert identity.user_dn.endswith(
        _require_env("LDAP_TEST_USER_BASE_DN", "ou=users,dc=example,dc=org")
    )
    assert identity.display_name


def test_live_ldap_rejects_bad_password() -> None:
    client = LdapClient(_ldap_cfg())

    with pytest.raises(LdapAuthError, match="Invalid credentials"):
        client.authenticate(
            _require_env("LDAP_TEST_USERNAME", "user01"),
            "definitely-not-the-right-password",
        )
