from __future__ import annotations

from collections.abc import Callable
from dataclasses import replace
from typing import Any

import pytest

from rbac_providers_auth_manager.config_runtime.models import LdapConfig
from rbac_providers_auth_manager.core.exceptions import LdapAuthError
from rbac_providers_auth_manager.providers.ldap_client import LdapClient


class _FakeLdapError(Exception):
    pass


class _FakeInvalidCredentials(_FakeLdapError):
    pass


class _FakeConn:
    def __init__(
        self,
        *,
        valid_binds: dict[str, str],
        search_handler: Callable[..., list[tuple[str | None, dict[str, list[bytes]]]]],
    ) -> None:
        self.valid_binds = valid_binds
        self.search_handler = search_handler
        self.unbound = False
        self.protocol_version: int | None = None
        self.options: list[tuple[int, Any]] = []

    def set_option(self, option: int, value: Any) -> None:
        self.options.append((option, value))

    def start_tls_s(self) -> None:
        return None

    def simple_bind_s(self, bind_dn: str, password: str) -> None:
        if self.valid_binds.get(bind_dn) != password:
            raise _FakeInvalidCredentials("bad credentials")

    def search_ext_s(
        self, *args: Any, **kwargs: Any
    ) -> list[tuple[str | None, dict[str, list[bytes]]]]:
        return self.search_handler(*args, **kwargs)

    def unbind_s(self) -> None:
        self.unbound = True


class _FakeLdapModule:
    VERSION3 = 3
    OPT_REFERRALS = 101
    OPT_NETWORK_TIMEOUT = 102
    OPT_TIMEOUT = 103
    OPT_CONNECT_TIMEOUT = 104
    OPT_X_TLS_NEVER = 105
    OPT_X_TLS_ALLOW = 106
    OPT_X_TLS_TRY = 107
    OPT_X_TLS_DEMAND = 108
    OPT_X_TLS_HARD = 109
    OPT_X_TLS_REQUIRE_CERT = 110
    OPT_X_TLS_CACERTFILE = 111
    SCOPE_BASE = 0
    SCOPE_SUBTREE = 2
    LDAPError = _FakeLdapError
    INVALID_CREDENTIALS = _FakeInvalidCredentials

    def __init__(self, conn: _FakeConn) -> None:
        self._conn = conn
        self.global_options: list[tuple[int, Any]] = []

    def set_option(self, option: int, value: Any) -> None:
        self.global_options.append((option, value))

    def initialize(self, uri: str) -> _FakeConn:
        assert uri.startswith(("ldap://", "ldaps://"))
        return self._conn


@pytest.fixture()
def ldap_cfg() -> LdapConfig:
    return LdapConfig(
        enabled=True,
        uri="ldaps://ldap.example.com:636",
        bind_dn="cn=svc,dc=example,dc=com",
        bind_password="svc-secret",
        user_base_dn="ou=Users,dc=example,dc=com",
        user_filter="(uid={username})",
        group_attribute="memberOf",
        username_dn_format=None,
        search_base="ou=Users,dc=example,dc=com",
        start_tls=False,
        allow_self_signed=False,
        tls_ca_cert_file=None,
        tls_require_cert="demand",
        resolve_nested_groups=False,
        nested_groups_base_dn="ou=Groups,dc=example,dc=com",
        nested_group_match_rule="1.2.840.113556.1.4.1941",
        connect_timeout_seconds=5,
        network_timeout_seconds=5,
        operation_timeout_seconds=5,
        search_time_limit_seconds=5,
        size_limit=10,
        chase_referrals=False,
        username_pattern=r"^[A-Za-z0-9._-]+$",
        username_max_length=64,
        attr_uid="uidNumber",
        attr_username="uid",
        attr_first_name="givenName",
        attr_last_name="sn",
        attr_email="mail",
    )


def test_ldap_direct_bind_with_nested_groups_returns_normalized_identity(
    monkeypatch: pytest.MonkeyPatch,
    ldap_cfg: LdapConfig,
    caplog: pytest.LogCaptureFixture,
) -> None:
    user_dn = "uid=alice,ou=Users,dc=example,dc=com"
    user_attrs = {
        "uidNumber": [b"1001"],
        "uid": [b"alice"],
        "givenName": [b"Alice"],
        "sn": [b"Admin"],
        "mail": [b"alice@example.com"],
        "memberOf": [b"cn=airflow-users,ou=Groups,dc=example,dc=com"],
    }

    def search_handler(
        base_dn: str,
        scope: int,
        filterstr: str,
        _attrs: list[str],
        *_args: Any,
    ) -> list[tuple[str | None, dict[str, list[bytes]]]]:
        if scope == _FakeLdapModule.SCOPE_BASE:
            assert base_dn == user_dn
            return [(user_dn, user_attrs)]
        assert "member:1.2.840.113556.1.4.1941:=" in filterstr
        return [
            ("cn=airflow-admins,ou=Groups,dc=example,dc=com", {}),
            ("cn=airflow-users,ou=Groups,dc=example,dc=com", {}),
        ]

    conn = _FakeConn(
        valid_binds={user_dn: "correct-password"}, search_handler=search_handler
    )
    fake_ldap = _FakeLdapModule(conn)

    direct_cfg = replace(
        ldap_cfg,
        bind_dn=None,
        bind_password=None,
        username_dn_format="uid=%s,ou=Users,dc=example,dc=com",
        resolve_nested_groups=True,
    )

    import rbac_providers_auth_manager.providers.ldap_client as ldap_client_module
    import rbac_providers_auth_manager.providers.ldap_connection_service as ldap_conn_module

    monkeypatch.setattr(ldap_client_module, "ldap_module", lambda: fake_ldap)
    monkeypatch.setattr(ldap_conn_module, "ldap_module", lambda: fake_ldap)
    monkeypatch.setattr(ldap_conn_module, "escape_filter_chars", lambda value: value)

    client = LdapClient(direct_cfg)

    with caplog.at_level("DEBUG"):
        identity = client.authenticate("alice", "correct-password")

    assert identity.user_id == "1001"
    assert identity.username == "alice"
    assert identity.display_name == "Alice Admin"
    assert identity.email == "alice@example.com"
    assert identity.group_dns == [
        "cn=airflow-users,ou=Groups,dc=example,dc=com",
        "cn=airflow-admins,ou=Groups,dc=example,dc=com",
    ]
    assert conn.unbound is True
    assert "LDAP direct-bind attempt" in caplog.text
    assert "LDAP group_dns fingerprints" in caplog.text


def test_ldap_search_bind_invalid_credentials_are_reported(
    monkeypatch: pytest.MonkeyPatch,
    ldap_cfg: LdapConfig,
) -> None:
    user_dn = "uid=alice,ou=Users,dc=example,dc=com"
    user_attrs = {
        "uidNumber": [b"1001"],
        "uid": [b"alice"],
        "givenName": [b"Alice"],
        "sn": [b"Admin"],
        "mail": [b"alice@example.com"],
        "memberOf": [b"cn=airflow-users,ou=Groups,dc=example,dc=com"],
    }

    def search_handler(
        *_args: Any, **_kwargs: Any
    ) -> list[tuple[str | None, dict[str, list[bytes]]]]:
        return [(user_dn, user_attrs)]

    conn = _FakeConn(
        valid_binds={
            ldap_cfg.bind_dn or "": ldap_cfg.bind_password or "",
            user_dn: "correct-password",
        },
        search_handler=search_handler,
    )
    fake_ldap = _FakeLdapModule(conn)

    import rbac_providers_auth_manager.providers.ldap_client as ldap_client_module
    import rbac_providers_auth_manager.providers.ldap_connection_service as ldap_conn_module

    monkeypatch.setattr(ldap_client_module, "ldap_module", lambda: fake_ldap)
    monkeypatch.setattr(ldap_conn_module, "ldap_module", lambda: fake_ldap)
    monkeypatch.setattr(ldap_conn_module, "escape_filter_chars", lambda value: value)

    client = LdapClient(ldap_cfg)

    with pytest.raises(LdapAuthError, match="Invalid credentials"):
        client.authenticate("alice", "wrong-password")

    assert conn.unbound is True


def test_ldap_rejects_invalid_username_before_backend_io(ldap_cfg: LdapConfig) -> None:
    client = LdapClient(ldap_cfg)

    with pytest.raises(LdapAuthError, match="Invalid username format"):
        client.authenticate("bad\nuser", "secret")

    with pytest.raises(LdapAuthError, match="Missing password"):
        client.authenticate("alice", "")
