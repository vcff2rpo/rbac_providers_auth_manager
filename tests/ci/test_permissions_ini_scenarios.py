from __future__ import annotations

from pathlib import Path

import pytest

from rbac_providers_auth_manager.config_runtime.mapping_parsers import (
    parse_role_mapping_raw,
)
from rbac_providers_auth_manager.config_runtime.parser import load_config
from rbac_providers_auth_manager.runtime.secret_references import SecurityConfigError

BASE_CONFIG = """
[general]
enable_ldap = true
enable_entra_id = false
config_reload_seconds = 0
strict_permissions = true
log_level = INFO
deny_if_no_roles = true
trusted_proxies = 127.0.0.1/32, 10.0.0.0/8

[security]
allow_plaintext_secrets = false
allow_insecure_ldap_tls = false
allow_graph_group_fallback = false
rate_limit_backend = memory
auth_state_backend = cookie

[jwt]
cookie_httponly = true
cookie_samesite = lax
cookie_path = /

[ldap]
enabled = true
server_uri = ldaps://ldap.example.com:636
username_dn_format = CN=%s,OU=Users,DC=example,DC=com
search_base = OU=Users,DC=example,DC=com
uid_attr = uid
username_attr = sAMAccountName
group_attr = memberOf
first_name_attr = givenName
last_name_attr = sn
email_attr = mail
start_tls = false
allow_self_signed = false
tls_require_cert = demand
connect_timeout_seconds = 5
network_timeout_seconds = 5
operation_timeout_seconds = 5
username_pattern = ^[A-Za-z0-9._-]{1,128}$
username_max_length = 128
resolve_nested_groups = false

[role_mapping]
CN=Example_Viewer,OU=Groups,DC=example,DC=com = Viewer
CN=Example_Operator,OU=Groups,DC=example,DC=com = Operator

[role:Viewer]
menu_access = Website, DAGs
can_read = Website, DAGs

[role:Operator]
menu_access = Website, DAGs, DAG Runs
can_read = Website, DAGs, DAG Runs
can_edit = DAG Runs
""".strip()


def _write_config(tmp_path: Path, text: str) -> Path:
    config_path = tmp_path / "permissions.ini"
    config_path.write_text(text + "\n", encoding="utf-8")
    return config_path


def test_permissions_ini_accepts_redis_backends_when_required_urls_are_present(
    tmp_path: Path,
) -> None:
    config_path = _write_config(
        tmp_path,
        BASE_CONFIG.replace(
            "rate_limit_backend = memory\nauth_state_backend = cookie",
            "rate_limit_backend = redis\n"
            "redis_url = redis://cache.example.com:6379/0\n"
            "auth_state_backend = redis\n"
            "auth_state_redis_url = redis://cache.example.com:6379/1",
        ),
    )

    cfg = load_config(config_path)

    assert cfg.security.rate_limit_backend == "redis"
    assert cfg.security.redis_url == "redis://cache.example.com:6379/0"
    assert cfg.security.auth_state_backend == "redis"
    assert cfg.security.auth_state_redis_url == "redis://cache.example.com:6379/1"


def test_permissions_ini_allows_self_signed_ldap_only_with_explicit_security_override(
    tmp_path: Path,
) -> None:
    config_path = _write_config(
        tmp_path,
        BASE_CONFIG.replace(
            "allow_insecure_ldap_tls = false", "allow_insecure_ldap_tls = true"
        ).replace("allow_self_signed = false", "allow_self_signed = true"),
    )

    cfg = load_config(config_path)

    assert cfg.security.allow_insecure_ldap_tls is True
    assert cfg.ldap is not None
    assert cfg.ldap.allow_self_signed is True


def test_permissions_ini_allows_entra_graph_overage_fallback_only_with_override(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("ENTRA_CLIENT_SECRET", "dummy-entra-secret")

    config_path = _write_config(
        tmp_path,
        BASE_CONFIG.replace(
            "enable_entra_id = false", "enable_entra_id = true"
        ).replace(
            "allow_graph_group_fallback = false",
            "allow_graph_group_fallback = true",
        )
        + "\n\n[entra_id]\n"
        + "enabled = true\n"
        + "tenant_id = tenant\n"
        + "client_id = client-id\n"
        + "client_secret = env:ENTRA_CLIENT_SECRET\n"
        + "graph_fetch_groups_on_overage = true\n"
        + "allowed_oidc_hosts = login.microsoftonline.com, graph.microsoft.com\n",
    )

    cfg = load_config(config_path)

    assert cfg.entra_id is not None
    assert cfg.general.enable_entra_id is True
    assert cfg.security.allow_graph_group_fallback is True
    assert cfg.entra_id.graph_fetch_groups_on_overage is True


def test_permissions_ini_rejects_missing_entra_secret_env_reference(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.delenv("ENTRA_CLIENT_SECRET", raising=False)

    config_path = _write_config(
        tmp_path,
        BASE_CONFIG.replace("enable_entra_id = false", "enable_entra_id = true")
        + "\n\n[entra_id]\n"
        + "enabled = true\n"
        + "tenant_id = tenant\n"
        + "client_id = client-id\n"
        + "client_secret = env:ENTRA_CLIENT_SECRET\n"
        + "allowed_oidc_hosts = login.microsoftonline.com, graph.microsoft.com\n",
    )

    with pytest.raises(
        SecurityConfigError,
        match="Secret environment variable is not set or empty: ENTRA_CLIENT_SECRET",
    ):
        load_config(config_path)


def test_permissions_ini_supports_jwt_cookie_alias_and_samesite_fallback(
    tmp_path: Path,
) -> None:
    config_path = _write_config(
        tmp_path,
        BASE_CONFIG.replace("[jwt]", "[jwt_cookie]").replace(
            "cookie_samesite = lax", "cookie_samesite = sideways"
        ),
    )

    cfg = load_config(config_path)

    assert cfg.jwt_cookie.cookie_samesite.lower() == "lax"
    assert cfg.jwt_cookie.cookie_path == "/"


def test_permissions_ini_role_mapping_merges_duplicate_dns_and_multiple_orientations(
    tmp_path: Path,
) -> None:
    config_path = _write_config(
        tmp_path,
        """
[role_mapping]
CN=Example_Viewer,OU=Groups,DC=example,DC=com = Viewer | Auditor
Viewer = CN=Example_Operator,OU=Groups,DC=example,DC=com | CN=Example_Viewer,OU=Groups,DC=example,DC=com
CN=Example_Operator,OU=Groups,DC=example,DC=com = Operator
""".strip(),
    )

    mapping = parse_role_mapping_raw(config_path)

    assert mapping.dn_to_roles["cn=example_viewer,ou=groups,dc=example,dc=com"] == {
        "Auditor",
        "Viewer",
    }
    assert mapping.dn_to_roles["cn=example_operator,ou=groups,dc=example,dc=com"] == {
        "Operator",
        "Viewer",
    }
