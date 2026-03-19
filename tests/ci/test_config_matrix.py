from __future__ import annotations

from pathlib import Path

import pytest

from rbac_providers_auth_manager.config_runtime.mapping_parsers import parse_role_mapping_raw
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

[security]
allow_plaintext_secrets = false
allow_insecure_ldap_tls = false
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

[role:Viewer]
menu_access = Website, DAGs
can_read = Website, DAGs
""".strip()


def _write_config(tmp_path: Path, text: str) -> Path:
    config_path = tmp_path / "permissions.ini"
    config_path.write_text(text + "\n", encoding="utf-8")
    return config_path


def test_load_config_accepts_minimal_valid_ldap_configuration(tmp_path: Path) -> None:
    config_path = _write_config(tmp_path, BASE_CONFIG)
    cfg = load_config(config_path)

    assert cfg.ldap is not None
    assert cfg.ldap.enabled is True
    assert cfg.entra_id is None
    assert cfg.jwt_cookie.cookie_httponly is True
    assert "Viewer" in cfg.roles.role_to_permissions
    assert any(advisory.code == "missing_meta_section" for advisory in cfg.advisories)


def test_load_config_rejects_invalid_rate_limit_backend(tmp_path: Path) -> None:
    config_path = _write_config(
        tmp_path,
        BASE_CONFIG.replace("rate_limit_backend = memory", "rate_limit_backend = broken"),
    )

    with pytest.raises(ValueError, match="Unsupported security.rate_limit_backend"):
        load_config(config_path)


def test_load_config_requires_redis_url_when_redis_backend_is_selected(tmp_path: Path) -> None:
    config_path = _write_config(
        tmp_path,
        BASE_CONFIG.replace("rate_limit_backend = memory", "rate_limit_backend = redis"),
    )

    with pytest.raises(ValueError, match="requires security.redis_url"):
        load_config(config_path)


def test_load_config_rejects_allow_self_signed_without_security_override(tmp_path: Path) -> None:
    config_path = _write_config(
        tmp_path,
        BASE_CONFIG.replace("allow_self_signed = false", "allow_self_signed = true"),
    )

    with pytest.raises(ValueError, match="allow_insecure_ldap_tls = true"):
        load_config(config_path)


def test_load_config_rejects_plaintext_secret_when_disabled(tmp_path: Path) -> None:
    config_path = _write_config(
        tmp_path,
        BASE_CONFIG.replace(
            "username_dn_format = CN=%s,OU=Users,DC=example,DC=com",
            "username_dn_format = CN=%s,OU=Users,DC=example,DC=com\nbind_password = supersecret",
        ),
    )

    with pytest.raises(SecurityConfigError, match="Plaintext secrets"):
        load_config(config_path)


def test_load_config_rejects_entra_graph_fallback_without_security_override(tmp_path: Path) -> None:
    config_path = _write_config(
        tmp_path,
        BASE_CONFIG.replace("enable_entra_id = false", "enable_entra_id = true")
        + "\n\n[entra_id]\n"
        + "enabled = true\n"
        + "tenant_id = tenant\n"
        + "client_id = client\n"
        + "client_secret = literal:secret\n"
        + "graph_fetch_groups_on_overage = true\n",
    )

    with pytest.raises(ValueError, match="allow_graph_group_fallback = true"):
        load_config(config_path)


def test_role_mapping_parser_supports_legacy_and_recommended_orientation(tmp_path: Path) -> None:
    config_path = _write_config(
        tmp_path,
        """
[role_mapping]
CN=Legacy_Group,OU=Groups,DC=example,DC=com = Viewer
Viewer = CN=Primary,OU=Groups,DC=example,DC=com | CN=Secondary,OU=Groups,DC=example,DC=com
""".strip(),
    )

    mapping = parse_role_mapping_raw(config_path)

    assert mapping.dn_to_roles["cn=legacy_group,ou=groups,dc=example,dc=com"] == {"Viewer"}
    assert mapping.dn_to_roles["cn=primary,ou=groups,dc=example,dc=com"] == {"Viewer"}
    assert mapping.dn_to_roles["cn=secondary,ou=groups,dc=example,dc=com"] == {"Viewer"}
