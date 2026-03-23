from __future__ import annotations

import os
import pytest

ldap = pytest.importorskip("ldap")


def _require_or_skip(name: str) -> str:
    value = os.environ.get(name, "").strip()
    if value:
        return value
    if os.environ.get("REQUIRE_EXTERNAL_SECRETS", "false").lower() == "true":
        pytest.fail(f"Missing required external validation variable: {name}")
    pytest.skip(f"External LDAP validation is not configured: missing {name}")


@pytest.mark.external_real
@pytest.mark.slow
def test_real_enterprise_ldap_schema_and_group_profile() -> None:
    uri = _require_or_skip("REAL_LDAP_URI")
    bind_dn = _require_or_skip("REAL_LDAP_BIND_DN")
    bind_password = _require_or_skip("REAL_LDAP_BIND_PASSWORD")
    search_base = _require_or_skip("REAL_LDAP_SEARCH_BASE")
    username = _require_or_skip("REAL_LDAP_TEST_USERNAME")
    user_filter = os.environ.get("REAL_LDAP_USER_FILTER", "(uid={username})")
    group_attr = os.environ.get("REAL_LDAP_GROUP_ATTR", "memberOf")
    expected_attrs = [
        item.strip()
        for item in os.environ.get("REAL_LDAP_EXPECTED_ATTRS", "cn,mail").split(",")
        if item.strip()
    ]
    expected_groups = [
        item.strip().lower()
        for item in os.environ.get("REAL_LDAP_EXPECTED_GROUPS", "").split(",")
        if item.strip()
    ]

    conn = ldap.initialize(uri)
    try:
        conn.simple_bind_s(bind_dn, bind_password)
        filter_str = user_filter.format(username=username)
        attrs_to_fetch = list(dict.fromkeys([*expected_attrs, group_attr]))
        rows: list[tuple[str, dict[str, list[bytes]]]] = conn.search_ext_s(
            search_base,
            ldap.SCOPE_SUBTREE,
            filter_str,
            attrs_to_fetch,
        )
        print("ldap_search_filter=", filter_str)
        print("ldap_result_count=", len(rows))
        assert rows, "Expected at least one LDAP row"
        dn, attrs = rows[0]
        print("ldap_user_dn=", dn)
        decoded: dict[str, list[str]] = {
            key: [value.decode("utf-8", errors="replace") for value in values]
            for key, values in attrs.items()
        }
        print("ldap_attrs=", decoded)
        for attr in expected_attrs:
            assert decoded.get(attr), f"Missing expected LDAP attribute: {attr}"
        if expected_groups:
            actual_groups = {value.lower() for value in decoded.get(group_attr, [])}
            assert set(expected_groups).issubset(actual_groups)
    finally:
        conn.unbind_s()
