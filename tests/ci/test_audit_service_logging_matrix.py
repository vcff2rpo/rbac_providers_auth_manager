from __future__ import annotations

import json
import logging

from rbac_providers_auth_manager.services.audit_service import AuditService


def _payloads(caplog) -> list[dict[str, object]]:
    payloads: list[dict[str, object]] = []
    for record in caplog.records:
        if record.name != "rbac_providers_auth_manager.audit":
            continue
        payloads.append(json.loads(record.getMessage()))
    return payloads


def test_audit_service_emits_structured_provider_and_mapping_logs(caplog) -> None:
    audit = AuditService()
    with caplog.at_level(logging.DEBUG, logger="rbac_providers_auth_manager.audit"):
        audit.log_provider_success(
            provider="ldap",
            principal="alice",
            subject="uid=alice,ou=users,dc=example,dc=test",
            ip_address="127.0.0.1",
            roles=("Admin", "Viewer"),
            external_values_count=3,
            mapped_values_count=2,
            strict_permissions=True,
            surface="api",
        )
        audit.log_role_mapping_empty(
            provider="ldap",
            principal="alice",
            subject="uid=alice,ou=users,dc=example,dc=test",
            ip_address="127.0.0.1",
            external_values_count=1,
            mapped_values_count=0,
            strict_permissions=True,
            deny_if_no_roles=True,
        )
        audit.log_dropped_roles(
            provider="ldap",
            principal="alice",
            dropped_roles=("UnknownRole",),
            strict_mode=True,
        )

    payloads = _payloads(caplog)
    print("audit_payloads=", payloads)

    assert [payload["event"] for payload in payloads] == [
        "api.auth.login.success",
        "auth.role_mapping.empty",
        "auth.role_mapping.dropped",
    ]
    assert payloads[0]["surface"] == "api"
    assert payloads[0]["outcome"] == "success"
    assert payloads[0]["roles"] == ["Admin", "Viewer"]
    assert payloads[1]["mapped_values_count"] == 0
    assert payloads[1]["deny_if_no_roles"] is True
    assert payloads[2]["severity"] == "info"
    assert payloads[2]["dropped_roles"] == ["UnknownRole"]


def test_audit_service_emits_token_and_browser_failure_logs(caplog) -> None:
    audit = AuditService()
    with caplog.at_level(logging.DEBUG, logger="rbac_providers_auth_manager.audit"):
        audit.log_token_issue(
            mode="api",
            principal="alice",
            ip_address="127.0.0.1",
            outcome="failure",
            detail="invalid credentials",
        )
        audit.log_flow_event(
            event="auth.browser_login.failure",
            level="warning",
            provider="ldap",
            principal="alice",
            mapped_error="throttled",
            retry_after=9,
        )

    payloads = _payloads(caplog)
    print("token_and_browser_payloads=", payloads)

    assert [payload["event"] for payload in payloads] == [
        "api.auth.token.failure",
        "ui.auth.login.failure",
    ]
    assert payloads[0]["severity"] == "warning"
    assert payloads[0]["detail"] == "invalid credentials"
    assert payloads[1]["legacy_event"] == "auth.browser_login.failure"
    assert payloads[1]["surface"] == "ui"
    assert payloads[1]["outcome"] == "failure"
    assert payloads[1]["mapped_error"] == "throttled"
    assert payloads[1]["retry_after"] == 9
