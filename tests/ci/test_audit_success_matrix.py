from __future__ import annotations

import json
import logging

import pytest

from rbac_providers_auth_manager.services.audit_service import AuditService


def _payloads(caplog: pytest.LogCaptureFixture) -> list[dict[str, object]]:
    payloads: list[dict[str, object]] = []
    for record in caplog.records:
        if record.name != "rbac_providers_auth_manager.audit":
            continue
        payloads.append(json.loads(record.getMessage()))
    return payloads


def test_audit_success_matrix_emits_ui_login_and_token_success_events(
    caplog: pytest.LogCaptureFixture,
) -> None:
    audit = AuditService()
    with caplog.at_level(logging.DEBUG, logger="rbac_providers_auth_manager.audit"):
        audit.log_provider_success(
            provider="ldap",
            principal="alice",
            subject="uid=alice,ou=users,dc=example,dc=test",
            ip_address="127.0.0.1",
            roles=("Viewer",),
            external_values_count=2,
            mapped_values_count=1,
            strict_permissions=True,
            surface="ui",
        )
        audit.log_token_issue(
            mode="cli",
            principal="alice",
            ip_address="127.0.0.1",
            outcome="success",
            detail=None,
        )

    payloads = _payloads(caplog)
    print("audit_success_payloads=", payloads)

    assert [payload["event"] for payload in payloads] == [
        "ui.auth.login.success",
        "api.auth.token.success",
    ]
    assert payloads[0]["surface"] == "ui"
    assert payloads[0]["outcome"] == "success"
    assert payloads[0]["roles"] == ["Viewer"]
    assert payloads[1]["mode"] == "cli"
    assert payloads[1]["severity"] == "info"
    assert payloads[1]["outcome"] == "success"


def test_audit_success_matrix_canonicalizes_callback_and_provider_disabled_events(
    caplog: pytest.LogCaptureFixture,
) -> None:
    audit = AuditService()
    with caplog.at_level(logging.DEBUG, logger="rbac_providers_auth_manager.audit"):
        audit.log_flow_event(
            event="auth.oauth_callback.rejected",
            level="warning",
            provider="entra",
            principal="carol@example.com",
            reason="state mismatch",
        )
        audit.log_flow_event(
            event="auth.provider.disabled",
            level="warning",
            provider="ldap",
            reason="optional dependency missing",
        )

    payloads = _payloads(caplog)
    print("audit_callback_and_disabled_payloads=", payloads)

    assert payloads[0]["event"] == "ui.auth.oauth_callback.rejected"
    assert payloads[0]["legacy_event"] == "auth.oauth_callback.rejected"
    assert payloads[0]["surface"] == "ui"
    assert payloads[0]["outcome"] == "rejected"
    assert payloads[0]["severity"] == "warning"
    assert payloads[1]["event"] == "auth.provider.disabled"
    assert payloads[1]["registry_status"] == "unregistered"
    assert payloads[1]["outcome"] == "disabled"
    assert payloads[1]["reason"] == "optional dependency missing"
