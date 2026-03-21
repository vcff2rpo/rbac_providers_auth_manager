from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

import pytest

from rbac_providers_auth_manager.config import AuthConfig
from rbac_providers_auth_manager.config_runtime.parser import load_config
from rbac_providers_auth_manager.core.exceptions import OptionalProviderDependencyError
from rbac_providers_auth_manager.services.provider_runtime_service import (
    ProviderRuntimeService,
)

from pathlib import Path

FIXTURE_PATH = (
    Path(__file__).resolve().parents[1]
    / "fixtures"
    / "permissions"
    / "load_config"
    / "valid_dual_provider_strict.ini"
)


@dataclass
class _CfgLoader:
    cfg: AuthConfig

    def get_config(self) -> AuthConfig:
        return self.cfg


@dataclass
class _AuditService:
    flow_events: list[dict[str, Any]] = field(default_factory=list)

    def log_flow_event(self, **payload: Any) -> None:
        self.flow_events.append(payload)


class _Manager:
    def __init__(self, cfg: AuthConfig) -> None:
        self._cfg_loader = _CfgLoader(cfg)
        self._audit_service = _AuditService()
        self._config_error_message: str | None = None
        self._provider_load_errors: list[str] = []
        self._ldap_provider = None
        self._entra_provider = None
        self._policy = None
        self._ldap_rate_limiter = None
        self._oauth_rate_limiter = None
        self.capability_reports: list[str] = []

    @staticmethod
    def _client_ip(request: Any | None) -> str:
        del request
        return "127.0.0.1"

    @staticmethod
    def _limit_key(*parts: str) -> str:
        return "|".join(parts)

    def _log_runtime_capability_report(self, cfg: AuthConfig) -> None:
        self.capability_reports.append(cfg.meta.plugin_family)


@pytest.fixture()
def dual_provider_cfg(monkeypatch: pytest.MonkeyPatch) -> AuthConfig:
    monkeypatch.setenv("ENTRA_CLIENT_SECRET", "dummy-entra-secret")
    return load_config(FIXTURE_PATH)


def test_initialize_provider_clients_records_disabled_provider_events(
    dual_provider_cfg: AuthConfig,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    manager = _Manager(dual_provider_cfg)
    service = ProviderRuntimeService(manager)

    def _raise_ldap(cfg: Any) -> Any:
        del cfg
        raise OptionalProviderDependencyError("ldap optional dependency missing")

    def _raise_entra(cfg: Any) -> Any:
        del cfg
        raise OptionalProviderDependencyError("entra optional dependency missing")

    monkeypatch.setattr(service, "build_ldap_client", _raise_ldap)
    monkeypatch.setattr(service, "build_entra_client", _raise_entra)

    ldap_client, entra_client, errors = service.initialize_provider_clients(
        dual_provider_cfg
    )

    assert ldap_client is None
    assert entra_client is None
    assert errors == [
        "ldap optional dependency missing",
        "entra optional dependency missing",
    ]
    assert manager._audit_service.flow_events == [
        {
            "event": "auth.provider.disabled",
            "level": "warning",
            "provider": "ldap",
            "reason": "ldap optional dependency missing",
        },
        {
            "event": "auth.provider.disabled",
            "level": "warning",
            "provider": "entra",
            "reason": "entra optional dependency missing",
        },
    ]


def test_refresh_if_needed_logs_degraded_mode_when_all_providers_fail(
    dual_provider_cfg: AuthConfig,
    monkeypatch: pytest.MonkeyPatch,
    caplog: pytest.LogCaptureFixture,
) -> None:
    manager = _Manager(dual_provider_cfg)
    service = ProviderRuntimeService(manager)

    monkeypatch.setattr(
        service,
        "initialize_provider_clients",
        lambda cfg: (None, None, ["ldap missing", "entra missing"]),
    )
    monkeypatch.setattr(service, "configure_rate_limiters", lambda cfg: None)

    with caplog.at_level("INFO", logger="rbac_providers_auth_manager.auth_manager"):
        service.refresh_if_needed()

    assert manager._config_error_message == "ldap missing | entra missing"
    assert manager.capability_reports == [dual_provider_cfg.meta.plugin_family]
    assert any(
        record.levelname == "ERROR" and "degraded mode after reload" in record.message
        for record in caplog.records
    )


def test_refresh_if_needed_logs_recovery_when_a_provider_is_restored(
    dual_provider_cfg: AuthConfig,
    monkeypatch: pytest.MonkeyPatch,
    caplog: pytest.LogCaptureFixture,
) -> None:
    manager = _Manager(dual_provider_cfg)
    manager._config_error_message = "ldap missing"
    service = ProviderRuntimeService(manager)

    def _initialize(cfg: Any) -> tuple[object, None, list[str]]:
        del cfg
        return object(), None, []

    monkeypatch.setattr(service, "initialize_provider_clients", _initialize)
    monkeypatch.setattr(service, "configure_rate_limiters", lambda cfg: None)

    with caplog.at_level("INFO", logger="rbac_providers_auth_manager.auth_manager"):
        service.refresh_if_needed()

    assert manager._config_error_message is None
    assert any(
        record.levelname == "INFO" and "recovered from degraded mode" in record.message
        for record in caplog.records
    )
