from __future__ import annotations

from dataclasses import dataclass
from typing import Any

import pytest

from rbac_providers_auth_manager.runtime import rate_limiter as rate_limiter_module
from rbac_providers_auth_manager.runtime.rate_limiter import SlidingWindowRateLimiter
from rbac_providers_auth_manager.services.provider_runtime_service import (
    ProviderRuntimeService,
)


class _Clock:
    def __init__(self) -> None:
        self.now = 1000.0

    def time(self) -> float:
        return self.now

    def advance(self, seconds: float) -> None:
        self.now += seconds


@dataclass
class _Manager:
    _ldap_rate_limiter: SlidingWindowRateLimiter | None = None
    _oauth_rate_limiter: SlidingWindowRateLimiter | None = None

    @staticmethod
    def _client_ip(request: Any | None) -> str:
        del request
        return "127.0.0.1"

    @staticmethod
    def _limit_key(*parts: str) -> str:
        return "|".join(parts)


def test_rate_limit_boundary_matrix_rate_limited_then_recovers_after_window(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    clock = _Clock()
    monkeypatch.setattr(rate_limiter_module.time, "time", clock.time)

    limiter = SlidingWindowRateLimiter(
        max_events=2,
        window_seconds=10,
        lockout_seconds=0,
    )

    first = limiter.record_event(key="alice")
    second = limiter.record_event(key="alice")
    blocked = limiter.check(key="alice")

    print("rate_limit_boundary_before_recovery=", first, second, blocked)
    assert first.allowed is True
    assert second.allowed is False
    assert second.reason == "rate_limited"
    assert blocked.allowed is False
    assert blocked.retry_after_seconds >= 1

    clock.advance(11)
    recovered = limiter.check(key="alice")
    print("rate_limit_boundary_after_recovery=", recovered)
    assert recovered.allowed is True
    assert recovered.reason == "allowed"


def test_rate_limit_boundary_matrix_provider_runtime_service_clears_ldap_failures(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    clock = _Clock()
    monkeypatch.setattr(rate_limiter_module.time, "time", clock.time)

    manager = _Manager(
        _ldap_rate_limiter=SlidingWindowRateLimiter(
            max_events=2,
            window_seconds=30,
            lockout_seconds=10,
        )
    )
    service = ProviderRuntimeService(manager)

    assert service.check_ldap_rate_limit(username="alice", request=None) == (True, 0)
    assert service.record_ldap_failure(username="alice", request=None) == 0

    retry_after = service.record_ldap_failure(username="alice", request=None)
    print("ldap_retry_after_before_clear=", retry_after)
    assert retry_after == 10
    assert service.check_ldap_rate_limit(username="alice", request=None) == (False, 10)

    service.clear_ldap_failures(username="alice", request=None)
    assert service.check_ldap_rate_limit(username="alice", request=None) == (True, 0)


def test_rate_limit_boundary_matrix_oauth_start_is_scoped_by_client_ip(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    clock = _Clock()
    monkeypatch.setattr(rate_limiter_module.time, "time", clock.time)

    manager = _Manager(
        _oauth_rate_limiter=SlidingWindowRateLimiter(
            max_events=1,
            window_seconds=20,
            lockout_seconds=0,
        )
    )
    service = ProviderRuntimeService(manager)

    first_retry_after = service.record_oauth_start(request=None)
    allowed, retry_after = service.check_oauth_rate_limit(request=None)

    print("oauth_rate_limit_boundary=", first_retry_after, allowed, retry_after)
    assert first_retry_after == 20
    assert allowed is False
    assert retry_after >= 1
