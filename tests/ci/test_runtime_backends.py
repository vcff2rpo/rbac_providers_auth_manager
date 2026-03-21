from __future__ import annotations

from dataclasses import replace
from http.cookies import SimpleCookie
import importlib
from typing import Any, cast

import pytest
from fastapi import Response
from starlette.requests import Request

from ._fake_airflow import install_fake_airflow

install_fake_airflow()

OAuthFlowState = importlib.import_module(
    "rbac_providers_auth_manager.identity.models"
).OAuthFlowState
_auth_state_backends = importlib.import_module(
    "rbac_providers_auth_manager.runtime.auth_state_backends"
)
MemoryAuthStateStore = _auth_state_backends.MemoryAuthStateStore
build_auth_state_store = _auth_state_backends.build_auth_state_store
_rate_limit_backends = importlib.import_module(
    "rbac_providers_auth_manager.runtime.rate_limit_backends"
)
build_rate_limiter = _rate_limit_backends.build_rate_limiter
SlidingWindowRateLimiter = importlib.import_module(
    "rbac_providers_auth_manager.runtime.rate_limiter"
).SlidingWindowRateLimiter
SessionService = cast(
    Any,
    importlib.import_module(
        "rbac_providers_auth_manager.services.session_service"
    ).SessionService,
)
browser_matrix = importlib.import_module(
    ".test_browser_token_flow_matrix", package=__package__
)


class _Clock:
    def __init__(self, start: float = 1_000.0) -> None:
        self.value = start

    def time(self) -> float:
        return self.value

    def advance(self, seconds: float) -> None:
        self.value += seconds


class _CfgLoader:
    def __init__(self, cfg) -> None:
        self._cfg = cfg

    def get_config(self):
        return self._cfg


class _Audit:
    def __init__(self) -> None:
        self.events: list[dict[str, str]] = []

    def log_flow_event(self, **payload: str) -> None:
        self.events.append(payload)


class _RedirectService:
    @staticmethod
    def is_secure_request(
        request: Request, *, trusted_proxies: tuple[str, ...]
    ) -> bool:
        del request, trusted_proxies
        return True


@pytest.fixture()
def auth_cfg():
    factory = getattr(browser_matrix.auth_cfg, "__wrapped__", browser_matrix.auth_cfg)
    return factory()


@pytest.fixture()
def session_service(auth_cfg) -> Any:
    return SessionService(
        config_loader=_CfgLoader(auth_cfg),
        redirect_service=_RedirectService(),
        audit_service=_Audit(),
    )


def _request_with_cookies(*, cookies: dict[str, str]) -> Request:
    cookie_header = "; ".join(f"{key}={value}" for key, value in cookies.items())
    return Request(
        {
            "type": "http",
            "method": "GET",
            "scheme": "https",
            "path": "/login",
            "headers": [(b"cookie", cookie_header.encode("utf-8"))],
            "client": ("127.0.0.1", 12345),
            "server": ("example.test", 443),
        }
    )


def _cookie_value(response: Response, key: str) -> str:
    cookies = SimpleCookie()
    for header in response.headers.getlist("set-cookie"):
        cookies.load(header)
    return str(cookies[key].value)


@pytest.mark.unit
def test_memory_auth_state_store_expires_items(monkeypatch: pytest.MonkeyPatch) -> None:
    clock = _Clock()
    monkeypatch.setattr(_auth_state_backends.time, "time", clock.time)

    store = MemoryAuthStateStore()
    state = OAuthFlowState(state="state-1", nonce="nonce-1", next_url="/next")
    store.put(key="flow-1", value=state, ttl_seconds=5)

    assert store.get(key="flow-1") == state
    clock.advance(6)
    assert store.get(key="flow-1") is None


@pytest.mark.unit
def test_build_auth_state_store_variants() -> None:
    assert (
        build_auth_state_store(
            backend_name="cookie", redis_url=None, redis_prefix="auth"
        )
        is None
    )
    assert isinstance(
        build_auth_state_store(
            backend_name="memory", redis_url=None, redis_prefix="auth"
        ),
        MemoryAuthStateStore,
    )
    with pytest.raises(ValueError, match="Unsupported auth-state backend"):
        build_auth_state_store(
            backend_name="unknown", redis_url=None, redis_prefix="auth"
        )


@pytest.mark.unit
def test_sliding_window_rate_limiter_lockout_and_reset(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    rate_limiter_module = importlib.import_module(
        "rbac_providers_auth_manager.runtime.rate_limiter"
    )

    clock = _Clock()
    monkeypatch.setattr(rate_limiter_module.time, "time", clock.time)

    limiter = SlidingWindowRateLimiter(
        max_events=2,
        window_seconds=30,
        lockout_seconds=10,
    )

    assert limiter.record_event(key="alice").allowed is True
    blocked = limiter.record_event(key="alice")
    assert blocked.allowed is False
    assert blocked.reason == "locked"
    assert limiter.check(key="alice").reason == "locked"

    limiter.reset(key="alice")
    assert limiter.check(key="alice").allowed is True


@pytest.mark.unit
def test_build_rate_limiter_memory_and_unknown_backend() -> None:
    limiter = build_rate_limiter(
        backend_name="memory",
        redis_url=None,
        redis_prefix="auth",
        scope="ldap",
        max_events=3,
        window_seconds=60,
        lockout_seconds=0,
    )
    assert isinstance(limiter, SlidingWindowRateLimiter)

    with pytest.raises(ValueError, match="Unsupported rate-limit backend"):
        build_rate_limiter(
            backend_name="unsupported",
            redis_url=None,
            redis_prefix="auth",
            scope="ldap",
            max_events=3,
            window_seconds=60,
            lockout_seconds=0,
        )


@pytest.mark.unit
def test_session_service_persists_and_loads_memory_backed_flow_state(
    session_service: Any,
    auth_cfg,
) -> None:
    cfg = replace(
        auth_cfg,
        security=replace(
            auth_cfg.security,
            auth_state_backend="memory",
            auth_state_ttl_seconds=300,
        ),
    )
    session_service = SessionService(
        config_loader=_CfgLoader(cfg),
        redirect_service=_RedirectService(),
        audit_service=_Audit(),
    )

    response = Response()
    session_service.persist_entra_flow_state(
        response,
        state="state-1",
        nonce="nonce-1",
        next_url="/target",
        secure=True,
        code_verifier="verifier-1",
    )

    flow_id = _cookie_value(response, SessionService.ENTRA_FLOW_ID_COOKIE_NAME)
    request = _request_with_cookies(
        cookies={SessionService.ENTRA_FLOW_ID_COOKIE_NAME: flow_id}
    )

    loaded = session_service.load_entra_flow_state(request)
    assert loaded == OAuthFlowState(
        state="state-1",
        nonce="nonce-1",
        next_url="/target",
        code_verifier="verifier-1",
    )


@pytest.mark.unit
def test_session_service_falls_back_to_cookie_backend_on_store_error(
    monkeypatch: pytest.MonkeyPatch,
    auth_cfg,
) -> None:
    cfg = replace(
        auth_cfg, security=replace(auth_cfg.security, auth_state_backend="redis")
    )
    audit = _Audit()
    service = SessionService(
        config_loader=_CfgLoader(cfg),
        redirect_service=_RedirectService(),
        audit_service=audit,
    )

    def _boom(**kwargs):
        del kwargs
        raise ValueError("redis unavailable")

    monkeypatch.setattr(
        "rbac_providers_auth_manager.services.session_service.build_auth_state_store",
        _boom,
    )

    response = Response()
    service.persist_entra_flow_state(
        response,
        state="cookie-state",
        nonce="cookie-nonce",
        next_url="/cookie-target",
        secure=True,
        code_verifier=None,
    )

    headers = response.headers.getlist("set-cookie")
    assert any("itim_entra_state=" in header for header in headers)
    assert any("itim_entra_nonce=" in header for header in headers)
    assert any("itim_entra_next=" in header for header in headers)
    assert audit.events
    assert audit.events[-1]["event"] == "auth.state_store.fallback"
