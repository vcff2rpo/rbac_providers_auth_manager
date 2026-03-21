from __future__ import annotations

from dataclasses import replace
from http.cookies import SimpleCookie
import importlib

import pytest
from fastapi import Response
from starlette.requests import Request

_FAKE_AIRFLOW = importlib.import_module("tests.ci._fake_airflow")

RedirectService = importlib.import_module(
    "rbac_providers_auth_manager.services.redirect_service"
).RedirectService
RuntimeContextService = importlib.import_module(
    "rbac_providers_auth_manager.services.runtime_context_service"
).RuntimeContextService
SessionService = importlib.import_module(
    "rbac_providers_auth_manager.services.session_service"
).SessionService
browser_matrix = importlib.import_module("tests.ci.test_browser_token_flow_matrix")


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


class _Manager:
    def __init__(self, cfg) -> None:
        self._cfg_loader = _CfgLoader(cfg)
        self._config_error_message = ""
        self._session_service = SessionService(
            config_loader=self._cfg_loader,
            redirect_service=RedirectService(),
        )
        self._redirect_service = RedirectService()

    @staticmethod
    def _ui_environment_label() -> str:
        return "Airflow | CeleryExecutor"


def _request(
    *,
    scheme: str = "https",
    host: str = "airflow.example.test",
    path: str = "/login",
    query_string: str = "",
    headers: dict[str, str] | None = None,
    client_ip: str = "127.0.0.1",
    cookies: dict[str, str] | None = None,
) -> Request:
    raw_headers: list[tuple[bytes, bytes]] = []
    for key, value in (headers or {}).items():
        raw_headers.append((key.lower().encode("utf-8"), value.encode("utf-8")))
    if cookies:
        cookie_header = "; ".join(f"{key}={value}" for key, value in cookies.items())
        raw_headers.append((b"cookie", cookie_header.encode("utf-8")))
    return Request(
        {
            "type": "http",
            "method": "GET",
            "scheme": scheme,
            "path": path,
            "query_string": query_string.encode("utf-8"),
            "headers": raw_headers,
            "client": (client_ip, 54321),
            "server": (host, 443 if scheme == "https" else 80),
        }
    )


def _request_with_cookies(*, cookies: dict[str, str]) -> Request:
    return _request(cookies=cookies)


def _cookie_value(response: Response, key: str) -> str:
    cookies = SimpleCookie()
    for header in response.headers.getlist("set-cookie"):
        cookies.load(header)
    return str(cookies[key].value)


@pytest.fixture()
def auth_cfg():
    factory = getattr(browser_matrix.auth_cfg, "__wrapped__", browser_matrix.auth_cfg)
    return factory()


def _cookie_attrs(response: Response, key: str) -> dict[str, str]:
    cookies = SimpleCookie()
    for header in response.headers.getlist("set-cookie"):
        cookies.load(header)
    morsel = cookies[key]
    return {name: str(value) for name, value in morsel.items() if value}


@pytest.mark.unit
def test_redirect_service_sanitizes_same_origin_and_blocks_external_urls() -> None:
    request = _request(scheme="https", host="airflow.example.test", path="/login")

    assert (
        RedirectService.sanitize_next(
            "/graph?dag_id=demo",
            request,
            trusted_proxies=(),
        )
        == "/graph?dag_id=demo"
    )
    assert (
        RedirectService.sanitize_next(
            "https://evil.example.net/phish",
            request,
            trusted_proxies=(),
        )
        == "/"
    )
    assert (
        RedirectService.sanitize_next(
            "//evil.example.net/phish",
            request,
            trusted_proxies=(),
        )
        == "/"
    )


@pytest.mark.unit
def test_redirect_service_respects_trusted_forwarded_headers() -> None:
    request = _request(
        scheme="http",
        host="internal.local",
        client_ip="10.10.10.5",
        headers={
            "x-forwarded-proto": "https",
            "x-forwarded-host": "airflow.public.example",
        },
    )

    assert (
        RedirectService.effective_external_base(
            request,
            trusted_proxies=("10.10.10.0/24",),
        )
        == "https://airflow.public.example"
    )
    assert (
        RedirectService.is_secure_request(
            request,
            trusted_proxies=("10.10.10.0/24",),
        )
        is True
    )


@pytest.mark.unit
def test_session_service_forces_secure_cookie_when_samesite_none(auth_cfg) -> None:
    cfg = replace(
        auth_cfg,
        jwt_cookie=replace(
            auth_cfg.jwt_cookie,
            cookie_samesite="none",
            cookie_secure=False,
        ),
    )
    service = SessionService(
        config_loader=_CfgLoader(cfg),
        redirect_service=RedirectService(),
    )
    request = _request(scheme="http", host="airflow.example.test")

    assert service.resolve_cookie_secure(request, trusted_proxies=()) is True


@pytest.mark.unit
def test_runtime_context_resolves_redirect_target_and_config_errors(auth_cfg) -> None:
    manager = _Manager(auth_cfg)
    manager._config_error_message = "line1 | line2"
    service = RuntimeContextService(manager)
    request = _request(scheme="https", host="airflow.example.test")

    assert service.auth_config_broken() is True
    assert service.config_error_lines() == ["line1", "line2"]
    assert (
        service.resolve_post_login_redirect_target(
            request=request,
            next_url="https://evil.example/phish",
            trusted_proxies=(),
        )
        == "/"
    )


@pytest.mark.unit
def test_session_service_persists_and_loads_memory_backed_flow_state(
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
    assert loaded == browser_matrix.OAuthFlowState(
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


@pytest.mark.unit
def test_session_service_clears_logout_cookies(auth_cfg) -> None:
    service = SessionService(
        config_loader=_CfgLoader(auth_cfg),
        redirect_service=RedirectService(),
    )
    response = Response()
    request = _request(
        cookies={SessionService.ENTRA_FLOW_ID_COOKIE_NAME: "flow-1"},
    )

    service.clear_logout_cookies(response, secure=True, request=request)
    headers = response.headers.getlist("set-cookie")

    assert any("session=" in header for header in headers)
    assert any("_token=" in header for header in headers)
    assert any(
        f"{SessionService.LDAP_CSRF_COOKIE_NAME}=" in header for header in headers
    )


@pytest.mark.unit
def test_session_service_sets_auth_cookie_with_configured_transport(auth_cfg) -> None:
    cfg = replace(
        auth_cfg,
        jwt_cookie=replace(
            auth_cfg.jwt_cookie,
            cookie_domain="example.test",
            cookie_path="/",
        ),
    )
    service = SessionService(
        config_loader=_CfgLoader(cfg),
        redirect_service=RedirectService(),
    )
    response = Response()

    service.set_auth_cookie(response, jwt_token="jwt-123", secure=True)
    attrs = _cookie_attrs(response, "_token")

    assert attrs["domain"] == "example.test"
    assert attrs["path"] == "/"
    assert attrs["secure"] in {True, "True"}
