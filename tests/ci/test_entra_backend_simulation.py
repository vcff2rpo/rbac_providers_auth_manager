from __future__ import annotations

from collections import deque
from typing import Any, cast
from urllib.parse import parse_qs, urlparse

import pytest

from rbac_providers_auth_manager.config_runtime.models import EntraIdConfig
from rbac_providers_auth_manager.core.exceptions import EntraIdAuthError
from rbac_providers_auth_manager.providers.entra_http_service import EntraHttpService
from rbac_providers_auth_manager.providers.entra_identity_service import (
    EntraIdentityService,
)


class _FakeRequestException(Exception):
    pass


class _FakeResponse:
    def __init__(self, *, status_code: int, payload: Any) -> None:
        self.status_code = status_code
        self._payload = payload

    def raise_for_status(self) -> None:
        if self.status_code >= 400:
            raise _FakeRequestException(f"HTTP {self.status_code}")

    def json(self) -> Any:
        return self._payload


class _FakeSession:
    def __init__(self, responses: list[_FakeResponse]) -> None:
        self.responses = deque(responses)
        self.calls: list[tuple[str, str, dict[str, Any]]] = []

    def request(
        self, method: str, url: str, timeout: int, **kwargs: Any
    ) -> _FakeResponse:
        self.calls.append((method, url, {"timeout": timeout, **kwargs}))
        return self.responses.popleft()


class _FakeRequestsModule:
    RequestException = _FakeRequestException

    def __init__(self, session: _FakeSession) -> None:
        self._session = session

    def Session(self) -> _FakeSession:
        return self._session


class _FakeJwtModule:
    class PyJWTError(Exception):
        pass

    @staticmethod
    def get_unverified_header(_token: str) -> dict[str, str]:
        return {"alg": "RS256", "kid": "kid-1"}

    @staticmethod
    def decode(
        _token: str,
        *,
        key: Any,
        algorithms: list[str],
        audience: list[str],
        issuer: str,
        options: dict[str, bool],
        leeway: int,
    ) -> dict[str, Any]:
        assert key == "rsa-public-key"
        assert algorithms == ["RS256"]
        assert audience == ["client-id"]
        assert issuer == "https://login.microsoftonline.com/tenant/v2.0"
        assert options["verify_signature"] is True
        assert leeway == 30
        return {
            "oid": "oid-123",
            "preferred_username": "alice@example.com",
            "name": "Alice Admin",
            "nonce": "nonce-123",
            "_claim_names": {"groups": "src1"},
        }


class _FakeJwtAlgorithms:
    class RSAAlgorithm:
        @staticmethod
        def from_jwk(_jwk_json: str) -> str:
            return "rsa-public-key"


class _FakeHttpService:
    def __init__(self) -> None:
        self.calls: list[tuple[str, str, dict[str, Any]]] = []

    def metadata(self) -> dict[str, str]:
        return {
            "authorization_endpoint": "https://login.microsoftonline.com/tenant/oauth2/v2.0/authorize",
            "token_endpoint": "https://login.microsoftonline.com/tenant/oauth2/v2.0/token",
            "issuer": "https://login.microsoftonline.com/tenant/v2.0",
            "jwks_uri": "https://login.microsoftonline.com/tenant/discovery/v2.0/keys",
        }

    def jwks(self) -> dict[str, list[dict[str, str]]]:
        return {"keys": [{"kid": "kid-1", "kty": "RSA", "n": "abc", "e": "AQAB"}]}

    def request_json(self, method: str, url: str, **kwargs: Any) -> dict[str, Any]:
        self.calls.append((method, url, kwargs))
        if method == "POST":
            return {
                "id_token": "encoded-id-token",
                "access_token": "graph-access-token",
            }
        if method == "GET":
            return {
                "value": [
                    {"id": "group-1", "displayName": "Airflow Users"},
                    {"id": "group-2", "displayName": "Airflow Admins"},
                    {"id": "group-1", "displayName": "Airflow Users"},
                ]
            }
        raise AssertionError(f"Unexpected request: {method} {url}")


@pytest.fixture()
def entra_cfg() -> EntraIdConfig:
    return EntraIdConfig(
        enabled=True,
        tenant_id="tenant",
        client_id="client-id",
        client_secret="client-secret",
        provider_name="entra",
        button_text="Microsoft Sign-In",
        icon="microsoft",
        scope=("openid", "profile", "email"),
        roles_claim_key="groups",
        verify_signature=True,
        allowed_audiences=("client-id",),
        http_timeout_seconds=5,
        http_max_retries=1,
        http_retry_backoff_seconds=1,
        metadata_url="https://login.microsoftonline.com/tenant/v2.0/.well-known/openid-configuration",
        authorize_url=None,
        access_token_url="https://login.microsoftonline.com/tenant/oauth2/v2.0/token",
        jwks_uri="https://login.microsoftonline.com/tenant/discovery/v2.0/keys",
        issuer="https://login.microsoftonline.com/tenant/v2.0",
        username_claim="preferred_username",
        email_claim="email",
        first_name_claim="given_name",
        last_name_claim="family_name",
        display_name_claim="name",
        graph_fetch_groups_on_overage=True,
        graph_memberof_url="https://graph.microsoft.com/v1.0/me/transitiveMemberOf?$select=id,displayName",
        enable_pkce=True,
        clock_skew_seconds=30,
        allowed_oidc_hosts=("login.microsoftonline.com", "graph.microsoft.com"),
    )


def test_entra_http_service_retries_then_caches_metadata_and_jwks(
    monkeypatch: pytest.MonkeyPatch,
    entra_cfg: EntraIdConfig,
    caplog: pytest.LogCaptureFixture,
) -> None:
    session = _FakeSession(
        [
            _FakeResponse(status_code=429, payload={"error": "throttled"}),
            _FakeResponse(
                status_code=200,
                payload={
                    "issuer": entra_cfg.issuer,
                    "jwks_uri": entra_cfg.jwks_uri,
                },
            ),
            _FakeResponse(status_code=200, payload={"keys": [{"kid": "kid-1"}]}),
        ]
    )
    fake_requests = _FakeRequestsModule(session)

    import rbac_providers_auth_manager.providers.entra_http_service as http_module

    monkeypatch.setattr(http_module, "load_requests_module", lambda: fake_requests)
    monkeypatch.setattr(http_module.time, "sleep", lambda _seconds: None)

    service = EntraHttpService(entra_cfg)

    with caplog.at_level("WARNING"):
        metadata_first = service.metadata()
        metadata_second = service.metadata()
        jwks = service.jwks()

    assert metadata_first == metadata_second
    assert metadata_first["issuer"] == entra_cfg.issuer
    assert jwks == {"keys": [{"kid": "kid-1"}]}
    assert len(session.calls) == 3
    assert "Azure request retrying" in caplog.text


def test_entra_authorize_url_and_token_exchange_with_graph_overage(
    monkeypatch: pytest.MonkeyPatch,
    entra_cfg: EntraIdConfig,
) -> None:
    import rbac_providers_auth_manager.providers.entra_identity_service as identity_module

    http_service = _FakeHttpService()
    service = EntraIdentityService(entra_cfg, cast(Any, http_service))

    monkeypatch.setattr(identity_module, "jwt_module", lambda: _FakeJwtModule)
    monkeypatch.setattr(identity_module, "jwt_algorithms", lambda: _FakeJwtAlgorithms)

    redirect_url = service.build_authorize_redirect_url(
        redirect_uri="https://airflow.example.com/auth/entra/callback",
        state="state-123",
        nonce="nonce-123",
        code_verifier="verifier-1234567890123456789012345678901234567890",
    )
    parsed = urlparse(redirect_url)
    query = parse_qs(parsed.query)

    assert parsed.scheme == "https"
    assert query["client_id"] == ["client-id"]
    assert query["state"] == ["state-123"]
    assert query["nonce"] == ["nonce-123"]
    assert query["code_challenge_method"] == ["S256"]
    assert query["scope"] == ["openid profile email"]

    identity = service.authenticate_authorization_code(
        code="auth-code-123",
        redirect_uri="https://airflow.example.com/auth/entra/callback",
        expected_nonce="nonce-123",
        code_verifier="verifier-1234567890123456789012345678901234567890",
    )

    assert identity.user_id == "oid-123"
    assert identity.username == "alice@example.com"
    assert identity.display_name == "Alice Admin"
    assert identity.first_name == "Alice"
    assert identity.last_name == "Admin"
    assert identity.claim_values == (
        "group-1",
        "Airflow Users",
        "group-2",
        "Airflow Admins",
    )
    assert http_service.calls[0][0] == "POST"
    assert http_service.calls[1][1] == entra_cfg.graph_memberof_url


def test_entra_nonce_validation_failure(
    monkeypatch: pytest.MonkeyPatch,
    entra_cfg: EntraIdConfig,
) -> None:
    import rbac_providers_auth_manager.providers.entra_identity_service as identity_module

    class _WrongNonceJwt(_FakeJwtModule):
        @staticmethod
        def decode(
            _token: str,
            *,
            key: Any,
            algorithms: list[str],
            audience: list[str],
            issuer: str,
            options: dict[str, bool],
            leeway: int,
        ) -> dict[str, Any]:
            claims = _FakeJwtModule.decode(
                _token,
                key=key,
                algorithms=algorithms,
                audience=audience,
                issuer=issuer,
                options=options,
                leeway=leeway,
            )
            claims["nonce"] = "unexpected"
            return claims

    http_service = _FakeHttpService()
    service = EntraIdentityService(entra_cfg, cast(Any, http_service))

    monkeypatch.setattr(identity_module, "jwt_module", lambda: _WrongNonceJwt)
    monkeypatch.setattr(identity_module, "jwt_algorithms", lambda: _FakeJwtAlgorithms)

    with pytest.raises(EntraIdAuthError, match="Azure nonce validation failed"):
        service.authenticate_authorization_code(
            code="auth-code-123",
            redirect_uri="https://airflow.example.com/auth/entra/callback",
            expected_nonce="nonce-123",
            code_verifier="verifier-1234567890123456789012345678901234567890",
        )


def test_entra_http_service_blocks_unapproved_host(
    entra_cfg: EntraIdConfig,
) -> None:
    service = EntraHttpService(entra_cfg)

    with pytest.raises(EntraIdAuthError, match="OIDC host allow-list"):
        service.request_json("GET", "https://evil.example.com/openid")
