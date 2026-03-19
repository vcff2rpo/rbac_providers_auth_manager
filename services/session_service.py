"""Cookie and transient session-state helpers for authentication flows."""

from __future__ import annotations

import secrets
from collections.abc import Iterable
from typing import Literal, cast

from fastapi import Request, Response

from rbac_providers_auth_manager.compatibility.airflow_public_api import (
    AUTH_MANAGER_FASTAPI_APP_PREFIX,
    COOKIE_NAME_JWT_TOKEN,
)
from rbac_providers_auth_manager.runtime.auth_state_backends import (
    build_auth_state_store,
)
from rbac_providers_auth_manager.identity.models import OAuthFlowState


class SessionService:
    """Centralize auth cookie writes and temporary flow-state cookies."""

    LDAP_CSRF_COOKIE_NAME = "itim_ldap_csrf"
    ENTRA_FLOW_ID_COOKIE_NAME = "itim_entra_flow"
    ENTRA_TRANSIENT_COOKIE_NAMES = (
        "itim_entra_state",
        "itim_entra_nonce",
        "itim_entra_pkce",
        "itim_entra_next",
        ENTRA_FLOW_ID_COOKIE_NAME,
    )

    def __init__(self, *, config_loader, redirect_service, audit_service=None) -> None:
        self._config_loader = config_loader
        self._redirect_service = redirect_service
        self._audit_service = audit_service
        self._auth_state_store = None
        self._auth_state_store_signature: tuple[str, str | None, str] | None = None

    def generate_csrf_token(self) -> str:
        """Return a URL-safe CSRF token for the current browser flow."""
        return secrets.token_urlsafe(32)

    def resolve_cookie_secure(
        self,
        request: Request,
        *,
        trusted_proxies: tuple[str, ...],
    ) -> bool:
        """Return the effective ``secure`` value for auth-related cookies."""
        cfg = self._config_loader.get_config()
        secure_auto = self._redirect_service.is_secure_request(
            request,
            trusted_proxies=trusted_proxies,
        )
        secure = (
            secure_auto
            if cfg.jwt_cookie.cookie_secure is None
            else bool(cfg.jwt_cookie.cookie_secure)
        )
        if (cfg.jwt_cookie.cookie_samesite or "").lower() == "none":
            secure = True
        return secure

    def set_auth_cookie(
        self, response: Response, *, jwt_token: str, secure: bool
    ) -> None:
        """Write the Airflow auth token cookie using configured transport settings."""
        cfg = self._config_loader.get_config()
        response.set_cookie(
            key=COOKIE_NAME_JWT_TOKEN,
            value=jwt_token,
            secure=secure,
            httponly=bool(cfg.jwt_cookie.cookie_httponly),
            samesite=cfg.jwt_cookie.cookie_samesite,
            path=(cfg.jwt_cookie.cookie_path or "/"),
            domain=(cfg.jwt_cookie.cookie_domain or None),
        )

    def delete_auth_cookie(self, response: Response, *, secure: bool) -> None:
        """Delete the Airflow auth token cookie using configured transport settings."""
        cfg = self._config_loader.get_config()
        response.delete_cookie(
            key=COOKIE_NAME_JWT_TOKEN,
            secure=secure,
            httponly=bool(cfg.jwt_cookie.cookie_httponly),
            path=(cfg.jwt_cookie.cookie_path or "/"),
            domain=(cfg.jwt_cookie.cookie_domain or None),
        )

    def set_transient_cookie(
        self,
        response: Response,
        *,
        key: str,
        value: str,
        secure: bool,
        path: str = AUTH_MANAGER_FASTAPI_APP_PREFIX,
        httponly: bool = True,
    ) -> None:
        """Persist short-lived auth flow state such as CSRF or OAuth state."""
        cfg = self._config_loader.get_config()
        raw_samesite = (cfg.jwt_cookie.cookie_samesite or "Lax").strip().lower()
        if raw_samesite not in {"lax", "strict", "none"}:
            raw_samesite = "lax"
        samesite = cast(Literal["lax", "strict", "none"], raw_samesite)
        response.set_cookie(
            key=key,
            value=value,
            secure=secure,
            httponly=httponly,
            samesite=samesite,
            path=path,
            domain=(cfg.jwt_cookie.cookie_domain or None),
        )

    def delete_transient_cookie(
        self,
        response: Response,
        *,
        key: str,
        path: str = AUTH_MANAGER_FASTAPI_APP_PREFIX,
    ) -> None:
        """Delete a single short-lived auth flow cookie."""
        cfg = self._config_loader.get_config()
        response.delete_cookie(
            key=key,
            path=path,
            domain=(cfg.jwt_cookie.cookie_domain or None),
        )

    def clear_transient_cookies(
        self,
        response: Response,
        *,
        cookie_names: Iterable[str],
        path: str = AUTH_MANAGER_FASTAPI_APP_PREFIX,
    ) -> None:
        """Delete multiple short-lived auth flow cookies in one operation."""
        for cookie_name in cookie_names:
            self.delete_transient_cookie(response, key=cookie_name, path=path)

    def _auth_state_signature(self) -> tuple[str, str | None, str]:
        cfg = self._config_loader.get_config()
        return (
            (cfg.security.auth_state_backend or "cookie").strip().lower(),
            cfg.security.auth_state_redis_url,
            (cfg.security.auth_state_redis_prefix or "airflow_auth_state").strip(),
        )

    def _get_auth_state_store(self):
        """Return a cached transient auth-state store for the active config."""
        cfg = self._config_loader.get_config()
        signature = self._auth_state_signature()
        if self._auth_state_store_signature == signature:
            return self._auth_state_store
        try:
            self._auth_state_store = build_auth_state_store(
                backend_name=cfg.security.auth_state_backend,
                redis_url=cfg.security.auth_state_redis_url,
                redis_prefix=cfg.security.auth_state_redis_prefix,
            )
            self._auth_state_store_signature = signature
            return self._auth_state_store
        except Exception as exc:  # noqa: BLE001
            self._auth_state_store = None
            self._auth_state_store_signature = signature
            if self._audit_service is not None:
                self._audit_service.log_flow_event(
                    event="auth.state_store.fallback",
                    level="warning",
                    backend=cfg.security.auth_state_backend,
                    reason=str(exc) or "state_store_error",
                    fallback_backend="cookie",
                )
            return None

    def uses_shared_auth_state_store(self) -> bool:
        """Return whether the active auth-state backend uses server-side storage."""
        return self._get_auth_state_store() is not None

    def set_ldap_csrf_cookie(
        self, response: Response, *, token: str, secure: bool
    ) -> None:
        """Persist the short-lived LDAP CSRF token cookie."""
        self.set_transient_cookie(
            response,
            key=self.LDAP_CSRF_COOKIE_NAME,
            value=token,
            secure=secure,
        )

    def clear_ldap_csrf_cookie(self, response: Response) -> None:
        """Delete the short-lived LDAP CSRF token cookie."""
        self.delete_transient_cookie(response, key=self.LDAP_CSRF_COOKIE_NAME)

    def persist_entra_flow_state(
        self,
        response: Response,
        *,
        state: str,
        nonce: str,
        next_url: str,
        secure: bool,
        code_verifier: str | None = None,
    ) -> None:
        """Persist short-lived Entra browser-flow state using the configured backend."""
        cfg = self._config_loader.get_config()
        flow_state = OAuthFlowState(
            state=state,
            nonce=nonce,
            next_url=next_url,
            code_verifier=code_verifier,
        )
        state_store = self._get_auth_state_store()
        if state_store is None:
            self.set_transient_cookie(
                response, key="itim_entra_state", value=state, secure=secure
            )
            self.set_transient_cookie(
                response, key="itim_entra_nonce", value=nonce, secure=secure
            )
            self.set_transient_cookie(
                response, key="itim_entra_next", value=next_url, secure=secure
            )
            if code_verifier:
                self.set_transient_cookie(
                    response, key="itim_entra_pkce", value=code_verifier, secure=secure
                )
            return

        flow_id = secrets.token_urlsafe(24)
        state_store.put(
            key=flow_id,
            value=flow_state,
            ttl_seconds=cfg.security.auth_state_ttl_seconds,
        )
        self.set_transient_cookie(
            response,
            key=self.ENTRA_FLOW_ID_COOKIE_NAME,
            value=flow_id,
            secure=secure,
        )

    def load_entra_flow_state(self, request: Request) -> OAuthFlowState | None:
        """Load the short-lived Entra browser-flow state from the active backend."""
        state_store = self._get_auth_state_store()
        if state_store is None:
            expected_state = request.cookies.get("itim_entra_state") or ""
            if not expected_state:
                return None
            return OAuthFlowState(
                state=expected_state,
                nonce=request.cookies.get("itim_entra_nonce") or "",
                next_url=request.cookies.get("itim_entra_next") or "/",
                code_verifier=request.cookies.get("itim_entra_pkce") or None,
            )

        flow_id = request.cookies.get(self.ENTRA_FLOW_ID_COOKIE_NAME) or ""
        if not flow_id:
            return None
        return state_store.get(key=flow_id)

    def clear_entra_flow_state(
        self, response: Response, *, request: Request | None = None
    ) -> None:
        """Delete short-lived Entra browser-flow state from cookies and optional backend."""
        state_store = self._get_auth_state_store()
        if state_store is not None and request is not None:
            flow_id = request.cookies.get(self.ENTRA_FLOW_ID_COOKIE_NAME) or ""
            if flow_id:
                state_store.delete(key=flow_id)
        self.clear_transient_cookies(
            response, cookie_names=self.ENTRA_TRANSIENT_COOKIE_NAMES
        )

    def clear_login_flow_cookies(
        self, response: Response, *, request: Request | None = None
    ) -> None:
        """Delete all short-lived login-flow cookies owned by the plugin."""
        self.clear_ldap_csrf_cookie(response)
        self.clear_entra_flow_state(response, request=request)

    def delete_server_session_cookie(self, response: Response, *, secure: bool) -> None:
        """Delete the framework session cookie used by the browser flow."""
        response.delete_cookie(key="session", secure=secure, httponly=True)

    def clear_logout_cookies(
        self, response: Response, *, secure: bool, request: Request | None = None
    ) -> None:
        """Delete all browser cookies owned by the plugin during logout."""
        self.delete_server_session_cookie(response, secure=secure)
        self.delete_auth_cookie(response, secure=secure)
        self.clear_login_flow_cookies(response, request=request)
