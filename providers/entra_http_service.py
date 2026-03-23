"""HTTP, OIDC metadata, and JWKS helpers for Entra authentication."""

from __future__ import annotations

import importlib
import logging
import time
from functools import lru_cache
from http import HTTPStatus
from typing import Any

from rbac_providers_auth_manager.config import EntraIdConfig
from rbac_providers_auth_manager.core.exceptions import (
    EntraIdAuthError,
    OptionalProviderDependencyError,
)
from rbac_providers_auth_manager.runtime.security import is_https_url

log = logging.getLogger(__name__)


@lru_cache(maxsize=1)
def load_requests_module() -> Any:
    """Return the lazily imported ``requests`` module used by Entra flows."""
    try:
        return importlib.import_module("requests")
    except (
        ModuleNotFoundError
    ) as exc:  # pragma: no cover - depends on deployment extras
        raise OptionalProviderDependencyError(
            "Entra authentication requires the optional requests dependency to be installed."
        ) from exc


class EntraHttpService:
    """Own outbound HTTP, metadata discovery, and JWKS caching for Entra."""

    def __init__(self, cfg: EntraIdConfig) -> None:
        self.cfg = cfg
        self._http: Any | None = None
        self._metadata_cache: dict[str, Any] | None = None
        self._metadata_cache_until: float = 0.0
        self._jwks_cache: dict[str, Any] | None = None
        self._jwks_cache_until: float = 0.0

    def reconfigure(self, cfg: EntraIdConfig) -> None:
        """Replace configuration and clear in-memory discovery caches."""
        self.cfg = cfg
        self._metadata_cache = None
        self._metadata_cache_until = 0.0
        self._jwks_cache = None
        self._jwks_cache_until = 0.0

    def _validate_outbound_url(self, url: str) -> None:
        """Reject unexpected outbound URLs before any HTTP request is sent."""
        if not is_https_url(url, allowed_hosts=self.cfg.allowed_oidc_hosts):
            raise EntraIdAuthError(
                f"Outbound URL is not allowed by the OIDC host allow-list: {url}"
            )

    def _http_session(self) -> Any:
        """Return the lazily created shared HTTP session for Entra requests."""
        if self._http is None:
            self._http = load_requests_module().Session()
        return self._http

    def _classify_http_error(
        self, *, url: str, response: Any | None, exc: Exception
    ) -> str:
        """Return a user-safe classified error message for HTTP failures."""
        if response is None:
            return f"Azure request failed: {exc}"

        status_code = int(response.status_code or 0)
        if status_code == HTTPStatus.BAD_REQUEST:
            if ".well-known/openid-configuration" in url:
                return (
                    "Azure OIDC metadata discovery failed. "
                    "Check tenant_id/metadata_url and verify the Entra tenant is valid."
                )
            return "Azure request was rejected as invalid. Check Entra configuration values."

        if status_code in {HTTPStatus.UNAUTHORIZED, HTTPStatus.FORBIDDEN}:
            return (
                "Azure request was not authorized. Check client_id, client_secret, "
                "app registration permissions, and tenant configuration."
            )

        if status_code == HTTPStatus.NOT_FOUND:
            return "Azure endpoint was not found. Check Entra endpoint and tenant configuration."

        if status_code == HTTPStatus.TOO_MANY_REQUESTS:
            return "Azure request was throttled. Retry later."

        if 500 <= status_code <= 599:
            return "Azure service is temporarily unavailable. Retry later."

        return f"Azure request failed with HTTP {status_code}: {exc}"

    def request_json(
        self,
        method: str,
        url: str,
        *,
        allow_retry: bool = False,
        **kwargs: Any,
    ) -> dict[str, Any]:
        """Perform an outbound JSON request with host allow-list enforcement."""
        self._validate_outbound_url(url)

        timeout = kwargs.pop("timeout", self.cfg.http_timeout_seconds)
        attempts = 1 + max(0, int(self.cfg.http_max_retries)) if allow_retry else 1
        backoff_seconds = max(0, int(self.cfg.http_retry_backoff_seconds))
        requests_module = load_requests_module()
        response: Any | None = None

        for attempt in range(1, attempts + 1):
            response = None
            try:
                response = self._http_session().request(
                    method, url, timeout=timeout, **kwargs
                )
                response.raise_for_status()
                try:
                    payload = response.json()
                except ValueError as exc:
                    raise EntraIdAuthError("Azure response was not valid JSON") from exc

                if not isinstance(payload, dict):
                    raise EntraIdAuthError(
                        "Azure response payload had an unexpected structure"
                    )
                return payload
            except requests_module.RequestException as exc:
                status_code = (
                    int(response.status_code or 0) if response is not None else 0
                )
                retriable = (
                    allow_retry
                    and attempt < attempts
                    and status_code in {429, 500, 502, 503, 504}
                )
                if retriable:
                    sleep_seconds = max(1, backoff_seconds) * attempt
                    log.warning(
                        "Azure request retrying method=%s url=%s attempt=%s/%s status=%s backoff=%ss",
                        method,
                        url,
                        attempt,
                        attempts,
                        status_code,
                        sleep_seconds,
                    )
                    time.sleep(sleep_seconds)
                    continue
                raise EntraIdAuthError(
                    self._classify_http_error(url=url, response=response, exc=exc)
                ) from exc

        raise EntraIdAuthError("Azure request failed after retries")

    def metadata(self) -> dict[str, Any]:
        """Return OIDC metadata, using a short in-process cache."""
        if (
            self._metadata_cache is not None
            and time.time() < self._metadata_cache_until
        ):
            return self._metadata_cache

        if not self.cfg.metadata_url:
            raise EntraIdAuthError("Azure metadata_url is not configured")

        metadata = self.request_json("GET", self.cfg.metadata_url, allow_retry=True)
        self._metadata_cache = metadata
        self._metadata_cache_until = time.time() + 3600
        return metadata

    def jwks(self) -> dict[str, Any]:
        """Return JWKS keys, using a short in-process cache."""
        if self._jwks_cache is not None and time.time() < self._jwks_cache_until:
            return self._jwks_cache

        metadata = self.metadata()
        jwks_uri = self.cfg.jwks_uri or str(metadata.get("jwks_uri") or "")
        if not jwks_uri:
            raise EntraIdAuthError("Azure JWKS URI is not available")

        jwks = self.request_json("GET", jwks_uri, allow_retry=True)
        self._jwks_cache = jwks
        self._jwks_cache_until = time.time() + 3600
        return jwks
