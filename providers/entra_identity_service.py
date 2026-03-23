"""OIDC code exchange, token validation, and identity normalization for Entra."""

from __future__ import annotations

import importlib
import json
from dataclasses import dataclass
from functools import lru_cache
from typing import Any
from urllib.parse import urlencode

from rbac_providers_auth_manager.config import EntraIdConfig
from rbac_providers_auth_manager.core.exceptions import (
    EntraIdAuthError,
    OptionalProviderDependencyError,
)
from rbac_providers_auth_manager.core.util import dedupe_preserve_order
from rbac_providers_auth_manager.runtime.security import generate_pkce_code_challenge
from rbac_providers_auth_manager.providers.entra_http_service import EntraHttpService


@lru_cache(maxsize=1)
def load_jwt_modules() -> tuple[Any, Any]:
    """Return the lazily imported JWT modules used by Entra flows."""
    try:
        jwt_module = importlib.import_module("jwt")
        algorithms_module = importlib.import_module("jwt.algorithms")
    except (
        ModuleNotFoundError
    ) as exc:  # pragma: no cover - depends on deployment extras
        raise OptionalProviderDependencyError(
            "Entra authentication requires the optional PyJWT dependency to be installed."
        ) from exc
    return jwt_module, algorithms_module


def jwt_module() -> Any:
    """Return the lazily imported top-level ``jwt`` module."""
    return load_jwt_modules()[0]


def jwt_algorithms() -> Any:
    """Return the lazily imported ``jwt.algorithms`` module."""
    return load_jwt_modules()[1]


@dataclass(frozen=True, slots=True)
class EntraIdIdentity:
    """Normalized identity information extracted from Azure tokens."""

    user_id: str
    username: str
    first_name: str | None
    last_name: str | None
    email: str | None
    display_name: str | None
    claim_values: tuple[str, ...]
    claims: dict[str, Any]


class EntraIdentityService:
    """Own browser redirect, code exchange, token validation, and claim extraction."""

    def __init__(self, cfg: EntraIdConfig, http_service: EntraHttpService) -> None:
        self.cfg = cfg
        self._http = http_service

    def reconfigure(self, cfg: EntraIdConfig) -> None:
        """Replace configuration while reusing the HTTP/discovery helper."""
        self.cfg = cfg

    def build_authorize_redirect_url(
        self,
        *,
        redirect_uri: str,
        state: str,
        nonce: str,
        code_verifier: str | None = None,
    ) -> str:
        """Build the Azure authorization endpoint URL for browser redirect."""
        authorize_url = self.cfg.authorize_url
        if not authorize_url:
            metadata = self._http.metadata()
            authorize_url = str(metadata.get("authorization_endpoint") or "")

        if not authorize_url:
            raise EntraIdAuthError("Azure authorization endpoint is not available")

        params = {
            "client_id": self.cfg.client_id,
            "response_type": "code",
            "redirect_uri": redirect_uri,
            "response_mode": "query",
            "scope": " ".join(self.cfg.scope),
            "state": state,
            "nonce": nonce,
        }

        if self.cfg.enable_pkce:
            if not code_verifier:
                raise EntraIdAuthError(
                    "PKCE is enabled but no code_verifier was provided"
                )
            params["code_challenge"] = generate_pkce_code_challenge(code_verifier)
            params["code_challenge_method"] = "S256"

        return f"{authorize_url}?{urlencode(params)}"

    def authenticate_authorization_code(
        self,
        *,
        code: str,
        redirect_uri: str,
        expected_nonce: str | None,
        code_verifier: str | None = None,
    ) -> EntraIdIdentity:
        """Exchange an authorization code and return normalized identity data."""
        token_payload = self._exchange_code(
            code=code,
            redirect_uri=redirect_uri,
            code_verifier=code_verifier,
        )
        claims = self._decode_id_token(
            id_token=str(token_payload.get("id_token") or ""),
            expected_nonce=expected_nonce,
        )
        access_token = str(token_payload.get("access_token") or "")
        claim_values = self._extract_claim_values(
            claims=claims,
            access_token=access_token,
        )

        user_id = str(claims.get("oid") or claims.get("sub") or "")
        if not user_id:
            raise EntraIdAuthError("Azure token did not include a stable subject")

        username = str(
            claims.get(self.cfg.username_claim)
            or claims.get("preferred_username")
            or claims.get("upn")
            or claims.get("email")
            or user_id
        )

        email_raw = (
            claims.get(self.cfg.email_claim)
            or claims.get("email")
            or claims.get("preferred_username")
        )
        email = str(email_raw) if email_raw else None

        first_name = str(claims.get(self.cfg.first_name_claim) or "").strip() or None
        last_name = str(claims.get(self.cfg.last_name_claim) or "").strip() or None
        display_name = (
            str(claims.get(self.cfg.display_name_claim) or "").strip() or None
        )

        if display_name and (not first_name or not last_name):
            display_parts = display_name.split()
            if len(display_parts) >= 2:
                first_name = first_name or display_parts[0]
                last_name = last_name or " ".join(display_parts[1:])

        return EntraIdIdentity(
            user_id=user_id,
            username=username,
            first_name=first_name,
            last_name=last_name,
            email=email,
            display_name=display_name,
            claim_values=tuple(claim_values),
            claims=claims,
        )

    def _exchange_code(
        self,
        *,
        code: str,
        redirect_uri: str,
        code_verifier: str | None = None,
    ) -> dict[str, Any]:
        """Exchange an authorization code for tokens."""
        access_token_url = self.cfg.access_token_url
        if not access_token_url:
            metadata = self._http.metadata()
            access_token_url = str(metadata.get("token_endpoint") or "")

        if not access_token_url:
            raise EntraIdAuthError("Azure token endpoint is not available")

        form_data = {
            "grant_type": "authorization_code",
            "client_id": self.cfg.client_id,
            "client_secret": self.cfg.client_secret,
            "code": code,
            "redirect_uri": redirect_uri,
        }

        if self.cfg.enable_pkce:
            if not code_verifier:
                raise EntraIdAuthError(
                    "PKCE is enabled but no code_verifier was provided"
                )
            form_data["code_verifier"] = code_verifier

        payload = self._http.request_json(
            "POST",
            access_token_url,
            data=form_data,
            headers={"Content-Type": "application/x-www-form-urlencoded"},
        )
        if not payload.get("id_token"):
            raise EntraIdAuthError("Azure token response did not include an id_token")
        return payload

    def _decode_id_token(
        self,
        *,
        id_token: str,
        expected_nonce: str | None,
    ) -> dict[str, Any]:
        """Validate and decode the Azure ID token."""
        if not id_token:
            raise EntraIdAuthError("Missing Azure id_token")

        issuer = self.cfg.issuer
        if not issuer:
            metadata = self._http.metadata()
            issuer = str(metadata.get("issuer") or "")
        if not issuer:
            raise EntraIdAuthError("Azure issuer is not available")

        jwt = jwt_module()
        algorithms_module = jwt_algorithms()
        header = jwt.get_unverified_header(id_token)
        algorithm = str(header.get("alg") or "RS256")

        verification_key: Any | None = None
        if self.cfg.verify_signature:
            kid = str(header.get("kid") or "")
            jwks = self._http.jwks()
            for jwk in jwks.get("keys", []):
                if isinstance(jwk, dict) and str(jwk.get("kid") or "") == kid:
                    verification_key = algorithms_module.RSAAlgorithm.from_jwk(
                        json.dumps(jwk)
                    )
                    break
            if verification_key is None:
                raise EntraIdAuthError("Could not find a matching Azure signing key")

        try:
            claims = jwt.decode(
                id_token,
                key=verification_key,
                algorithms=[algorithm],
                audience=list(self.cfg.allowed_audiences),
                issuer=issuer,
                options={
                    "verify_signature": self.cfg.verify_signature,
                    "verify_aud": True,
                    "verify_iss": True,
                    "verify_exp": True,
                    "verify_nbf": True,
                },
                leeway=self.cfg.clock_skew_seconds,
            )
        except jwt_module().PyJWTError as exc:
            raise EntraIdAuthError(f"Azure id_token validation failed: {exc}") from exc

        if expected_nonce:
            token_nonce = str(claims.get("nonce") or "")
            if not token_nonce or token_nonce != expected_nonce:
                raise EntraIdAuthError("Azure nonce validation failed")

        return claims

    def _extract_claim_values(
        self, *, claims: dict[str, Any], access_token: str
    ) -> list[str]:
        """Extract authorization claim values used for Airflow role mapping."""
        claim_key = (self.cfg.roles_claim_key or "groups").strip()
        raw_value = claims.get(claim_key)

        if isinstance(raw_value, str) and raw_value.strip():
            return [raw_value.strip()]

        if isinstance(raw_value, list):
            values = [str(item).strip() for item in raw_value if str(item).strip()]
            return dedupe_preserve_order(values)

        overage = claims.get("_claim_names") or {}
        if (
            self.cfg.graph_fetch_groups_on_overage
            and isinstance(overage, dict)
            and claim_key in overage
        ):
            return self._fetch_claim_values_from_graph(access_token=access_token)

        if isinstance(overage, dict) and claim_key in overage:
            raise EntraIdAuthError("Azure group/role claim overage detected")

        return []

    def _fetch_claim_values_from_graph(self, *, access_token: str) -> list[str]:
        """Fetch transitive group membership from Microsoft Graph on overage."""
        if not access_token:
            raise EntraIdAuthError(
                "Azure access_token is required for Graph group fallback"
            )

        payload = self._http.request_json(
            "GET",
            self.cfg.graph_memberof_url,
            allow_retry=True,
            headers={"Authorization": f"Bearer {access_token}"},
        )

        values: list[str] = []
        for item in payload.get("value", []):
            if not isinstance(item, dict):
                continue

            group_id = str(item.get("id") or "").strip()
            display_name = str(item.get("displayName") or "").strip()

            if group_id:
                values.append(group_id)
            if display_name:
                values.append(display_name)

        return dedupe_preserve_order(values)
