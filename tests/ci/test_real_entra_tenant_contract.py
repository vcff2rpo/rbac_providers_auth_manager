from __future__ import annotations

import os

import pytest

from rbac_providers_auth_manager.config_runtime.models import EntraIdConfig
from rbac_providers_auth_manager.providers.entra_http_service import EntraHttpService
from rbac_providers_auth_manager.providers.entra_identity_service import EntraIdentityService


def _require_or_skip(name: str) -> str:
    value = os.environ.get(name, "").strip()
    if value:
        return value
    if os.environ.get("REQUIRE_EXTERNAL_SECRETS", "false").lower() == "true":
        pytest.fail(f"Missing required external validation variable: {name}")
    pytest.skip(f"External Entra validation is not configured: missing {name}")


@pytest.mark.external_real
@pytest.mark.slow
def test_real_entra_tenant_authorization_code_callback() -> None:
    tenant_id = _require_or_skip("REAL_ENTRA_TENANT_ID")
    client_id = _require_or_skip("REAL_ENTRA_CLIENT_ID")
    client_secret = _require_or_skip("REAL_ENTRA_CLIENT_SECRET")
    auth_code = _require_or_skip("REAL_ENTRA_AUTH_CODE")
    redirect_uri = _require_or_skip("REAL_ENTRA_REDIRECT_URI")
    expected_nonce = _require_or_skip("REAL_ENTRA_EXPECTED_NONCE")
    code_verifier = os.environ.get("REAL_ENTRA_CODE_VERIFIER") or None

    cfg = EntraIdConfig(
        enabled=True,
        tenant_id=tenant_id,
        client_id=client_id,
        client_secret=client_secret,
        provider_name="entra",
        button_text="Microsoft Sign-In",
        icon="microsoft",
        scope=("openid", "profile", "email"),
        roles_claim_key="groups",
        verify_signature=True,
        allowed_audiences=(client_id,),
        http_timeout_seconds=int(os.environ.get("REAL_ENTRA_HTTP_TIMEOUT_SECONDS", "20")),
        http_max_retries=1,
        http_retry_backoff_seconds=1,
        metadata_url=f"https://login.microsoftonline.com/{tenant_id}/v2.0/.well-known/openid-configuration",
        authorize_url=None,
        access_token_url=f"https://login.microsoftonline.com/{tenant_id}/oauth2/v2.0/token",
        jwks_uri=f"https://login.microsoftonline.com/{tenant_id}/discovery/v2.0/keys",
        issuer=f"https://login.microsoftonline.com/{tenant_id}/v2.0",
        username_claim="preferred_username",
        email_claim="email",
        first_name_claim="given_name",
        last_name_claim="family_name",
        display_name_claim="name",
        graph_fetch_groups_on_overage=bool(os.environ.get("REAL_ENTRA_GRAPH_FETCH_GROUPS", "").strip()),
        graph_memberof_url="https://graph.microsoft.com/v1.0/me/transitiveMemberOf?$select=id,displayName",
        enable_pkce=bool(code_verifier),
        clock_skew_seconds=30,
        allowed_oidc_hosts=("login.microsoftonline.com", "graph.microsoft.com"),
    )

    service = EntraIdentityService(cfg, EntraHttpService(cfg))
    identity = service.authenticate_authorization_code(
        code=auth_code,
        redirect_uri=redirect_uri,
        expected_nonce=expected_nonce,
        code_verifier=code_verifier,
    )
    print("entra_identity_username=", identity.username)
    print("entra_identity_user_id=", identity.user_id)
    print("entra_identity_claim_values=", identity.claim_values)
    assert identity.user_id
    assert identity.username
