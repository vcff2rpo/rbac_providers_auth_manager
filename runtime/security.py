"""Security-focused helper facade for the custom auth manager.

This facade preserves the historic import surface while canonical
implementations are split into smaller runtime modules.
"""

from __future__ import annotations

from rbac_providers_auth_manager.runtime.config_integrity import verify_hmac_integrity
from rbac_providers_auth_manager.runtime.fingerprints import (
    fingerprint_text,
    fingerprint_values,
)
from rbac_providers_auth_manager.runtime.pkce import (
    generate_pkce_code_challenge,
    generate_pkce_code_verifier,
)
from rbac_providers_auth_manager.runtime.rate_limiter import (
    RateLimitDecision,
    SlidingWindowRateLimiter,
)
from rbac_providers_auth_manager.runtime.secret_references import (
    SecretReferenceResolution,
    SecurityConfigError,
    resolve_secret_reference,
)
from rbac_providers_auth_manager.runtime.url_security import is_https_url

__all__ = (
    "RateLimitDecision",
    "SecretReferenceResolution",
    "SecurityConfigError",
    "SlidingWindowRateLimiter",
    "fingerprint_text",
    "fingerprint_values",
    "generate_pkce_code_challenge",
    "generate_pkce_code_verifier",
    "is_https_url",
    "resolve_secret_reference",
    "verify_hmac_integrity",
)
