"""PKCE helper generation utilities."""

from __future__ import annotations

import base64
import hashlib
import os


def generate_pkce_code_verifier() -> str:
    """Generate a PKCE code verifier using URL-safe Base64 characters."""
    return base64.urlsafe_b64encode(os.urandom(48)).rstrip(b"=").decode("ascii")


def generate_pkce_code_challenge(verifier: str) -> str:
    """Generate an ``S256`` PKCE challenge from a verifier."""
    digest = hashlib.sha256(verifier.encode("ascii")).digest()
    return base64.urlsafe_b64encode(digest).rstrip(b"=").decode("ascii")
