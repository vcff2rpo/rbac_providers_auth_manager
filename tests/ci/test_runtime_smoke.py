from __future__ import annotations

from pathlib import Path

from rbac_providers_auth_manager import __version__
from rbac_providers_auth_manager.runtime.fingerprints import (
    fingerprint_text,
    fingerprint_values,
)
from rbac_providers_auth_manager.runtime.pkce import (
    generate_pkce_code_challenge,
    generate_pkce_code_verifier,
)
from rbac_providers_auth_manager.runtime.url_security import is_https_url


def test_package_version_present() -> None:
    assert __version__


def test_pkce_roundtrip_shape() -> None:
    verifier = generate_pkce_code_verifier()
    challenge = generate_pkce_code_challenge(verifier)
    assert len(verifier) >= 43
    assert len(challenge) >= 43
    assert verifier != challenge


def test_fingerprints_are_stable_for_same_input() -> None:
    assert fingerprint_text("abc") == fingerprint_text("abc")
    assert fingerprint_values(("a", "b")) == fingerprint_values(("a", "b"))


def test_https_url_validation() -> None:
    assert is_https_url("https://example.com/path") is True
    assert is_https_url("http://example.com") is False


def test_permissions_ini_exists() -> None:
    ini_path = (
        Path(__file__).resolve().parents[2] / "config_runtime" / "permissions.ini"
    )
    assert ini_path.exists()
