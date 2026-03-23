"""Detached HMAC integrity verification helpers for runtime config files."""

from __future__ import annotations

import hashlib
import hmac
import os
from pathlib import Path

from rbac_providers_auth_manager.runtime.secret_references import SecurityConfigError


def _load_integrity_key_from_env() -> str | None:
    """Load the optional config-integrity HMAC key from environment or file."""
    inline_key = (os.environ.get("AIRFLOW_ITIM_LDAP_CONFIG_HMAC_KEY") or "").strip()
    if inline_key:
        return inline_key

    key_file = (os.environ.get("AIRFLOW_ITIM_LDAP_CONFIG_HMAC_KEY_FILE") or "").strip()
    if not key_file:
        return None

    try:
        return (
            Path(key_file).expanduser().resolve().read_text(encoding="utf-8").strip()
            or None
        )
    except OSError as exc:
        raise SecurityConfigError(f"Unable to read HMAC key file: {key_file}") from exc


def verify_hmac_integrity(file_path: Path) -> None:
    """Verify a detached HMAC signature for ``file_path`` when configured."""
    key = _load_integrity_key_from_env()
    if not key:
        return

    sig_file_override = (
        os.environ.get("AIRFLOW_ITIM_LDAP_CONFIG_HMAC_SIG_FILE") or ""
    ).strip()
    signature_path = (
        Path(sig_file_override).expanduser().resolve()
        if sig_file_override
        else file_path.with_suffix(file_path.suffix + ".sig")
    )

    try:
        signature_raw = signature_path.read_text(encoding="utf-8").strip()
    except OSError as exc:
        raise SecurityConfigError(
            f"Missing or unreadable config integrity signature file: {signature_path}"
        ) from exc

    signature = (
        signature_raw.split(":", 1)[1].strip()
        if signature_raw.lower().startswith("sha256:")
        else signature_raw
    )
    if not signature:
        raise SecurityConfigError(
            f"Config integrity signature file is empty: {signature_path}"
        )

    expected = hmac.new(
        key.encode("utf-8"),
        file_path.read_bytes(),
        hashlib.sha256,
    ).hexdigest()

    if not hmac.compare_digest(expected, signature):
        raise SecurityConfigError(
            f"Config integrity verification failed for {file_path}"
        )
