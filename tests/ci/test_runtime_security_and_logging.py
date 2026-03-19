from __future__ import annotations

import hashlib
import hmac
import logging
from pathlib import Path

import pytest

from rbac_providers_auth_manager.core import logging_utils
from rbac_providers_auth_manager.runtime.config_integrity import verify_hmac_integrity
from rbac_providers_auth_manager.runtime.secret_references import (
    SecurityConfigError,
    resolve_secret_reference,
)


def test_resolve_secret_reference_supports_env_file_and_literal(tmp_path: Path) -> None:
    secret_file = tmp_path / "secret.txt"
    secret_file.write_text("file-secret\n", encoding="utf-8")

    env_secret = resolve_secret_reference(
        "env:AUTH_SECRET",
        env={"AUTH_SECRET": " env-secret "},
    )
    file_secret = resolve_secret_reference(f"file:{secret_file}")
    literal_secret = resolve_secret_reference("literal:literal-secret")

    assert env_secret is not None and env_secret.value == "env-secret"
    assert file_secret is not None and file_secret.value == "file-secret"
    assert literal_secret is not None and literal_secret.value == "literal-secret"


def test_resolve_secret_reference_rejects_plaintext_by_default() -> None:
    with pytest.raises(SecurityConfigError, match="Plaintext secrets"):
        resolve_secret_reference("supersecret")


def test_verify_hmac_integrity_accepts_valid_signature(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    config_path = tmp_path / "permissions.ini"
    config_path.write_text("[general]\n", encoding="utf-8")

    key = "top-secret-key"
    signature = hmac.new(
        key.encode("utf-8"),
        config_path.read_bytes(),
        hashlib.sha256,
    ).hexdigest()
    sig_path = tmp_path / "permissions.ini.sig"
    sig_path.write_text(signature + "\n", encoding="utf-8")

    monkeypatch.setenv("AIRFLOW_ITIM_LDAP_CONFIG_HMAC_KEY", key)
    verify_hmac_integrity(config_path)


def test_verify_hmac_integrity_rejects_invalid_signature(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    config_path = tmp_path / "permissions.ini"
    config_path.write_text("[general]\n", encoding="utf-8")
    sig_path = tmp_path / "permissions.ini.sig"
    sig_path.write_text("bad-signature\n", encoding="utf-8")

    monkeypatch.setenv("AIRFLOW_ITIM_LDAP_CONFIG_HMAC_KEY", "top-secret-key")

    with pytest.raises(
        SecurityConfigError, match="Config integrity verification failed"
    ):
        verify_hmac_integrity(config_path)


def test_configure_logging_adds_and_removes_debug_fallback_handler() -> None:
    namespace_logger = logging.getLogger(logging_utils.LOGGER_NAMESPACE)
    root_logger = logging.getLogger()
    original_root_level = root_logger.level

    logging_utils._remove_fallback_handler(namespace_logger)
    root_logger.setLevel(logging.INFO)

    logging_utils.configure("DEBUG")
    assert logging_utils._FALLBACK_HANDLER is not None
    assert namespace_logger.level == logging.DEBUG

    logging_utils.configure("INFO")
    assert logging_utils._FALLBACK_HANDLER is None
    assert namespace_logger.level == logging.INFO

    root_logger.setLevel(original_root_level)
