"""Secret-reference resolution helpers for runtime configuration."""

from __future__ import annotations

import os
from collections.abc import Mapping
from dataclasses import dataclass
from pathlib import Path
from typing import Final

_SECRET_ENV_PREFIX: Final[str] = "env:"
_SECRET_FILE_PREFIX: Final[str] = "file:"
_SECRET_LITERAL_PREFIX: Final[str] = "literal:"
_SECRET_AIRFLOW_VAR_PREFIX: Final[str] = "airflow_var:"


class SecurityConfigError(ValueError):
    """Raised when a security-sensitive configuration value is invalid."""


@dataclass(frozen=True, slots=True)
class SecretReferenceResolution:
    """Resolved secret value and its origin."""

    value: str
    source: str


def _resolve_airflow_variable(variable_name: str) -> str:
    """Resolve a secret from an Airflow Variable."""
    try:
        from airflow.models.variable import Variable  # type: ignore
    except Exception as exc:  # pragma: no cover  # noqa: BLE001
        raise SecurityConfigError(
            "Secret reference airflow_var: requires Airflow Variable support to be available"
        ) from exc

    try:
        secret = Variable.get(variable_name, default_var=None)
    except Exception as exc:  # pragma: no cover  # noqa: BLE001
        raise SecurityConfigError(
            f"Unable to read Airflow Variable for secret reference: {variable_name}"
        ) from exc

    if secret is None or not str(secret).strip():
        raise SecurityConfigError(
            f"Secret Airflow Variable is not set or empty: {variable_name}"
        )

    return str(secret).strip()


def resolve_secret_reference(
    value: str | None,
    *,
    allow_plaintext: bool = False,
    env: Mapping[str, str] | None = None,
) -> SecretReferenceResolution | None:
    """Resolve a secret reference used in ``permissions.ini``."""
    raw = (value or "").strip()
    if not raw:
        return None

    environment = os.environ if env is None else env

    if raw.startswith(_SECRET_ENV_PREFIX):
        variable_name = raw[len(_SECRET_ENV_PREFIX) :].strip()
        if not variable_name:
            raise SecurityConfigError(
                "Secret reference env: must include an environment variable name"
            )

        secret = environment.get(variable_name)
        if secret is None or not str(secret).strip():
            raise SecurityConfigError(
                f"Secret environment variable is not set or empty: {variable_name}"
            )
        return SecretReferenceResolution(
            value=str(secret).strip(),
            source=f"env:{variable_name}",
        )

    if raw.startswith(_SECRET_FILE_PREFIX):
        file_name = raw[len(_SECRET_FILE_PREFIX) :].strip()
        if not file_name:
            raise SecurityConfigError("Secret reference file: must include a file path")

        secret_path = Path(file_name).expanduser().resolve()
        try:
            secret = secret_path.read_text(encoding="utf-8").strip()
        except OSError as exc:
            raise SecurityConfigError(
                f"Unable to read secret file: {secret_path}"
            ) from exc

        if not secret:
            raise SecurityConfigError(f"Secret file is empty: {secret_path}")

        return SecretReferenceResolution(
            value=secret,
            source=f"file:{secret_path}",
        )

    if raw.startswith(_SECRET_LITERAL_PREFIX):
        literal_value = raw[len(_SECRET_LITERAL_PREFIX) :]
        if not literal_value:
            raise SecurityConfigError("Secret reference literal: must include a value")
        return SecretReferenceResolution(value=literal_value, source="literal")

    if raw.startswith(_SECRET_AIRFLOW_VAR_PREFIX):
        variable_name = raw[len(_SECRET_AIRFLOW_VAR_PREFIX) :].strip()
        if not variable_name:
            raise SecurityConfigError(
                "Secret reference airflow_var: must include an Airflow Variable name"
            )
        secret = _resolve_airflow_variable(variable_name)
        return SecretReferenceResolution(
            value=secret,
            source=f"airflow_var:{variable_name}",
        )

    if allow_plaintext:
        return SecretReferenceResolution(value=raw, source="plaintext")

    raise SecurityConfigError(
        "Plaintext secrets in permissions.ini are disabled. "
        "Use env:VAR, file:/path, airflow_var:VARIABLE_NAME, or literal:... explicitly."
    )
