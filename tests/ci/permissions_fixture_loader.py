from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest

from rbac_providers_auth_manager.config import AuthConfig
from rbac_providers_auth_manager.config_runtime.parser import load_config

FIXTURE_ROOT = Path(__file__).resolve().parents[1] / "fixtures" / "permissions"


def case_metadata(case_path: Path) -> dict[str, Any]:
    """Return parsed JSON metadata for a permissions fixture case."""
    return json.loads(case_path.with_suffix(".json").read_text(encoding="utf-8"))


def resolve_attr_path(obj: object, dotted_path: str) -> object:
    """Resolve a dotted attribute or dictionary path from a loaded config object."""
    current = obj
    for part in dotted_path.split("."):
        if isinstance(current, dict):
            current = current[part]
        else:
            current = getattr(current, part)
    return current


def apply_env(metadata: dict[str, Any], monkeypatch: pytest.MonkeyPatch) -> None:
    """Apply environment-variable overrides declared by a fixture sidecar."""
    for key, value in metadata.get("env", {}).items():
        monkeypatch.setenv(str(key), str(value))
    for key in metadata.get("clear_env", []):
        monkeypatch.delenv(str(key), raising=False)


def fixture_cases(kind: str) -> list[Path]:
    """Return sorted .ini fixtures for the requested permissions scenario kind."""
    return sorted((FIXTURE_ROOT / kind).glob("*.ini"))


def fixture_path(kind: str, fixture_name: str) -> Path:
    """Return the full path for a named permissions fixture case."""
    return FIXTURE_ROOT / kind / fixture_name


def load_config_case(
    fixture_name: str,
    monkeypatch: pytest.MonkeyPatch,
    *,
    kind: str = "load_config",
) -> tuple[Path, dict[str, Any], AuthConfig]:
    """Load a named permissions fixture with its environment sidecar applied."""
    case_path = fixture_path(kind, fixture_name)
    metadata = case_metadata(case_path)
    apply_env(metadata, monkeypatch)
    return case_path, metadata, load_config(case_path)
