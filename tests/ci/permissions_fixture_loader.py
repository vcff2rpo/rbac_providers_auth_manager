from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest

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
