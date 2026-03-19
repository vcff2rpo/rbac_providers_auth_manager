from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest

from rbac_providers_auth_manager.config_runtime.mapping_parsers import (
    parse_role_mapping_raw,
)
from rbac_providers_auth_manager.config_runtime.parser import load_config
from rbac_providers_auth_manager.runtime.secret_references import SecurityConfigError

FIXTURE_ROOT = Path(__file__).resolve().parents[1] / "fixtures" / "permissions"


def _case_metadata(case_path: Path) -> dict[str, Any]:
    return json.loads(case_path.with_suffix('.json').read_text(encoding='utf-8'))


def _resolve_attr_path(obj: object, dotted_path: str) -> object:
    current = obj
    for part in dotted_path.split('.'):
        current = getattr(current, part)
    return current


def _apply_env(metadata: dict[str, Any], monkeypatch: pytest.MonkeyPatch) -> None:
    for key, value in metadata.get('env', {}).items():
        monkeypatch.setenv(str(key), str(value))
    for key in metadata.get('clear_env', []):
        monkeypatch.delenv(str(key), raising=False)


def _load_config_cases() -> list[Path]:
    return sorted((FIXTURE_ROOT / 'load_config').glob('*.ini'))


def _role_mapping_cases() -> list[Path]:
    return sorted((FIXTURE_ROOT / 'role_mapping').glob('*.ini'))


@pytest.mark.parametrize(
    'case_path',
    _load_config_cases(),
    ids=lambda path: Path(path).stem,
)
def test_permissions_ini_load_config_scenarios(
    case_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    metadata = _case_metadata(case_path)
    _apply_env(metadata, monkeypatch)

    if metadata['expect'] == 'error':
        error_type = metadata.get('error_type', 'SecurityConfigError')
        exc_type: type[Exception]
        if error_type == 'SecurityConfigError':
            exc_type = SecurityConfigError
        else:
            raise AssertionError(f'Unsupported error_type: {error_type}')
        with pytest.raises(exc_type, match=str(metadata['error_match'])):
            load_config(case_path)
        return

    cfg = load_config(case_path)
    for dotted_path, expected in metadata.get('assertions', {}).items():
        actual = _resolve_attr_path(cfg, str(dotted_path))
        if dotted_path == 'jwt_cookie.cookie_samesite':
            assert str(actual).lower() == str(expected)
        else:
            assert actual == expected


@pytest.mark.parametrize(
    'case_path',
    _role_mapping_cases(),
    ids=lambda path: Path(path).stem,
)
def test_permissions_ini_role_mapping_scenarios(case_path: Path) -> None:
    metadata = _case_metadata(case_path)
    mapping = parse_role_mapping_raw(case_path)

    assert metadata['expect'] == 'success'
    expected_assertions = metadata.get('assertions', {})
    for dn, expected_roles in expected_assertions.items():
        assert mapping.dn_to_roles[str(dn)] == set(expected_roles)
