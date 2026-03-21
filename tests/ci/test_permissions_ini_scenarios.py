from __future__ import annotations

from pathlib import Path

import pytest

from rbac_providers_auth_manager.config_runtime.mapping_parsers import (
    parse_role_mapping_raw,
)
from rbac_providers_auth_manager.config_runtime.parser import load_config
from rbac_providers_auth_manager.runtime.secret_references import SecurityConfigError

from .permissions_fixture_loader import (
    apply_env,
    case_metadata,
    fixture_cases,
    resolve_attr_path,
)


def _load_config_cases() -> list[Path]:
    return fixture_cases("load_config")


def _role_mapping_cases() -> list[Path]:
    return fixture_cases("role_mapping")


@pytest.mark.parametrize(
    "case_path",
    _load_config_cases(),
    ids=lambda path: Path(path).stem,
)
def test_permissions_ini_load_config_scenarios(
    case_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    metadata = case_metadata(case_path)
    apply_env(metadata, monkeypatch)

    if metadata["expect"] == "error":
        error_type = metadata.get("error_type", "SecurityConfigError")
        exc_type: type[Exception]
        if error_type == "SecurityConfigError":
            exc_type = SecurityConfigError
        else:
            raise AssertionError(f"Unsupported error_type: {error_type}")
        with pytest.raises(exc_type, match=str(metadata["error_match"])):
            load_config(case_path)
        return

    cfg = load_config(case_path)
    for dotted_path, expected in metadata.get("assertions", {}).items():
        actual = resolve_attr_path(cfg, str(dotted_path))
        if dotted_path == "jwt_cookie.cookie_samesite":
            assert str(actual).lower() == str(expected)
        elif isinstance(actual, tuple) and isinstance(expected, list):
            assert list(actual) == expected
        else:
            assert actual == expected


@pytest.mark.parametrize(
    "case_path",
    _role_mapping_cases(),
    ids=lambda path: Path(path).stem,
)
def test_permissions_ini_role_mapping_scenarios(case_path: Path) -> None:
    metadata = case_metadata(case_path)
    mapping = parse_role_mapping_raw(case_path)

    assert metadata["expect"] == "success"
    expected_assertions = metadata.get("assertions", {})
    for dn, expected_roles in expected_assertions.items():
        assert mapping.dn_to_roles[str(dn)] == set(expected_roles)
