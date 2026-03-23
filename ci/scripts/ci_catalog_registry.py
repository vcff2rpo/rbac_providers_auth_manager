from __future__ import annotations

import importlib
import sys
from pathlib import Path
from types import ModuleType
from typing import Final

REPO_ROOT: Final[Path] = Path(__file__).resolve().parents[2]


def load_contract_manifest() -> ModuleType:
    if str(REPO_ROOT) not in sys.path:
        sys.path.insert(0, str(REPO_ROOT))
    return importlib.import_module("tests.ci.contract_manifest")


CONTRACT_MANIFEST: Final[ModuleType] = load_contract_manifest()
FAMILY_ORDER: Final[tuple[str, ...]] = CONTRACT_MANIFEST.coverage_family_names()
FAMILY_FILES: Final[dict[str, tuple[str, ...]]] = {
    family: CONTRACT_MANIFEST.coverage_family_files(family) for family in FAMILY_ORDER
}
FAMILY_SOURCE_AREAS: Final[dict[str, tuple[str, ...]]] = {
    family: tuple(
        str(item) for item in CONTRACT_MANIFEST.COVERAGE_FAMILIES[family]["cov_targets"]
    )
    for family in FAMILY_ORDER
}
QUALITY_FAMILY_FILES: Final[tuple[str, ...]] = tuple(
    sorted({path for files in FAMILY_FILES.values() for path in files})
)
QUALITY_AND_DEEP_SOURCE_AREAS: Final[tuple[str, ...]] = tuple(
    sorted({area for areas in FAMILY_SOURCE_AREAS.values() for area in areas})
)

QUALITY_FAMILY_TASK_DESCRIPTION: Final[str] = (
    "Runs the quality-lane pytest families grouped by plugin functionality area "
    "with per-family coverage thresholds and scenario-rich API, RBAC mapping, "
    "role-filter runtime, rate-limit, and audit checks."
)

DEEP_VALIDATION_TASK_DESCRIPTIONS: Final[dict[str, str]] = {
    "config-permissions-runtime": (
        "Validates configuration loading, permissions.ini variants, role-filter "
        "runtime enforcement, runtime defaults, and low-level helper behavior."
    ),
    "role-mapping-rbac-compatibility": (
        "Validates RBAC policy behavior, LDAP/Entra edge-case role mapping, "
        "cross-provider isolation, vocabulary drift protection, and static mirror contracts."
    ),
    "api-ui-browser-session-observability": (
        "Validates API routes, browser flows, UI status rendering, rate-limit responses, "
        "redirect safety, session helpers, and negative-path observability."
    ),
    "provider-backends-and-rate-limits": (
        "Validates LDAP and Entra simulations together with runtime auth-state, "
        "rate-limit backend, and callback flow behavior."
    ),
    "audit-logging-governance": (
        "Validates audit payloads, API/browser event logging, runtime security messages, "
        "and governance/version reporting."
    ),
    "bootstrap-imports": "Validates repository import smoke and bootstrap entrypoints.",
}


SUITE_METADATA_EXTRAS: Final[dict[str, tuple[str, ...]]] = {
    "quality": ("tests/ci", "ci/scripts"),
    "deep_validation": ("rbac_providers_auth_manager", "tests/ci", "ci/scripts"),
}


def suite_source_areas(suite: str) -> tuple[str, ...]:
    dynamic_areas = set(
        QUALITY_AND_DEEP_SOURCE_AREAS if suite in {"quality", "deep_validation"} else ()
    )
    dynamic_areas.update(SUITE_METADATA_EXTRAS.get(suite, ()))
    return tuple(sorted(dynamic_areas))
