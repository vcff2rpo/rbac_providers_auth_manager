from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Final, TypedDict, cast

REPO_ROOT: Final[Path] = Path(__file__).resolve().parents[2]
TEST_ROOT: Final[Path] = REPO_ROOT / "tests" / "ci"


class CoverageFamily(TypedDict):
    threshold: int
    files: tuple[str, ...]


@dataclass(frozen=True)
class TestContract:
    path: str
    primary_tier: str
    suite: str
    extra_markers: tuple[str, ...] = ()
    capability_tags: tuple[str, ...] = ()


CONTRACTS: Final[tuple[TestContract, ...]] = (
    TestContract("tests/ci/test_authorization_policy.py", "unit", "quality", capability_tags=("rbac_policy",)),
    TestContract("tests/ci/test_api_surface_contracts.py", "idp_runtime", "quality", ("slow",), ("api_surface_contracts",)),
    TestContract("tests/ci/test_browser_token_flow_matrix.py", "idp_runtime", "quality", ("slow",), ("browser_login", "browser_logout", "jwt_token")),
    TestContract("tests/ci/test_config_matrix.py", "unit", "quality", capability_tags=("config_matrix",)),
    TestContract("tests/ci/test_config_runtime.py", "unit", "quality", capability_tags=("config_runtime",)),
    TestContract("tests/ci/test_entra_backend_simulation.py", "unit", "quality", capability_tags=("entra_backend_simulation",)),
    TestContract("tests/ci/test_entra_browser_flow_integration.py", "idp_runtime", "quality", ("slow",), ("entra_callback_flow",)),
    TestContract("tests/ci/test_fab_provider_mirror_latest.py", "provider_mirror", "fab_provider_validation", ("slow",), ("fab_provider_official_mirror",)),
    TestContract("tests/ci/test_fab_role_static_mirror.py", "provider_mirror", "quality", capability_tags=("fab_static_mirror",)),
    TestContract("tests/ci/test_identity_mapping_matrix.py", "provider_mirror", "quality", capability_tags=("identity_mapping",)),
    TestContract("tests/ci/test_role_vocabulary_drift_guard.py", "provider_mirror", "quality", capability_tags=("role_vocabulary_drift_guard",)),
    TestContract("tests/ci/test_import_smoke.py", "unit", "quality", capability_tags=("import_bootstrap",)),
    TestContract("tests/ci/test_ldap_backend_simulation.py", "unit", "quality", capability_tags=("ldap_backend_simulation",)),
    TestContract("tests/ci/test_ldap_live_container_integration.py", "idp_runtime", "identity_provider_integration", ("slow",), ("ldap_live_bind_search",)),
    TestContract("tests/ci/test_permissions_ini_scenarios.py", "unit", "quality", capability_tags=("permissions_ini_matrix", "permissions_fixture_corpus")),
    TestContract("tests/ci/test_runtime_negative_paths.py", "idp_runtime", "quality", ("slow",), ("negative_runtime",)),
    TestContract("tests/ci/test_runtime_security_and_logging.py", "unit", "quality", capability_tags=("security_logging",)),
    TestContract("tests/ci/test_runtime_smoke.py", "unit", "quality", capability_tags=("runtime_smoke",)),
    TestContract(
        "tests/ci/test_airflow_smoke.py",
        "airflow_runtime",
        "airflow_integration",
        ("slow",),
        (
            "airflow_auth_manager_import",
            "airflow_db_migrate",
            "airflow_api_health",
            "airflow_protected_endpoint_auth",
            "hello_world_dag_discovery",
            "hello_world_dag_execution",
        ),
    ),
    TestContract(
        "tests/ci/test_db_backed_role_persistence_integration.py",
        "external_runtime",
        "external_real_validation",
        ("slow", "external_real"),
        ("db_backed_roles",),
    ),
    TestContract(
        "tests/ci/test_real_enterprise_ldap_contract.py",
        "external_runtime",
        "external_real_validation",
        ("slow", "external_real"),
        ("real_enterprise_ldap",),
    ),
    TestContract(
        "tests/ci/test_real_entra_tenant_contract.py",
        "external_runtime",
        "external_real_validation",
        ("slow", "external_real"),
        ("real_entra_tenant",),
    ),
)

DEEP_VALIDATION_GROUPS: Final[dict[str, tuple[str, ...]]] = {
    "config-runtime": (
        "tests/ci/test_config_matrix.py",
        "tests/ci/test_config_runtime.py",
        "tests/ci/test_fab_role_static_mirror.py",
        "tests/ci/test_identity_mapping_matrix.py",
        "tests/ci/test_role_vocabulary_drift_guard.py",
        "tests/ci/test_permissions_ini_scenarios.py",
        "tests/ci/test_runtime_negative_paths.py",
        "tests/ci/test_runtime_security_and_logging.py",
        "tests/ci/test_runtime_smoke.py",
    ),
    "authorization-routes": (
        "tests/ci/test_authorization_policy.py",
        "tests/ci/test_api_surface_contracts.py",
        "tests/ci/test_browser_token_flow_matrix.py",
        "tests/ci/test_import_smoke.py",
    ),
    "provider-simulations": (
        "tests/ci/test_ldap_backend_simulation.py",
        "tests/ci/test_entra_backend_simulation.py",
        "tests/ci/test_entra_browser_flow_integration.py",
    ),
}

COVERAGE_FAMILIES: Final[dict[str, CoverageFamily]] = {
    "config-runtime": {
        "threshold": 45,
        "files": (
            "tests/ci/test_config_matrix.py",
            "tests/ci/test_config_runtime.py",
            "tests/ci/test_permissions_ini_scenarios.py",
            "tests/ci/test_runtime_negative_paths.py",
            "tests/ci/test_runtime_security_and_logging.py",
            "tests/ci/test_runtime_smoke.py",
        ),
    },
    "rbac-mirror": {
        "threshold": 35,
        "files": (
            "tests/ci/test_authorization_policy.py",
            "tests/ci/test_fab_role_static_mirror.py",
            "tests/ci/test_identity_mapping_matrix.py",
            "tests/ci/test_role_vocabulary_drift_guard.py",
        ),
    },
    "browser-flows": {
        "threshold": 40,
        "files": (
            "tests/ci/test_api_surface_contracts.py",
            "tests/ci/test_browser_token_flow_matrix.py",
            "tests/ci/test_entra_browser_flow_integration.py",
        ),
    },
    "provider-simulations": {
        "threshold": 35,
        "files": (
            "tests/ci/test_ldap_backend_simulation.py",
            "tests/ci/test_entra_backend_simulation.py",
        ),
    },
    "bootstrap-imports": {
        "threshold": 5,
        "files": ("tests/ci/test_import_smoke.py",),
    },
}

QUALITY_FILES: Final[tuple[str, ...]] = tuple(contract.path for contract in CONTRACTS if contract.suite == "quality")
ALL_ASSIGNED_FILES: Final[tuple[str, ...]] = tuple(contract.path for contract in CONTRACTS)

CAPABILITY_CATALOG: Final[tuple[dict[str, object], ...]] = (
    {"name": "Import/bootstrap smoke", "tag": "import_bootstrap", "status": "covered"},
    {"name": "Config matrix parsing", "tag": "config_matrix", "status": "covered"},
    {"name": "Config runtime loading", "tag": "config_runtime", "status": "covered"},
    {"name": "permissions.ini scenario matrix", "tag": "permissions_ini_matrix", "status": "covered"},
    {"name": "RBAC authorization policy", "tag": "rbac_policy", "status": "covered"},
    {"name": "API surface contracts (HTML, JSON, cookie behavior)", "tag": "api_surface_contracts", "status": "covered"},
    {"name": "Browser login/logout/token routes", "tag": "browser_login", "status": "covered"},
    {"name": "JWT/token flow", "tag": "jwt_token", "status": "covered"},
    {"name": "LDAP backend simulation", "tag": "ldap_backend_simulation", "status": "covered"},
    {"name": "LDAP live bind/search integration", "tag": "ldap_live_bind_search", "status": "covered"},
    {"name": "Entra backend simulation", "tag": "entra_backend_simulation", "status": "covered"},
    {"name": "Entra callback/browser flow integration", "tag": "entra_callback_flow", "status": "covered"},
    {"name": "Identity mapping matrix", "tag": "identity_mapping", "status": "covered"},
    {"name": "FAB static mirror", "tag": "fab_static_mirror", "status": "covered"},
    {"name": "FAB official provider mirror", "tag": "fab_provider_official_mirror", "status": "covered"},
    {"name": "Runtime security/logging behavior", "tag": "security_logging", "status": "covered"},
    {"name": "Negative-path runtime behavior", "tag": "negative_runtime", "status": "covered"},
    {"name": "Airflow auth manager import", "tag": "airflow_auth_manager_import", "status": "covered"},
    {"name": "Airflow DB migrate smoke", "tag": "airflow_db_migrate", "status": "covered"},
    {"name": "Airflow API health/version", "tag": "airflow_api_health", "status": "covered"},
    {"name": "Protected Airflow API rejects anonymous access", "tag": "airflow_protected_endpoint_auth", "status": "covered"},
    {"name": "Hello-world DAG discovery", "tag": "hello_world_dag_discovery", "status": "covered"},
    {"name": "Hello-world DAG execution", "tag": "hello_world_dag_execution", "status": "covered"},
    {"name": "Nightly rolling compatibility matrix", "tag": "nightly_matrix", "status": "covered"},
    {"name": "Artifact summarization per CI lane", "tag": "artifact_summaries", "status": "covered"},
    {"name": "Coverage thresholds per test family", "tag": "family_coverage_thresholds", "status": "covered"},
    {"name": "CI runtime logic centralized in reusable repo scripts", "tag": "ci_runtime_scripts", "status": "covered"},
    {"name": "permissions.ini fixture corpus and parametrized scenario tests", "tag": "permissions_fixture_corpus", "status": "covered"},
    {"name": "Role vocabulary drift guard", "tag": "role_vocabulary_drift_guard", "status": "covered"},
    {"name": "Real DB-backed role persistence integration", "tag": "db_backed_roles", "status": "covered"},
    {"name": "Real Entra tenant callback", "tag": "real_entra_tenant", "status": "covered"},
    {"name": "Real enterprise LDAP/AD schema validation", "tag": "real_enterprise_ldap", "status": "covered"},
)


def discovered_test_files() -> tuple[str, ...]:
    return tuple(sorted(path.relative_to(REPO_ROOT).as_posix() for path in TEST_ROOT.glob("test_*.py")))


def contract_by_path() -> dict[str, TestContract]:
    return {contract.path: contract for contract in CONTRACTS}


def suite_files(suite: str) -> tuple[str, ...]:
    return tuple(contract.path for contract in CONTRACTS if contract.suite == suite)


def deep_validation_group_files(group: str) -> tuple[str, ...]:
    return DEEP_VALIDATION_GROUPS[group]


def coverage_family_files(family: str) -> tuple[str, ...]:
    return cast(tuple[str, ...], COVERAGE_FAMILIES[family]["files"])


def coverage_family_threshold(family: str) -> int:
    return COVERAGE_FAMILIES[family]["threshold"]


def coverage_family_names() -> tuple[str, ...]:
    return tuple(COVERAGE_FAMILIES.keys())


def marker_names_for(path: str) -> tuple[str, ...]:
    contract = contract_by_path()[path]
    return (contract.primary_tier, *contract.extra_markers)
