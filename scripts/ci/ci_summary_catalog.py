from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class LaneTask:
    lane: str
    task: str
    files: tuple[str, ...]
    description: str


PHASES: tuple[tuple[str, tuple[str, ...]], ...] = (
    ("Fast static analysis and contract inventory", ("quality",)),
    ("Deep functional validation and coverage", ("deep_validation",)),
    (
        "Runtime and identity integration",
        ("airflow_integration", "identity_provider_integration"),
    ),
    (
        "Compatibility and external environment validation",
        (
            "fab_provider_validation",
            "nightly_compatibility",
            "external_real_validation",
        ),
    ),
    ("Compliance, security, and release readiness", ("license_compliance",)),
)

LANE_DISPLAY_NAMES: dict[str, str] = {
    "quality": "Quality gate",
    "deep_validation": "Deep validation",
    "airflow_integration": "Airflow integration",
    "identity_provider_integration": "Identity provider integration",
    "fab_provider_validation": "Official FAB provider validation",
    "nightly_compatibility": "Nightly compatibility matrix",
    "external_real_validation": "External real-environment validation",
    "license_compliance": "Licensing, security, and release readiness",
}

LANE_PURPOSE: dict[str, str] = {
    "quality": "Fast repository-wide static checks plus plugin-function-area pytest families to catch regressions early.",
    "deep_validation": "Broader plugin-function-area unit and mock validation across multiple Python versions with coverage and dead-code scanning.",
    "airflow_integration": "Bootstraps Airflow with the plugin and validates runtime import, database, DAG, UI, and API behavior.",
    "identity_provider_integration": "Exercises live LDAP-container behavior and Entra callback/browser-flow integration paths.",
    "fab_provider_validation": "Validates the plugin RBAC mirror against the installed official FAB provider release.",
    "nightly_compatibility": "Scheduled compatibility sweep across the declared Airflow, FAB provider, and Python version matrix.",
    "external_real_validation": "Optional checks against real LDAP, real Entra, and DB-backed role persistence when secrets are provided.",
    "license_compliance": "Checks licensing materials, build/package smoke, SBOM generation, static security findings, and repository release readiness.",
}

SUITE_SOURCE_AREAS: dict[str, tuple[str, ...]] = {
    "quality": (
        "rbac_providers_auth_manager.authorization",
        "rbac_providers_auth_manager.compatibility",
        "rbac_providers_auth_manager.config",
        "rbac_providers_auth_manager.config_runtime",
        "rbac_providers_auth_manager.core",
        "rbac_providers_auth_manager.identity",
        "rbac_providers_auth_manager.runtime",
        "rbac_providers_auth_manager.api",
        "rbac_providers_auth_manager.entrypoints",
        "rbac_providers_auth_manager.services",
        "rbac_providers_auth_manager.ui",
        "rbac_providers_auth_manager.providers",
        "tests/ci",
        "scripts/ci",
    ),
    "deep_validation": (
        "rbac_providers_auth_manager",
        "tests/ci",
        "scripts/ci",
    ),
    "airflow_integration": (
        "rbac_providers_auth_manager.auth_manager",
        "rbac_providers_auth_manager.entrypoints",
        "rbac_providers_auth_manager.services",
        "rbac_providers_auth_manager.ui",
        "scripts/ci/bootstrap_airflow_runtime.py",
        "scripts/ci/write_airflow_ci_config.py",
        "scripts/ci/check_airflow_auth_surface.sh",
        "scripts/ci/check_airflow_discovery.sh",
        "tests/ci/test_airflow_smoke.py",
        "tests/ci/test_airflow_packaged_provider_runtime.py",
    ),
    "identity_provider_integration": (
        "rbac_providers_auth_manager.providers.ldap_*",
        "rbac_providers_auth_manager.identity.ldap_mapper",
        "rbac_providers_auth_manager.providers.entra_*",
        "rbac_providers_auth_manager.identity.entra_mapper",
        "scripts/ci/idp_wait_for_ldap.py",
        "scripts/ci/idp_ldap_bind_smoke.py",
        "tests/ci/test_ldap_live_container_integration.py",
        "tests/ci/test_entra_browser_flow_integration.py",
    ),
    "fab_provider_validation": (
        "rbac_providers_auth_manager.authorization",
        "rbac_providers_auth_manager.compatibility",
        "scripts/ci/validate_fab_mirror.py",
        "tests/ci/test_fab_provider_mirror_latest.py",
    ),
    "external_real_validation": (
        "rbac_providers_auth_manager.providers",
        "rbac_providers_auth_manager.identity",
        "rbac_providers_auth_manager.services",
        "tests/ci/test_db_backed_role_persistence_integration.py",
        "tests/ci/test_real_enterprise_ldap_contract.py",
        "tests/ci/test_real_entra_tenant_contract.py",
    ),
    "license_compliance": (
        "LICENSE",
        "NOTICE",
        "REUSE.toml",
        "LICENSES/Apache-2.0.txt",
        "scripts/ci/check_license_compliance.py",
        "scripts/ci/check_release_readiness.py",
        "scripts/ci/render_static_security_summary.py",
        "scripts/ci/report_requirements_usage.py",
        "scripts/ci/summarize_sbom.py",
        ".github/workflows/reusable_license_compliance.yml",
    ),
    "nightly_compatibility": (
        "rbac_providers_auth_manager.authorization",
        "rbac_providers_auth_manager.compatibility",
        "scripts/ci/validate_fab_mirror.py",
        "tests/ci/test_fab_provider_mirror_latest.py",
    ),
}

LANE_TASKS: dict[str, tuple[LaneTask, ...]] = {
    "quality": (
        LaneTask(
            lane="quality",
            task="compile (Python 3.13)",
            files=("repository Python sources", "tests/ci/*.py", "scripts/ci/*.py"),
            description="Compiles the repository to catch syntax and import-time bytecode errors early.",
        ),
        LaneTask(
            lane="quality",
            task="pytest collect and coverage catalog",
            files=(
                "tests/ci/* selected by suite quality",
                "scripts/ci/report_solution_coverage.py",
            ),
            description="Collects all quality-lane tests and renders the repository-level capability coverage report.",
        ),
        LaneTask(
            lane="quality",
            task="ruff lint",
            files=("repository Python sources", "tests/ci/*.py", "scripts/ci/*.py"),
            description="Runs static lint checks across repository sources, tests, and CI helpers.",
        ),
        LaneTask(
            lane="quality",
            task="ruff format check",
            files=("repository Python sources", "tests/ci/*.py", "scripts/ci/*.py"),
            description="Verifies repository formatting without modifying files.",
        ),
        LaneTask(
            lane="quality",
            task="mypy package",
            files=("rbac_providers_auth_manager/**",),
            description="Type-checks the package implementation.",
        ),
        LaneTask(
            lane="quality",
            task="mypy tests and CI helpers",
            files=("tests/ci/**/*.py", "scripts/ci/**/*.py"),
            description="Type-checks the full CI-facing test and helper surface.",
        ),
        LaneTask(
            lane="quality",
            task="pytest plugin-function families",
            files=(
                "tests/ci/test_config_matrix.py",
                "tests/ci/test_config_runtime.py",
                "tests/ci/test_permissions_ini_scenarios.py",
                "tests/ci/test_runtime_smoke.py",
                "tests/ci/test_core_helpers.py",
                "tests/ci/test_authorization_policy.py",
                "tests/ci/test_fab_role_static_mirror.py",
                "tests/ci/test_identity_mapping_matrix.py",
                "tests/ci/test_role_vocabulary_drift_guard.py",
                "tests/ci/test_api_surface_contracts.py",
                "tests/ci/test_api_observability_matrix.py",
                "tests/ci/test_browser_token_flow_matrix.py",
                "tests/ci/test_runtime_negative_paths.py",
                "tests/ci/test_redirect_and_session_services.py",
                "tests/ci/test_ui_status_components.py",
                "tests/ci/test_permissions_api_payload_matrix.py",
                "tests/ci/test_ldap_backend_simulation.py",
                "tests/ci/test_entra_backend_simulation.py",
                "tests/ci/test_entra_browser_flow_integration.py",
                "tests/ci/test_runtime_backends.py",
                "tests/ci/test_runtime_security_and_logging.py",
                "tests/ci/test_audit_and_governance_reports.py",
                "tests/ci/test_audit_service_logging_matrix.py",
                "tests/ci/test_import_smoke.py",
            ),
            description="Runs the quality-lane pytest families grouped by plugin functionality area with per-family coverage thresholds and scenario-rich API/audit checks.",
        ),
        LaneTask(
            lane="quality",
            task="pip audit",
            files=(
                "requirements-dev.txt",
                "requirements-airflow-integration.txt",
                "requirements-fab-provider-validation.txt",
            ),
            description="Audits installed Python dependencies for known vulnerabilities.",
        ),
    ),
    "deep_validation": (
        LaneTask(
            lane="deep_validation",
            task="test catalog coverage",
            files=("tests/ci/test_*.py", "tests/ci/contract_manifest.py"),
            description="Checks that every CI test file is assigned to a workflow suite exactly once.",
        ),
        LaneTask(
            lane="deep_validation",
            task="compile + import smoke",
            files=("repository Python sources", "tests/ci/test_import_smoke.py"),
            description="Compiles the package and performs an import smoke gate.",
        ),
        LaneTask(
            lane="deep_validation",
            task="area shard: config-permissions-runtime",
            files=(
                "tests/ci/test_config_matrix.py",
                "tests/ci/test_config_runtime.py",
                "tests/ci/test_permissions_ini_scenarios.py",
                "tests/ci/test_runtime_smoke.py",
                "tests/ci/test_core_helpers.py",
            ),
            description="Validates configuration loading, permissions.ini variants, runtime defaults, and low-level helper behavior.",
        ),
        LaneTask(
            lane="deep_validation",
            task="area shard: role-mapping-rbac-compatibility",
            files=(
                "tests/ci/test_authorization_policy.py",
                "tests/ci/test_fab_role_static_mirror.py",
                "tests/ci/test_identity_mapping_matrix.py",
                "tests/ci/test_role_vocabulary_drift_guard.py",
            ),
            description="Validates RBAC policy behavior, role mapping, vocabulary drift protection, and static mirror contracts.",
        ),
        LaneTask(
            lane="deep_validation",
            task="area shard: api-ui-browser-session-observability",
            files=(
                "tests/ci/test_api_surface_contracts.py",
                "tests/ci/test_api_observability_matrix.py",
                "tests/ci/test_browser_token_flow_matrix.py",
                "tests/ci/test_runtime_negative_paths.py",
                "tests/ci/test_redirect_and_session_services.py",
                "tests/ci/test_ui_status_components.py",
                "tests/ci/test_permissions_api_payload_matrix.py",
            ),
            description="Validates API routes, browser flows, UI status rendering, rate-limit responses, redirect safety, session helpers, and negative-path observability.",
        ),
        LaneTask(
            lane="deep_validation",
            task="area shard: provider-backends-and-rate-limits",
            files=(
                "tests/ci/test_ldap_backend_simulation.py",
                "tests/ci/test_entra_backend_simulation.py",
                "tests/ci/test_entra_browser_flow_integration.py",
                "tests/ci/test_runtime_backends.py",
            ),
            description="Validates LDAP and Entra simulations together with runtime auth-state, rate-limit backend, and callback flow behavior.",
        ),
        LaneTask(
            lane="deep_validation",
            task="area shard: audit-logging-governance",
            files=(
                "tests/ci/test_runtime_security_and_logging.py",
                "tests/ci/test_audit_and_governance_reports.py",
                "tests/ci/test_audit_service_logging_matrix.py",
            ),
            description="Validates audit payloads, API/browser event logging, runtime security messages, and governance/version reporting.",
        ),
        LaneTask(
            lane="deep_validation",
            task="dead code scan",
            files=(
                "repository root package",
                "tests/ci/**/*.py",
                "scripts/ci/**/*.py",
            ),
            description="Runs vulture to detect unreachable or unused code paths.",
        ),
    ),
    "airflow_integration": (
        LaneTask(
            lane="airflow_integration",
            task="Airflow runtime bootstrap",
            files=(
                "scripts/ci/bootstrap_airflow_runtime.py",
                "scripts/ci/write_airflow_ci_config.py",
                "scripts/ci/create_hello_world_dag.py",
            ),
            description="Builds an isolated Airflow runtime, stages the plugin archive, and writes CI config.",
        ),
        LaneTask(
            lane="airflow_integration",
            task="installed package metadata and provider facade smoke",
            files=(
                "pyproject.toml",
                "setup.py",
                "tests/ci/test_airflow_packaged_provider_runtime.py",
            ),
            description="Validates that the built package metadata is visible inside the Airflow runtime and that the root auth-manager facade resolves to the runtime entrypoint.",
        ),
        LaneTask(
            lane="airflow_integration",
            task="Airflow DB, DAG, UI, and API smoke",
            files=(
                "scripts/ci/check_airflow_discovery.sh",
                "scripts/ci/check_airflow_auth_surface.sh",
                "tests/ci/test_airflow_smoke.py",
                "tests/ci/test_airflow_packaged_provider_runtime.py",
            ),
            description="Validates DB migration, DAG discovery, API health, login surface, packaged-provider runtime behavior, and a hello-world DAG run.",
        ),
    ),
    "identity_provider_integration": (
        LaneTask(
            lane="identity_provider_integration",
            task="LDAP service wait and bind smoke",
            files=(
                "scripts/ci/idp_wait_for_ldap.py",
                "scripts/ci/idp_ldap_bind_smoke.py",
            ),
            description="Waits for the LDAP service container and verifies a real bind before pytest starts.",
        ),
        LaneTask(
            lane="identity_provider_integration",
            task="identity-provider integration pytest",
            files=(
                "tests/ci/test_ldap_live_container_integration.py",
                "tests/ci/test_entra_browser_flow_integration.py",
            ),
            description="Exercises live LDAP container flows plus Entra browser callback behavior.",
        ),
    ),
    "fab_provider_validation": (
        LaneTask(
            lane="fab_provider_validation",
            task="official FAB support snapshot",
            files=("scripts/ci/validate_fab_mirror.py",),
            description="Captures the official FAB provider permission/resource surface before mirror tests run.",
        ),
        LaneTask(
            lane="fab_provider_validation",
            task="provider mirror pytest",
            files=("tests/ci/test_fab_provider_mirror_latest.py",),
            description="Checks the plugin vocabulary and behavior against the installed official FAB provider release.",
        ),
    ),
    "nightly_compatibility": (
        LaneTask(
            lane="nightly_compatibility",
            task="compatibility matrix bootstrap",
            files=(
                "scripts/ci/validate_fab_mirror.py",
                "tests/ci/test_fab_provider_mirror_latest.py",
            ),
            description="Runs the FAB mirror validation across the scheduled Airflow, FAB provider, and Python matrix.",
        ),
    ),
    "external_real_validation": (
        LaneTask(
            lane="external_real_validation",
            task="external Airflow bootstrap",
            files=(
                "scripts/ci/bootstrap_airflow_runtime.py",
                "scripts/ci/write_airflow_ci_config.py",
                "scripts/ci/create_hello_world_dag.py",
            ),
            description="Bootstraps an Airflow runtime ready to exercise real external identity systems.",
        ),
        LaneTask(
            lane="external_real_validation",
            task="real integration pytest",
            files=(
                "tests/ci/test_db_backed_role_persistence_integration.py",
                "tests/ci/test_real_enterprise_ldap_contract.py",
                "tests/ci/test_real_entra_tenant_contract.py",
            ),
            description="Runs optional DB-backed, real LDAP, and real Entra contract checks when secrets are supplied.",
        ),
    ),
    "license_compliance": (
        LaneTask(
            lane="license_compliance",
            task="requirements usage",
            files=("requirements*.txt", ".github/workflows/*.yml"),
            description="Shows which requirement files are actually used by the workflows.",
        ),
        LaneTask(
            lane="license_compliance",
            task="license compliance scan",
            files=(
                "LICENSE",
                "NOTICE",
                "REUSE.toml",
                "LICENSES/Apache-2.0.txt",
                "repository sources",
            ),
            description="Checks distribution licensing materials, scans for copyleft indicators, and runs REUSE lint.",
        ),
        LaneTask(
            lane="license_compliance",
            task="release readiness",
            files=(
                "README.md",
                "py.typed",
                "pyproject.toml or setup.py",
                "repository tree hygiene",
            ),
            description="Checks whether the repository is shaped like a releasable Python distribution and flags committed cache/build artefacts.",
        ),
        LaneTask(
            lane="license_compliance",
            task="build distribution",
            files=("pyproject.toml", "setup.py", "repository sources"),
            description="Builds wheel and sdist artifacts to prove the repository is packageable for release.",
        ),
        LaneTask(
            lane="license_compliance",
            task="built distribution install smoke",
            files=("dist/*.whl", "isolated virtual environment"),
            description="Installs the freshly built wheel in a clean virtual environment and verifies package metadata import.",
        ),
        LaneTask(
            lane="license_compliance",
            task="SBOM",
            files=("installed environment",),
            description="Generates CycloneDX JSON/XML SBOM output and a compact markdown summary.",
        ),
        LaneTask(
            lane="license_compliance",
            task="static security",
            files=("repository sources", ".gitleaks.toml"),
            description="Runs Bandit and Gitleaks and publishes a finding-oriented static-security summary.",
        ),
    ),
}

SUPPLEMENTAL_AREAS: tuple[dict[str, object], ...] = (
    {
        "name": "Repository compile gate",
        "tag": "compile_gate",
        "status": "covered",
        "lanes": ("quality", "deep_validation"),
    },
    {
        "name": "Repository lint and format gate",
        "tag": "lint_format_gate",
        "status": "covered",
        "lanes": ("quality",),
    },
    {
        "name": "Repository type checking",
        "tag": "type_checking",
        "status": "covered",
        "lanes": ("quality",),
    },
    {
        "name": "Dependency vulnerability audit",
        "tag": "dependency_vulnerability_audit",
        "status": "covered",
        "lanes": ("quality",),
    },
    {
        "name": "Dead-code analysis",
        "tag": "dead_code_scan",
        "status": "covered",
        "lanes": ("deep_validation",),
    },
    {
        "name": "Airflow auth-manager runtime smoke",
        "tag": "airflow_runtime_smoke",
        "status": "covered",
        "lanes": ("airflow_integration",),
        "reason": "Executed by the Airflow integration suite against the declared Airflow version.",
    },
    {
        "name": "Packaged provider install inside Airflow runtime",
        "tag": "airflow_packaged_provider_install",
        "status": "covered",
        "lanes": ("airflow_integration",),
        "reason": "The Airflow integration lane installs the local distribution and validates the packaged runtime facade.",
    },
    {
        "name": "Official FAB provider compatibility snapshot",
        "tag": "official_fab_snapshot",
        "status": "covered",
        "lanes": ("fab_provider_validation", "nightly_compatibility"),
    },
    {
        "name": "Apache distribution files (LICENSE and NOTICE)",
        "tag": "apache_distribution_files",
        "status": "covered",
        "lanes": ("license_compliance",),
    },
    {
        "name": "REUSE metadata and machine-readable licensing",
        "tag": "reuse_metadata",
        "status": "covered",
        "lanes": ("license_compliance",),
    },
    {
        "name": "Dependency license inventory",
        "tag": "dependency_license_inventory",
        "status": "covered",
        "lanes": ("license_compliance",),
    },
    {
        "name": "Release-readiness and repository hygiene",
        "tag": "release_readiness",
        "status": "covered",
        "lanes": ("license_compliance",),
    },
    {
        "name": "SBOM generation",
        "tag": "sbom_generation",
        "status": "covered",
        "lanes": ("license_compliance",),
    },
    {
        "name": "Static secret and code security scan",
        "tag": "static_security_scan",
        "status": "covered",
        "lanes": ("license_compliance",),
    },
    {
        "name": "Visual browser regression screenshots",
        "tag": "visual_regression",
        "status": "gap",
        "lanes": (),
        "reason": "No browser screenshot-diff harness is wired into the current CI matrix yet.",
    },
    {
        "name": "Built wheel or sdist installation smoke",
        "tag": "built_distribution_install",
        "status": "covered",
        "lanes": ("license_compliance",),
        "reason": "The license-compliance lane now installs the freshly built wheel in an isolated virtual environment.",
    },
    {
        "name": "Multi-node shared-state failover simulation",
        "tag": "ha_failover",
        "status": "gap",
        "lanes": (),
        "reason": "The current CI topology runs on single-host ephemeral workers and does not provision clustered shared-session infrastructure.",
    },
    {
        "name": "Airflow 3.2+ provider CLI surface validation",
        "tag": "provider_cli_surface",
        "status": "gap",
        "lanes": (),
        "reason": "The declared compatibility matrix in this repository is still centered on Airflow 3.1.8 and FAB provider 3.5.0.",
    },
)


def checkbox(value: bool) -> str:
    return "[x] yes" if value else "[ ] no"
