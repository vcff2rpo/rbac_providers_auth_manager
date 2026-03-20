from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class LaneTask:
    lane: str
    task: str
    files: tuple[str, ...]
    description: str


SUITE_SOURCE_AREAS: dict[str, tuple[str, ...]] = {
    "quality": (
        "rbac_providers_auth_manager.authorization",
        "rbac_providers_auth_manager.identity",
        "rbac_providers_auth_manager.config",
        "rbac_providers_auth_manager.config_runtime",
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
            files=("repository Python sources", "tests/ci/*.py"),
            description="Compiles the repository to catch syntax and import-time bytecode errors early.",
        ),
        LaneTask(
            lane="quality",
            task="pytest collect (Python 3.13)",
            files=(
                "tests/ci/* selected by suite quality",
                "scripts/ci/report_solution_coverage.py",
            ),
            description="Collects all quality-lane tests and renders the repository-level capability coverage report.",
        ),
        LaneTask(
            lane="quality",
            task="ruff lint",
            files=("repository Python sources",),
            description="Runs static lint checks across the repository.",
        ),
        LaneTask(
            lane="quality",
            task="ruff format check",
            files=("repository Python sources",),
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
            task="mypy tests",
            files=("tests/ci/* selected by suite quality", "scripts/ci/*"),
            description="Type-checks the CI tests and helper scripts.",
        ),
        LaneTask(
            lane="quality",
            task="pytest family coverage",
            files=(
                "tests/ci/test_config_*.py",
                "tests/ci/test_permissions_ini_scenarios.py",
                "tests/ci/test_runtime_*.py",
                "tests/ci/test_authorization_policy.py",
                "tests/ci/test_fab_role_static_mirror.py",
                "tests/ci/test_identity_mapping_matrix.py",
                "tests/ci/test_role_vocabulary_drift_guard.py",
                "tests/ci/test_api_surface_contracts.py",
                "tests/ci/test_browser_token_flow_matrix.py",
                "tests/ci/test_entra_browser_flow_integration.py",
                "tests/ci/test_ldap_backend_simulation.py",
                "tests/ci/test_entra_backend_simulation.py",
                "tests/ci/test_import_smoke.py",
            ),
            description="Runs the quality-lane pytest families with per-family coverage thresholds and selector summaries.",
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
            description="Checks that every CI test file is assigned to a workflow suite.",
        ),
        LaneTask(
            lane="deep_validation",
            task="compile + import smoke",
            files=("repository Python sources", "tests/ci/test_import_smoke.py"),
            description="Compiles the package and performs an import smoke gate.",
        ),
        LaneTask(
            lane="deep_validation",
            task="unit + mock tests",
            files=(
                "tests/ci/test_config_*.py",
                "tests/ci/test_permissions_ini_scenarios.py",
                "tests/ci/test_runtime_*.py",
                "tests/ci/test_authorization_policy.py",
                "tests/ci/test_api_surface_contracts.py",
                "tests/ci/test_browser_token_flow_matrix.py",
                "tests/ci/test_ldap_backend_simulation.py",
                "tests/ci/test_entra_backend_simulation.py",
                "tests/ci/test_entra_browser_flow_integration.py",
            ),
            description="Executes the three deep-validation shards across the configured Python matrix with coverage.",
        ),
        LaneTask(
            lane="deep_validation",
            task="dead code scan",
            files=("repository Python sources", "tests/**"),
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
            task="Airflow DB/API smoke",
            files=(
                "scripts/ci/check_airflow_discovery.sh",
                "scripts/ci/check_airflow_auth_surface.sh",
                "tests/ci/test_airflow_smoke.py",
            ),
            description="Validates DB migration, DAG discovery, API health, login surface, and a hello-world DAG run.",
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
            description="Runs the FAB mirror validation across the scheduled Airflow/FAB/Python matrix.",
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
            task="SBOM",
            files=("installed environment",),
            description="Generates CycloneDX JSON/XML SBOM output and a compact markdown summary.",
        ),
        LaneTask(
            lane="license_compliance",
            task="static security",
            files=("repository sources", ".gitleaks.toml"),
            description="Runs Bandit and Gitleaks and publishes a static-security summary.",
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
    },
    {
        "name": "Built wheel or sdist installation smoke",
        "tag": "built_distribution_install",
        "status": "gap",
        "lanes": (),
    },
    {
        "name": "Multi-node shared-state failover simulation",
        "tag": "ha_failover",
        "status": "gap",
        "lanes": (),
    },
    {
        "name": "Airflow 3.2+ provider CLI surface validation",
        "tag": "provider_cli_surface",
        "status": "gap",
        "lanes": (),
    },
)


def checkbox(value: bool) -> str:
    return "[x] yes" if value else "[ ] no"
