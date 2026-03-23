from __future__ import annotations

from dataclasses import dataclass

from ci_catalog_registry import (
    DEEP_VALIDATION_TASK_DESCRIPTIONS,
    FAMILY_FILES,
    FAMILY_ORDER,
    QUALITY_FAMILY_FILES,
    QUALITY_FAMILY_TASK_DESCRIPTION,
    suite_source_areas,
)


@dataclass(frozen=True)
class LaneTask:
    lane: str
    task: str
    files: tuple[str, ...]
    description: str


PHASES: tuple[tuple[str, tuple[str, ...]], ...] = (
    ("CI infrastructure integrity", ("ci_self_check",)),
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
    "ci_self_check": "CI self-check",
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
    "ci_self_check": "Fast CI-owned workflow, registry, inventory, and documentation integrity checks.",
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
    "ci_self_check": (
        ".github/workflows/*.yml",
        "ci/actions/**/*.yml",
        "ci/config/*.json",
        "ci/scripts/**/*.py",
        "ci/CI_REFERENCE.md",
        "ci/CI_REFERENCE.json",
        "tests/ci/test_ci_*",
    ),
    "quality": suite_source_areas("quality"),
    "deep_validation": suite_source_areas("deep_validation"),
    "airflow_integration": (
        "rbac_providers_auth_manager.auth_manager",
        "rbac_providers_auth_manager.entrypoints",
        "rbac_providers_auth_manager.services",
        "rbac_providers_auth_manager.ui",
        "ci/scripts/bootstrap_airflow_runtime.py",
        "ci/scripts/write_airflow_ci_config.py",
        "ci/bash/check_airflow_auth_surface.sh",
        "ci/bash/check_airflow_discovery.sh",
        "tests/ci/test_airflow_smoke.py",
        "tests/ci/test_airflow_packaged_provider_runtime.py",
    ),
    "identity_provider_integration": (
        "rbac_providers_auth_manager.providers.ldap_*",
        "rbac_providers_auth_manager.identity.ldap_mapper",
        "rbac_providers_auth_manager.providers.entra_*",
        "rbac_providers_auth_manager.identity.entra_mapper",
        "ci/scripts/idp_wait_for_ldap.py",
        "ci/scripts/idp_ldap_bind_smoke.py",
        "tests/ci/test_ldap_live_container_integration.py",
        "tests/ci/test_entra_browser_flow_integration.py",
    ),
    "fab_provider_validation": (
        "rbac_providers_auth_manager.authorization",
        "rbac_providers_auth_manager.compatibility",
        "ci/scripts/validate_fab_mirror.py",
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
        "ci/scripts/check_license_compliance.py",
        "ci/scripts/check_release_readiness.py",
        "ci/scripts/render_static_security_summary.py",
        "ci/scripts/report_requirements_usage.py",
        "ci/scripts/summarize_sbom.py",
        ".github/workflows/reusable_license_compliance.yml",
    ),
    "nightly_compatibility": (
        "rbac_providers_auth_manager.authorization",
        "rbac_providers_auth_manager.compatibility",
        "ci/scripts/validate_fab_mirror.py",
        "tests/ci/test_fab_provider_mirror_latest.py",
    ),
}

LANE_TASKS: dict[str, tuple[LaneTask, ...]] = {
    "ci_self_check": (
        LaneTask(
            lane="ci_self_check",
            task="CI registry, workflow, and action compile/parse checks",
            files=(
                ".github/workflows/*.yml",
                "ci/actions/*/action.yml",
                "ci/config/*.json",
                "ci/scripts/*.py",
            ),
            description="Compiles CI helper modules and parses workflows plus composite actions to catch broken CI infrastructure early.",
        ),
        LaneTask(
            lane="ci_self_check",
            task="CI reference and inventory generation",
            files=(
                "ci/scripts/render_ci_inventory.py",
                "ci/scripts/render_ci_reference.py",
                "ci/scripts/ci_versions.py",
                "ci/scripts/ci_path_filters.py",
                "ci/CI_REFERENCE.md",
                "ci/CI_REFERENCE.json",
                "ci/CI_REFERENCE.json",
            ),
            description="Renders the committed CI reference, inventory, versions, and path-filter documentation and checks that the in-repo reference stays synchronized.",
        ),
        LaneTask(
            lane="ci_self_check",
            task="CI policy and registry tests",
            files=(
                "tests/ci/test_ci_lane_policy.py",
                "tests/ci/test_ci_catalog_registry.py",
                "tests/ci/test_ci_versions_registry.py",
                "tests/ci/test_ci_path_filters_registry.py",
                "tests/ci/test_render_final_ci_summary.py",
                "tests/ci/test_ci_reference_sync.py",
            ),
            description="Validates lane policy, summary catalog, versions registry, path-filter registry, committed CI reference synchronization, and final-summary rendering contracts.",
        ),
    ),
    "quality": (
        LaneTask(
            lane="quality",
            task="compile (Python 3.13)",
            files=("repository Python sources", "tests/ci/*.py", "ci/scripts/*.py"),
            description="Compiles the repository to catch syntax and import-time bytecode errors early.",
        ),
        LaneTask(
            lane="quality",
            task="pytest collect and coverage catalog",
            files=(
                "tests/ci/* selected by suite quality",
                "ci/scripts/report_solution_coverage.py",
            ),
            description="Collects all quality-lane tests and renders the repository-level capability coverage report.",
        ),
        LaneTask(
            lane="quality",
            task="ruff lint",
            files=("repository Python sources", "tests/ci/*.py", "ci/scripts/*.py"),
            description="Runs static lint checks across repository sources, tests, and CI helpers.",
        ),
        LaneTask(
            lane="quality",
            task="ruff format check",
            files=("repository Python sources", "tests/ci/*.py", "ci/scripts/*.py"),
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
            files=("tests/ci/**/*.py", "ci/scripts/**/*.py"),
            description="Type-checks the full CI-facing test and helper surface.",
        ),
        LaneTask(
            lane="quality",
            task="pytest plugin-function families",
            files=QUALITY_FAMILY_FILES,
            description=QUALITY_FAMILY_TASK_DESCRIPTION,
        ),
        LaneTask(
            lane="quality",
            task="pip audit",
            files=(
                "ci/requirements/requirements-dev.txt",
                "ci/requirements/requirements-airflow-integration.txt",
                "ci/requirements/requirements-fab-provider-validation.txt",
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
        *(
            LaneTask(
                lane="deep_validation",
                task=f"area shard: {family}",
                files=FAMILY_FILES[family],
                description=DEEP_VALIDATION_TASK_DESCRIPTIONS[family],
            )
            for family in FAMILY_ORDER
            if family != "bootstrap-imports"
        ),
        LaneTask(
            lane="deep_validation",
            task="dead code scan",
            files=(
                "repository root package",
                "tests/ci/**/*.py",
                "ci/scripts/**/*.py",
            ),
            description="Runs vulture to detect unreachable or unused code paths.",
        ),
    ),
    "airflow_integration": (
        LaneTask(
            lane="airflow_integration",
            task="Airflow runtime bootstrap",
            files=(
                "ci/scripts/bootstrap_airflow_runtime.py",
                "ci/scripts/write_airflow_ci_config.py",
                "ci/scripts/create_hello_world_dag.py",
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
                "ci/bash/check_airflow_discovery.sh",
                "ci/bash/check_airflow_auth_surface.sh",
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
                "ci/scripts/idp_wait_for_ldap.py",
                "ci/scripts/idp_ldap_bind_smoke.py",
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
            files=("ci/scripts/validate_fab_mirror.py",),
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
                "ci/scripts/validate_fab_mirror.py",
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
                "ci/scripts/bootstrap_airflow_runtime.py",
                "ci/scripts/write_airflow_ci_config.py",
                "ci/scripts/create_hello_world_dag.py",
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
            files=(
                "ci/requirements/*.txt",
                "ci/config/versions.json",
                ".github/workflows/*.yml",
            ),
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
