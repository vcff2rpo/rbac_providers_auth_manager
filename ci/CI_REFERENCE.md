# CI reference

This file is generated from the CI-owned registries under `ci/` and should be updated whenever workflow structure, version pins, or path-filter ownership changes.

## Version registry

| Area | Value |
| --- | --- |
| Python primary | 3.13 |
| Python secondary | 3.12 |
| Deep-validation matrix | 3.12, 3.13 |
| Nightly matrix | 3.12, 3.13 |
| Airflow default | 3.1.8 |
| FAB provider default | 3.5.0 |
| Derived deep-validation Python context | 3.12, 3.13 |
| Derived nightly Airflow context | 3.1.8 |

Top-level workflows resolve their version and matrix defaults from the `export-ci-context` action backed by `ci/scripts/ci_versions.py`, so the pinned context lives in one CI-owned registry.

## Lane policy registry

| Lane | Workflow | Blocking | Cadence | Secrets profile | Artifact prefix | Summary group | Notes |
| --- | --- | --- | --- | --- | --- | --- | --- |
| ci_self_check | reusable_ci_self_check.yml | no | per-change on CI-owned files | none | ci-self-check | ci-infrastructure | Fast CI integrity lane for workflows, actions, registries, and summaries. |
| quality | reusable_quality.yml | yes | per-change | none | quality | core-quality | Fast lint, typing, unit, and family coverage gates. |
| deep_validation | reusable_deep_validation.yml | yes | per-change optional | none | deep-validation | deep-validation | Area-sharded coverage, dead-code, and wider behavioral validation. |
| airflow_integration | reusable_airflow_integration.yml | yes | per-change optional | none | airflow-integration | integration | Bootstraps Airflow runtime and validates plugin install/import health. |
| identity_provider_integration | reusable_identity_provider_integration.yml | yes | per-change optional | test-services | idp-integration | integration | Exercises LDAP and Entra integration-style flows without external enterprise secrets. |
| fab_provider_validation | reusable_fab_provider_validation.yml | yes | per-change optional | none | fab-provider-validation | compatibility | Installs official FAB provider and checks mirror drift. |
| nightly_compatibility | reusable_nightly_compatibility.yml | no | nightly or manual | none | nightly-compatibility | compatibility | Matrix canary against pinned Airflow and FAB versions. |
| external_real_validation | reusable_external_real_validation.yml | no | manual opt-in | external-real | external-real-validation | external-validation | Requires real external identity and DB-backed resources. |
| license_compliance | reusable_license_compliance.yml | yes | per-change optional | none | license-compliance | release-readiness | OSS compliance, build smoke, SBOM, and static security. |

## Path-filter registry

| Workflow | Event | Paths |
| --- | --- | --- |
| ci_self_check | pull_request | .github/workflows/**<br>ci/**<br>tests/ci/**<br>pyproject.toml<br>pytest.ini<br>mypy.ini<br>docs/CI_OVERVIEW.md |
| ci_self_check | push | .github/workflows/**<br>ci/**<br>tests/ci/**<br>pyproject.toml<br>pytest.ini<br>mypy.ini<br>docs/CI_OVERVIEW.md |
| compliance_fast | pull_request | .github/workflows/reusable_license_compliance.yml<br>.github/workflows/compliance_fast.yml<br>LICENSE<br>NOTICE<br>REUSE.toml<br>LICENSES/**<br>.gitleaks.toml<br>pyproject.toml<br>setup.py<br>ci/** |
| compliance_fast | push | .github/workflows/reusable_license_compliance.yml<br>.github/workflows/compliance_fast.yml<br>LICENSE<br>NOTICE<br>REUSE.toml<br>LICENSES/**<br>.gitleaks.toml<br>pyproject.toml<br>setup.py<br>ci/** |
| quality_fast | pull_request | __init__.py<br>api/**<br>auth_manager.py<br>authorization/**<br>compatibility/**<br>config.py<br>config_runtime/**<br>core/**<br>entrypoints/**<br>identity/**<br>providers/**<br>runtime/**<br>services/**<br>ui/**<br>tests/**<br>.github/workflows/reusable_quality.yml<br>.github/workflows/quality_fast.yml<br>ci/**<br>pyproject.toml<br>pytest.ini<br>mypy.ini |
| quality_fast | push | __init__.py<br>api/**<br>auth_manager.py<br>authorization/**<br>compatibility/**<br>config.py<br>config_runtime/**<br>core/**<br>entrypoints/**<br>identity/**<br>providers/**<br>runtime/**<br>services/**<br>ui/**<br>tests/**<br>.github/workflows/reusable_quality.yml<br>.github/workflows/quality_fast.yml<br>ci/**<br>pyproject.toml<br>pytest.ini<br>mypy.ini |

## CI-owned file layout

- composite actions: 14
- bash helpers: 3
- python helpers: 26
- requirement sets: 4
- config files: 3
- workflows: 18
- reusable workflows with declared inputs: 13
- manual entrypoints with dispatch inputs: 2

### Composite actions

- `actions/bootstrap-python/action.yml`
- `actions/export-ci-context/action.yml`
- `actions/install-ldap-build-deps/action.yml`
- `actions/install-python-deps/action.yml`
- `actions/render-ci-ownership/action.yml`
- `actions/render-ci-reference/action.yml`
- `actions/render-ci-scope-summary/action.yml`
- `actions/render-ci-workflow-inputs/action.yml`
- `actions/render-final-ci-summary/action.yml`
- `actions/render-project-ci-overview/action.yml`
- `actions/resolve-airflow-constraints/action.yml`
- `actions/summarize-ci-artifacts/action.yml`
- `actions/upload-artifact-bundle/action.yml`
- `actions/validate-ci-governance/action.yml`

### Python helpers

- `scripts/bootstrap_airflow_runtime.py`
- `scripts/check_license_compliance.py`
- `scripts/check_release_readiness.py`
- `scripts/ci_catalog_registry.py`
- `scripts/ci_lane_policy.py`
- `scripts/ci_path_filters.py`
- `scripts/ci_summary_catalog.py`
- `scripts/ci_versions.py`
- `scripts/create_hello_world_dag.py`
- `scripts/idp_ldap_bind_smoke.py`
- `scripts/idp_wait_for_ldap.py`
- `scripts/list_contract_tests.py`
- `scripts/render_ci_inventory.py`
- `scripts/render_ci_ownership.py`
- `scripts/render_ci_reference.py`
- `scripts/render_ci_scope_summary.py`
- `scripts/render_ci_workflow_inputs.py`
- `scripts/render_final_ci_summary.py`
- `scripts/render_project_ci_overview.py`
- `scripts/render_static_security_summary.py`
- `scripts/report_requirements_usage.py`
- `scripts/report_solution_coverage.py`
- `scripts/summarize_ci_artifacts.py`
- `scripts/summarize_sbom.py`
- `scripts/validate_fab_mirror.py`
- `scripts/write_airflow_ci_config.py`

### Workflows

- `ci.yml`
- `ci_self_check.yml`
- `compliance_fast.yml`
- `nightly_compatibility.yml`
- `quality_fast.yml`
- `reusable_airflow_integration.yml`
- `reusable_airflow_suite.yml`
- `reusable_ci_self_check.yml`
- `reusable_deep_validation.yml`
- `reusable_external_real_validation.yml`
- `reusable_fab_provider_suite.yml`
- `reusable_fab_provider_validation.yml`
- `reusable_identity_provider_integration.yml`
- `reusable_license_compliance.yml`
- `reusable_nightly_compatibility.yml`
- `reusable_open_pr.yml`
- `reusable_quality.yml`
- `reusable_review_pr_gate.yml`
