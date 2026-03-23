# CI overview

This document is generated from the CI-owned registries and is intended for maintainers who need the high-level operating model without reading each workflow file.

## Architecture at a glance

The CI setup is intentionally layered:

- top-level entrypoints in `.github/workflows/` decide when CI runs and which reusable workflows are called
- reusable workflows own lane-level execution such as quality, deep validation, Airflow integration, identity validation, and compliance
- composite actions under `ci/actions/` centralize repeated bootstrap, rendering, and upload steps
- CI registries under `ci/config/` and `ci/scripts/` provide the single source of truth for versions, path filters, lane policy, ownership, and generated documentation

This split follows GitHub's distinction between reusable workflows for whole-job reuse and composite actions for repeated step bundles.

## Key defaults

- primary Python: `3.13`
- secondary Python: `3.12`
- default Airflow: `3.1.8`
- default FAB provider: `3.5.0`

These defaults are exported into top-level workflows through the `export-ci-context` composite action, so version drift is reduced.

## Main CI lanes

| Lane | Blocking | Cadence | Secrets profile | Purpose |
| --- | --- | --- | --- | --- |
| ci_self_check | no | per-change on CI-owned files | none | Fast CI integrity lane for workflows, actions, registries, and summaries. |
| quality | yes | per-change | none | Fast lint, typing, unit, and family coverage gates. |
| deep_validation | yes | per-change optional | none | Area-sharded coverage, dead-code, and wider behavioral validation. |
| airflow_integration | yes | per-change optional | none | Bootstraps Airflow runtime and validates plugin install/import health. |
| identity_provider_integration | yes | per-change optional | test-services | Exercises LDAP and Entra integration-style flows without external enterprise secrets. |
| fab_provider_validation | yes | per-change optional | none | Installs official FAB provider and checks mirror drift. |
| nightly_compatibility | no | nightly or manual | none | Matrix canary against pinned Airflow and FAB versions. |
| external_real_validation | no | manual opt-in | external-real | Requires real external identity and DB-backed resources. |
| license_compliance | yes | per-change optional | none | OSS compliance, build smoke, SBOM, and static security. |

## Lightweight path-aware workflows

These workflows exist mainly for performance and FinOps control on private repositories:

| Workflow | Triggered when these areas change |
| --- | --- |
| ci_self_check | .github/workflows/**<br>ci/**<br>tests/ci/**<br>pyproject.toml<br>pytest.ini<br>mypy.ini<br>docs/CI_OVERVIEW.md |
| compliance_fast | .github/workflows/reusable_license_compliance.yml<br>.github/workflows/compliance_fast.yml<br>LICENSE<br>NOTICE<br>REUSE.toml<br>LICENSES/**<br>.gitleaks.toml<br>pyproject.toml<br>setup.py<br>ci/** |
| quality_fast | __init__.py<br>api/**<br>auth_manager.py<br>authorization/**<br>compatibility/**<br>config.py<br>config_runtime/**<br>core/**<br>entrypoints/**<br>identity/**<br>providers/**<br>runtime/**<br>services/**<br>ui/**<br>tests/**<br>.github/workflows/reusable_quality.yml<br>.github/workflows/quality_fast.yml<br>ci/**<br>pyproject.toml<br>pytest.ini<br>mypy.ini |

## CI-owned support layout

- workflows: 18
- composite actions: 14
- Python helpers: 26
- bash helpers: 3
- requirement sets: 4

## Extend this CI safely

1. Add or update the lane/workflow in the appropriate reusable workflow file.
2. Register version pins or path filters in `ci/config/` instead of hardcoding them in YAML.
3. Reuse an existing composite action before adding inline shell glue.
4. Update `tests/ci/contract_manifest.py` when new CI self-check tests are added.
5. Regenerate the committed CI reference documents so the self-check lane stays green.

## Complexity assessment

The setup is now moderately sophisticated, but it is not unmanageably overcomplicated for a project that combines plugin runtime tests, Airflow integration, identity-provider validation, compliance, generated documentation, and private-repo minute controls. The main reason it remains maintainable is that metadata and repeated logic have been moved out of workflow YAML and into registries, scripts, and reusable actions.
