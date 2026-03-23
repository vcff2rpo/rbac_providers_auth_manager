# CI_README.md

## 1. What this document is for

This document is the maintainer, operator, and administrator guide for the current GitHub Actions CI design used by this repository.

It is written to help four audiences become productive quickly:

- contributors who want to understand what runs and why
- maintainers who need to extend or refactor the pipeline safely
- reviewers who need to interpret CI results and promotion readiness
- administrators who manage repository settings, secrets, required checks, and governance rules

The repository does not use a single flat workflow. Instead, the CI is intentionally split into top-level entry workflows, reusable lane workflows, local composite actions, registry files, render scripts, and a contract-driven test manifest. That makes the system easier to evolve, but it also means changes must be made in the correct layer.

This guide explains that layering in practical terms.

---

## 2. CI philosophy and operating model

The current CI design follows a few strong principles:

### 2.1 Separate orchestration from execution

Top-level workflows decide **when CI runs**.
Reusable workflows decide **what a lane does**.
Composite actions decide **how repeated step bundles are reused**.
Python helpers decide **how CI metadata is rendered, validated, and summarized**.

This prevents the top-level workflows from becoming unreadable and keeps maintenance localized.

### 2.2 Keep policy in registries, not scattered YAML

The pipeline relies on dedicated source-of-truth files instead of hardcoding policy in multiple places.

Examples:

- version policy lives in `ci/config/versions.json`
- path trigger policy lives in `ci/config/path_filters.json`
- lane intent lives in `ci/scripts/ci_lane_policy.py`
- test-to-suite assignment lives in `tests/ci/contract_manifest.py`

This is one of the most important design choices in the current CI. When the system changes, maintainers should update the registry or manifest first, then the workflows that consume it.

### 2.3 Treat CI documentation as a tested deliverable

The repository commits generated CI reference files and validates that they stay synchronized with the real workflows and registries.

That means CI documentation is not purely informational. It is part of governance.

### 2.4 Prefer summary-first troubleshooting

The pipeline produces job summaries and artifacts so maintainers can understand failures quickly, without reading raw runner logs first.

### 2.5 Keep heavy or environment-dependent lanes optional

Not every validation belongs in every push. Fast lanes cover routine developer feedback. Heavier or environment-backed lanes are manual, scheduled, or opt-in.

---

## 3. CI at a glance

The current bundle contains the following CI support structure:

- **18 workflows** in `.github/workflows/`
- **14 composite actions** in `ci/actions/`
- **26 Python CI helper scripts** in `ci/scripts/`
- **3 Bash helper scripts** in `ci/bash/`
- **4 CI requirements files** in `ci/requirements/`
- **50 CI-focused tests** in `tests/ci/`

### 3.1 Main CI entrypoints

The repository currently exposes these main workflow entrypoints:

- `ci.yml` — manual umbrella gate
- `quality_fast.yml` — fast path-filtered quality run
- `compliance_fast.yml` — fast path-filtered compliance run
- `ci_self_check.yml` — governance/self-check run for CI-owned files
- `nightly_compatibility.yml` — scheduled or manual compatibility canary

### 3.2 Core reusable lane workflows

The main reusable lane workflows are:

- `reusable_ci_self_check.yml`
- `reusable_quality.yml`
- `reusable_deep_validation.yml`
- `reusable_airflow_integration.yml`
- `reusable_airflow_suite.yml`
- `reusable_identity_provider_integration.yml`
- `reusable_fab_provider_validation.yml`
- `reusable_fab_provider_suite.yml`
- `reusable_nightly_compatibility.yml`
- `reusable_external_real_validation.yml`
- `reusable_license_compliance.yml`
- `reusable_review_pr_gate.yml`
- `reusable_open_pr.yml`

### 3.3 Primary CI source-of-truth files

These files are especially important for maintenance:

- `ci/config/versions.json`
- `ci/config/path_filters.json`
- `ci/config/core_promotion_allowlist.txt`
- `ci/scripts/ci_lane_policy.py`
- `tests/ci/contract_manifest.py`
- `ci/CI_REFERENCE.md`
- `ci/CI_REFERENCE.json`
- `ci/CI_WORKFLOW_INPUTS.md`
- `ci/CI_WORKFLOW_INPUTS.json`
- `ci/CI_OWNERSHIP.json`

---

## 4. High-level architecture

The easiest way to understand this CI is to read it from outside to inside.

### 4.1 Layer 1: entry workflows

These answer: **what event starts CI?**

Examples:

- push and pull-request scoped fast workflows
- manual dispatch umbrella workflow
- scheduled nightly compatibility workflow

### 4.2 Layer 2: reusable lane workflows

These answer: **what is the job family that should run?**

Examples:

- quality
- deep validation
- Airflow integration
- IDP integration
- license compliance

### 4.3 Layer 3: composite actions

These answer: **what common step bundle should be reused across workflows?**

Examples:

- Python bootstrap
- dependency installation
- CI context export
- reference rendering
- artifact upload
- final summary rendering

### 4.4 Layer 4: registries and manifests

These answer: **what are the rules, versions, paths, and memberships?**

Examples:

- which Python versions are supported by the CI matrix
- which paths trigger which workflow
- which lanes are blocking
- which tests belong to which suite and coverage family

### 4.5 Layer 5: tests and renderers

These answer: **is the CI still internally consistent?** and **what documentation or summaries should be generated?**

Examples:

- CI self-check tests
- renderers for workflow input docs
- renderers for ownership data
- renderers for project CI overview
- final summary renderer

---

## 5. Directory structure and what each area means

### 5.1 `.github/workflows/`

This directory contains both the entry workflows and reusable workflows.

A practical maintainer rule:

- if you are changing trigger conditions, manual inputs, or top-level orchestration, start here
- if you are changing an entire lane’s behavior, the reusable workflow is the main place to change it

### 5.2 `ci/actions/`

This directory contains local composite actions.

Use this layer when the same cluster of steps appears in multiple workflows and should be standardized.

This is the correct place for reusable step bundles such as:

- Python setup and caching
- context export
- artifact upload
- rendered documentation generation
- governance validation

### 5.3 `ci/scripts/`

This directory contains the logic that turns raw CI metadata into structured outputs.

Examples include:

- version registry readers
- lane-policy readers
- path-filter readers
- inventory renderers
- summary builders
- static security summarizers
- Airflow bootstrap helpers

If a CI behavior is data-driven or involves structured rendering, it usually belongs here instead of inline shell in YAML.

### 5.4 `ci/config/`

This directory contains registry-like CI configuration.

At the moment it includes:

- version matrix data
- workflow path filter rules
- the core promotion allowlist

This directory is central to maintainability.

### 5.5 `ci/requirements/`

This directory defines dependency groups for different CI lanes.

Separate requirements files help avoid over-installing dependencies in lanes that do not need them.

### 5.6 `ci/bash/`

This directory contains small shell helpers used by runtime-oriented lanes, especially the Airflow surface checks.

### 5.7 `tests/ci/`

This directory is not a random collection of tests. It is the CI contract surface.

It contains:

- governance validation tests
- runtime smoke tests
- matrix tests
- provider and mapping tests
- integration-style tests
- documentation sync tests

The key file in this area is `tests/ci/contract_manifest.py`, because that manifest assigns tests to suites and groupings.

---

## 6. Current workflow inventory and intent

This section explains what each workflow is for and when to use or edit it.

### 6.1 `ci.yml` — manual umbrella gate

This is the operator-facing manual workflow.

It is used when a maintainer wants a controlled, multi-lane validation run before promotion. It resolves shared CI context first and then conditionally invokes several reusable workflows.

The currently exposed manual inputs include:

- `run_deep_validation`
- `run_airflow`
- `run_idp_integration`
- `run_fab_provider_validation`
- `run_nightly_compatibility`
- `run_external_real_validation`
- `run_license_compliance`
- `require_external_secrets`
- `create_review_pr`

This makes `ci.yml` the main umbrella control plane.

It also uses `concurrency` to prevent overlapping runs of the same workflow/reference combination and ends with a final summary job that runs even when earlier lanes fail.

### 6.2 `quality_fast.yml`

This is the fast path-filtered workflow for everyday source changes.

Its job is to provide quick developer feedback without forcing the full heavy matrix every time.

Edit this workflow when the fast-path trigger policy or quality entry behavior needs to change.

### 6.3 `compliance_fast.yml`

This is the fast workflow for licensing, packaging, and compliance-relevant changes.

It is intended to keep compliance checks focused and appropriately triggered.

### 6.4 `ci_self_check.yml`

This is the governance entry workflow.

It exists to validate the CI system itself when CI-related files change.

It should be considered the guardian of CI integrity.

### 6.5 `nightly_compatibility.yml`

This workflow runs the compatibility canary path.

Its purpose is not routine contributor feedback. Its purpose is surveillance for drift against the pinned compatibility matrix.

---

## 7. Reusable lane workflows in detail

### 7.1 `reusable_ci_self_check.yml`

This lane validates the CI system itself.

It checks items such as:

- YAML validity for workflows and action definitions
- registry and renderer compilation
- generated CI reference synchronization
- governance pytest targets
- project CI overview synchronization

This lane is critical whenever you change workflows, CI scripts, registries, or generated CI docs.

### 7.2 `reusable_quality.yml`

This is the main developer-quality lane.

From the current implementation, it includes dedicated jobs for:

- compile smoke
- pytest collection inventory
- Ruff lint
- Ruff format check
- mypy for the package
- mypy for CI tests and helper scripts
- family-based pytest coverage shards
- `pip_audit`
- summary rendering

This lane is intentionally broad but still relatively fast compared with heavier runtime and external validations.

### 7.3 `reusable_deep_validation.yml`

This lane performs broader repository-local validation.

It currently includes:

- test-catalog assignment validation
- compile and import smoke
- matrixed unit and mock tests across declared groups
- dead-code scanning using `vulture`
- a summary job that aggregates the results

This lane is useful when maintainers want stronger assurance without requiring a full external environment.

### 7.4 `reusable_airflow_integration.yml`

This lane bootstraps a real Airflow runtime and validates the package in that environment.

It is where install-time and startup-time problems tend to surface.

Typical behavior includes:

- installing Airflow-compatible dependencies
- setting up Airflow config
- creating test DAGs
- initializing the metadata database
- starting Airflow services
- checking auth surface and selected API behavior

### 7.5 `reusable_airflow_suite.yml`

This is a suite wrapper around Airflow integration runs for multiple Python versions.

Currently it coordinates:

- one run on Python 3.12
- one run on Python 3.13
- one suite-level result summary

Use this wrapper when changing overall Airflow validation policy rather than a single Airflow test step.

### 7.6 `reusable_identity_provider_integration.yml`

This lane validates integration-style LDAP and Entra scenarios without requiring real enterprise production secrets.

It includes support for LDAP bootstrap and LDAP bind smoke before executing broader identity-provider tests.

### 7.7 `reusable_fab_provider_validation.yml`

This lane validates compatibility behavior against the official FAB provider version pinned by the CI registry.

Its goal is drift detection and supportability validation.

### 7.8 `reusable_fab_provider_suite.yml`

This wrapper runs the FAB provider validation lane across Python versions and reports one suite-level result.

### 7.9 `reusable_nightly_compatibility.yml`

This lane is a compatibility canary for pinned Airflow, FAB provider, and Python combinations.

It is not meant to be a contributor-speed gate. It is meant to expose compatibility drift early.

### 7.10 `reusable_external_real_validation.yml`

This is the opt-in lane for validation requiring real external systems or secrets.

Because it depends on environment readiness, it should remain explicitly controlled.

### 7.11 `reusable_license_compliance.yml`

This lane covers release-readiness and supply-chain concerns.

It currently includes areas such as:

- license compliance reporting
- release-readiness checks
- build smoke for distribution artifacts
- isolated install validation
- SBOM generation
- static security checks such as Bandit and Gitleaks

### 7.12 `reusable_review_pr_gate.yml`

This lane evaluates the results of enabled validation lanes and decides whether the repository state is promotable.

It should be understood as a **promotion decision layer**, not a testing layer.

### 7.13 `reusable_open_pr.yml`

This lane creates the review branch and PR when the promotion gate has passed and the workflow configuration allows PR creation.

It relies on the allowlist used for core-only promotion.

---

## 8. Composite actions and when to use them

The repository uses composite actions to keep repeated step bundles consistent across workflows.

### 8.1 Key composite actions currently present

- `bootstrap-python`
- `export-ci-context`
- `install-ldap-build-deps`
- `install-python-deps`
- `render-ci-ownership`
- `render-ci-reference`
- `render-ci-scope-summary`
- `render-ci-workflow-inputs`
- `render-final-ci-summary`
- `render-project-ci-overview`
- `resolve-airflow-constraints`
- `summarize-ci-artifacts`
- `upload-artifact-bundle`
- `validate-ci-governance`

### 8.2 When to create a composite action

Create a composite action when:

- the same step group appears in multiple workflows
- the step group has a stable interface
- you want one place to fix or improve repeated operational logic

Do **not** create a composite action for logic that only appears once or logic that would be clearer as a Python helper script.

### 8.3 Composite action vs reusable workflow

Use a composite action when you want to reuse **steps inside a job**.
Use a reusable workflow when you want to reuse **an entire workflow job structure** with its own inputs, jobs, permissions, and outputs.

That distinction matters for maintainability and is part of the current CI’s design style.

---

## 9. Registry-driven CI behavior

One of the most important aspects of this CI is that it is not controlled only by YAML.

### 9.1 `ci/config/versions.json`

This file is the central version registry.

In the current bundle it defines:

- primary Python: `3.13`
- secondary Python: `3.12`
- deep-validation matrix: `3.12`, `3.13`
- nightly matrix: `3.12`, `3.13`
- default Airflow: `3.1.8`
- nightly Airflow matrix: `3.1.8`
- default FAB provider: `3.5.0`
- nightly FAB provider matrix: `3.5.0`
- lane-specific requirements file paths

When changing supported Python or runtime versions, start here first.

### 9.2 `ci/config/path_filters.json`

This file controls which file changes trigger which fast workflows.

At the moment it defines path filters for:

- `ci_self_check`
- `compliance_fast`
- `quality_fast`

When a path-trigger policy changes, update this file and the workflow behavior that consumes it.

### 9.3 `ci/scripts/ci_lane_policy.py`

This file describes lane metadata such as:

- workflow name
- cadence
- blocking status
- secrets profile
- artifact prefix
- summary group
- maintainer notes

This is the policy inventory for lanes.

### 9.4 `tests/ci/contract_manifest.py`

This file defines test ownership by suite, group, family, thresholds, and coverage target mappings.

For maintainers, this is the most important file when adding or moving CI tests.

---

## 10. How test selection works

The repository does not rely only on raw directory-level `pytest` discovery for the main CI lanes.

Instead, test scope is contract-driven.

### 10.1 Why this matters

A contract-driven manifest gives maintainers:

- explicit suite membership
- more stable coverage grouping
- self-checkable test ownership
- less accidental drift when tests are added or renamed

### 10.2 Main grouping concepts

The CI currently uses concepts such as:

- suite
- family
- group
- coverage threshold
- coverage targets

From the reusable workflows currently present, the main family and group names include areas like:

- `config-permissions-runtime`
- `role-mapping-rbac-compatibility`
- `api-ui-browser-session-observability`
- `provider-backends-and-rate-limits`
- `audit-logging-governance`
- `bootstrap-imports`

### 10.3 Practical maintainer rule

When adding a new file under `tests/ci/`, do not stop at creating the test file.
You must also decide:

- which suite owns it
- whether it belongs to an existing family or group
- whether thresholds or coverage targets need to be updated
- whether summaries or artifacts should expose it differently

---

## 11. Generated CI documentation and governance synchronization

The CI currently treats generated reference material as part of governance.

### 11.1 Generated outputs expected by the current design

The repository includes committed generated artifacts such as:

- `ci/CI_REFERENCE.md`
- `ci/CI_REFERENCE.json`
- `ci/CI_WORKFLOW_INPUTS.md`
- `ci/CI_WORKFLOW_INPUTS.json`
- `ci/CI_OWNERSHIP.json`

The governance action also compares a generated project overview against:

- `docs/CI_OVERVIEW.md`

### 11.2 Why this is important

The `validate-ci-governance` composite action uses direct file comparison against committed outputs.

If a workflow, registry, lane policy, or renderer changes but the generated outputs are not refreshed and committed, the CI self-check lane will fail.

### 11.3 Practical consequence for maintainers

Changing CI code often requires two commits worth of thought in one change set:

1. the actual logic change
2. the regenerated documentation/reference outputs that prove the system is still synchronized

### 11.4 Known operational detail

The governance action expects `docs/CI_OVERVIEW.md` to exist and match the output of `render_project_ci_overview.py`.

If that file is missing or stale, CI self-check will fail.

---

## 12. How to run the CI as a maintainer

### 12.1 Routine contributor path

For ordinary source changes, the repository is designed to rely primarily on the fast workflows triggered by matching path filters.

In practice, this gives fast quality and compliance feedback without forcing every optional heavy lane.

### 12.2 Manual full-gate path

Use `ci.yml` when you want a complete, intentional validation run.

Recommended pre-merge or pre-promotion settings:

- enable deep validation
- enable Airflow
- enable IDP integration
- enable FAB provider validation
- enable license compliance
- leave nightly compatibility disabled unless compatibility canary coverage is needed
- leave external real validation disabled unless real environment coverage is required

### 12.3 External real validation path

Only enable external real validation when the target secrets and backing services are available and intentionally being tested.

If you want missing secret state to fail loudly instead of skipping, use the `require_external_secrets` flag.

### 12.4 Promotion path

When a manual CI run is intended to create a promotion review branch and PR, keep `create_review_pr=true` and ensure the run is started from a non-`main` branch.

The review PR gate is designed to run only after enabled gates complete and to create the PR only when promotion criteria are satisfied.

---

## 13. How to read CI results efficiently

Do not start with raw logs unless the summaries are insufficient.

### 13.1 Recommended reading order

1. workflow-level summary in GitHub Actions
2. lane summary job such as `summary`, `summarize_quality`, or `final_summary`
3. uploaded artifacts from the failed lane
4. raw job logs only after the artifacts and summaries narrow the likely cause

### 13.2 What the final summary is for

The final summary job exists so the maintainer gets one high-level view of all lanes, including skipped, failed, and successful states.

### 13.3 What artifacts are for

Artifacts provide evidence that is easier to inspect than plain logs, for example:

- coverage XML
- JUnit XML
- rendered scope summaries
- static security outputs
- compatibility tables
- Airflow runtime logs
- LDAP container logs

---

## 14. Lane blocking model and promotion logic

The current CI lane policy defines which lanes are considered blocking and which are informational or optional.

### 14.1 Lanes currently marked blocking in lane policy

The lane-policy registry currently marks these lanes as blocking:

- `quality`
- `deep_validation`
- `airflow_integration`
- `identity_provider_integration`
- `fab_provider_validation`
- `license_compliance`

### 14.2 Lanes currently non-blocking or optional by policy

The current policy marks these as non-blocking in lane metadata:

- `ci_self_check`
- `nightly_compatibility`
- `external_real_validation`

That does not mean they are unimportant. It means they do not represent the same merge/promotion gate semantics as the main blocking validation lanes.

### 14.3 Promotion gate design

A useful mental model is:

- validation lanes produce evidence
- the review PR gate interprets enabled results
- the open PR workflow performs the promotion action
- the final summary reports the overall picture

This separation is clean and intentional.

---

## 15. Repository settings and admin responsibilities

### 15.1 GitHub Actions settings

Administrators should ensure that repository settings allow the workflows to use local actions and local reusable workflows.

### 15.2 Required checks strategy

Take care when making path-filtered workflows required in branch protection.

If a workflow is skipped because its path filters did not match, GitHub can leave that required check pending, which may block merges. This is an important operational constraint when designing required checks for fast filtered workflows. citeturn397308search2

### 15.3 Concurrency expectations

The manual umbrella workflow uses `concurrency` to avoid overlapping runs for the same workflow/reference group. GitHub documents `concurrency` specifically for controlling simultaneous runs or jobs when you need to prevent duplicate execution. citeturn397308search3turn397308search6

### 15.4 Secrets discipline

Separate secrets by lane purpose:

- no-secrets lanes should stay no-secrets
- test-service integration secrets should stay isolated from real external secrets
- real external validation should remain clearly opt-in

### 15.5 Artifact retention and storage

As the CI grows, administrators should periodically review artifact retention policy because the design intentionally produces many helpful artifacts.

---

## 16. How to add a new CI test

This is one of the most common maintenance tasks.

### 16.1 Minimum required steps

1. Create the test file under `tests/ci/`.
2. Register the test in `tests/ci/contract_manifest.py`.
3. Assign it to the correct suite.
4. Add or adjust family/group membership if needed.
5. Adjust thresholds or coverage targets if needed.
6. Run the relevant local checks.
7. Update rendered CI docs if the change affects documented CI scope or governance outputs.

### 16.2 Decide the correct owning suite

Use these principles:

- use `ci_self_check` for CI-governance or CI-registry correctness
- use `quality` for repository-local correctness, unit behavior, and fast contract validation
- use `deep_validation` group participation for broader, sharded validation scope
- use `airflow_integration` when the test needs a real Airflow runtime
- use `identity_provider_integration` for LDAP/Entra integration-style flows
- use `fab_provider_validation` when comparing against official FAB provider behavior
- use `external_real_validation` only when the test truly requires real external systems or secrets

### 16.3 Helpful local commands

```bash
python ci/scripts/list_contract_tests.py --suite quality
python ci/scripts/list_contract_tests.py --group config-permissions-runtime
python ci/scripts/list_contract_tests.py --family config-permissions-runtime
python ci/scripts/list_contract_tests.py --family config-permissions-runtime --threshold
python ci/scripts/list_contract_tests.py --family config-permissions-runtime --cov-targets
```

### 16.4 Common mistake to avoid

Do not add a test file and assume the workflow will “just pick it up correctly.”

In this CI, silent drift is exactly what the contract manifest is designed to prevent.

---

## 17. How to add a new coverage family or deep-validation group

Create a new family or group when the new area represents a real architectural concern that deserves separate ownership, thresholding, or reporting.

### 17.1 Steps

1. Update `tests/ci/contract_manifest.py`.
2. Add the new family or group definition.
3. Assign tests to it.
4. Set realistic thresholds.
5. Set correct coverage targets.
6. Update any workflow matrix that enumerates the family or group explicitly.
7. Re-run local validation and CI self-check paths.

### 17.2 Design guideline

Avoid creating tiny groups that exist only because a single new test was added. Prefer meaningful architectural groupings that maintainers will still understand later.

---

## 18. How to add a completely new CI lane

A new lane is justified when the new validation has materially different runtime needs, cadence, permissions, or secrets requirements.

Examples might include:

- documentation build validation
- package provenance verification
- performance regression detection
- platform-specific runtime testing
- benchmark or scalability tracking

### 18.1 Required implementation steps

1. Create a reusable workflow under `.github/workflows/`.
2. Decide whether it also needs a top-level entry workflow or whether it is only called from `ci.yml`.
3. Add lane metadata to `ci/scripts/ci_lane_policy.py`.
4. Update `ci/config/path_filters.json` if it needs filtered entrypoints.
5. Update `ci/config/versions.json` if it depends on new version registry values.
6. Add composite actions only if repeated step bundles justify them.
7. Add tests for the new lane’s registries, summaries, or governance behavior if appropriate.
8. Wire the lane into `ci.yml` if it should be controllable from the umbrella workflow.
9. Decide whether it should affect the promotion gate.
10. Regenerate CI reference outputs and run self-check.

### 18.2 Promotion decision you must make explicitly

For every new lane, decide whether it is:

- blocking
- informational
- scheduled-only
- manual-only
- secret-backed and skippable

Do not leave this ambiguous.

---

## 19. How to change version support safely

### 19.1 Start with `ci/config/versions.json`

This registry is the correct first edit location for Python, Airflow, and FAB provider matrix changes.

### 19.2 Then verify consumers

After updating the version registry, verify:

- manual umbrella inputs still make sense
- reusable workflows consume the values correctly
- compatibility lanes still reflect intended support policy
- docs and summaries still describe the correct versions

### 19.3 Then run targeted validations

At minimum, re-run:

- CI self-check
- quality
- affected integration or compatibility lanes

---

## 20. How to change path filters safely

### 20.1 Edit the registry, not only the workflow YAML

Path filter rules are centralized in `ci/config/path_filters.json`.

### 20.2 Validate the operational effect

When changing path filters, confirm three things:

- the intended file changes now trigger the correct workflow
- unrelated file changes do not trigger the workflow unnecessarily
- required check strategy in branch protection still makes sense

### 20.3 Why this matters

Path-filtered workflows are excellent for speed, but they add operational nuance to branch protection and merge gating. GitHub’s documentation explicitly warns that skipped required workflows can remain pending when skipped by path filtering. citeturn397308search2

---

## 21. How to change CI governance safely

CI governance changes are the easiest place to introduce accidental drift.

### 21.1 Typical governance-sensitive changes

- changing workflow inputs
- changing lane policy metadata
- changing path filters
- changing render scripts
- changing inventory calculations
- changing expected committed CI reference files

### 21.2 Local validation sequence

A safe local sequence is:

```bash
python -m py_compile \
  ci/scripts/ci_catalog_registry.py \
  ci/scripts/ci_lane_policy.py \
  ci/scripts/ci_summary_catalog.py \
  ci/scripts/ci_versions.py \
  ci/scripts/ci_path_filters.py \
  ci/scripts/render_ci_inventory.py \
  ci/scripts/render_ci_reference.py \
  ci/scripts/render_ci_ownership.py \
  ci/scripts/render_ci_scope_summary.py \
  ci/scripts/render_final_ci_summary.py \
  ci/scripts/render_project_ci_overview.py

pytest -q \
  tests/ci/test_ci_lane_policy.py \
  tests/ci/test_ci_catalog_registry.py \
  tests/ci/test_ci_versions_registry.py \
  tests/ci/test_ci_path_filters_registry.py \
  tests/ci/test_render_final_ci_summary.py \
  tests/ci/test_ci_reference_sync.py \
  tests/ci/test_ci_ownership_sync.py \
  tests/ci/test_ci_workflow_inputs_sync.py \
  tests/ci/test_project_ci_overview_sync.py
```

### 21.3 Regeneration commands

A practical regeneration sequence is:

```bash
python ci/scripts/render_ci_reference.py \
  --repo-root . \
  --output-md ci/CI_REFERENCE.md \
  --output-json ci/CI_REFERENCE.json

python ci/scripts/render_ci_workflow_inputs.py \
  --repo-root . \
  --output-md ci/CI_WORKFLOW_INPUTS.md \
  --output-json ci/CI_WORKFLOW_INPUTS.json

python ci/scripts/render_ci_ownership.py \
  --output-json ci/CI_OWNERSHIP.json

python ci/scripts/render_project_ci_overview.py \
  --repo-root . \
  --output-md docs/CI_OVERVIEW.md
```

---

## 22. Failure triage guide

### 22.1 If `ci_self_check` fails

Most likely causes:

- generated references are stale
- workflow inputs changed but generated input docs were not refreshed
- path-filter registry drifted from expectation
- `docs/CI_OVERVIEW.md` is missing or out of sync
- CI render scripts no longer compile

### 22.2 If `quality` fails

Most likely causes:

- lint or format regression
- mypy regression
- family coverage threshold failure
- package vulnerability reported by `pip_audit`
- newly added tests were not registered or grouped correctly

### 22.3 If `deep_validation` fails

Most likely causes:

- missing test assignment in the manifest
- import smoke failure
- coverage failure in one shard
- dead code or unreachable code reported by `vulture`

### 22.4 If `airflow_suite` fails

Most likely causes:

- runtime bootstrap issue
- Airflow config mismatch
- provider installation or import issue
- server startup issue
- auth surface regression

### 22.5 If `identity_provider_integration` fails

Most likely causes:

- LDAP bootstrap or bind smoke failure
- IDP test assumptions drifted
- dependency issue around LDAP support

### 22.6 If `fab_provider_validation` fails

Most likely causes:

- official FAB provider behavior drift
- mirror vocabulary mismatch
- compatibility expectation mismatch

### 22.7 If `license_compliance` fails

Most likely causes:

- build regression
- packaging or metadata issue
- static security finding
- license or SBOM generation issue

### 22.8 If the review PR is not created

Most likely causes:

- one enabled blocking gate failed
- the workflow ran from `main`
- `create_review_pr` was disabled
- the gate lane interpreted an enabled result as non-promotable

---

## 23. Maintainer checklist before committing CI changes

- [ ] changed the correct layer: workflow, reusable workflow, composite action, registry, script, or manifest
- [ ] updated `tests/ci/contract_manifest.py` for any new or moved test
- [ ] updated `ci/scripts/ci_lane_policy.py` if lane metadata changed
- [ ] updated `ci/config/versions.json` if support policy changed
- [ ] updated `ci/config/path_filters.json` if trigger policy changed
- [ ] regenerated committed CI reference files
- [ ] regenerated `docs/CI_OVERVIEW.md`
- [ ] ran CI self-check targets locally where appropriate
- [ ] reviewed required-check and branch-protection impact
- [ ] reviewed secrets and permissions impact
- [ ] ensured artifacts and summaries remain readable

---

## 24. Recommended future enhancements

The current CI design is already strong, but the next practical enhancements could include:

### 24.1 High-value additions

- a docs build and link-check lane
- provenance or attestation validation for build artifacts
- a performance or latency regression lane for critical auth flows
- a non-blocking dependency freshness lane
- clearer root-level maintainer shortcuts such as `make ci-self-check` or `nox` sessions mirroring core lanes

### 24.2 Documentation improvements

- optionally render a dedicated lane-ownership matrix for maintainers
- optionally render a contributor quick-start CI map from the same registry data
- optionally keep `CI_README.md` partially generated from lane policy metadata if you want stricter long-term synchronization

---

## 25. Quick reference map

### Where do I change version support?

`ci/config/versions.json`

### Where do I change path triggers?

`ci/config/path_filters.json`

### Where do I change lane blocking policy?

`ci/scripts/ci_lane_policy.py`

### Where do I add a new CI test?

`tests/ci/contract_manifest.py`

### Where do I change the manual umbrella workflow?

`.github/workflows/ci.yml`

### Where do I change quality-lane behavior?

`.github/workflows/reusable_quality.yml`

### Where do I change CI governance behavior?

`.github/workflows/reusable_ci_self_check.yml`
`ci/actions/validate-ci-governance/action.yml`

### Where do I change PR promotion logic?

`.github/workflows/reusable_review_pr_gate.yml`
`.github/workflows/reusable_open_pr.yml`

### Where do I regenerate CI reference outputs?

Use the render scripts under `ci/scripts/`.

### Which file is easy to forget but important for governance?

`docs/CI_OVERVIEW.md`

---

## 26. Final takeaway

This CI is not just a set of workflows. It is a structured system with clear layering:

- entry workflows for timing and triggering
- reusable workflows for lane orchestration
- composite actions for repeated step bundles
- registries for policy and version truth
- contract manifests for test ownership
- scripts for rendering, summarizing, and governance validation
- committed generated docs for self-documenting CI behavior

That architecture is a strength.

The main maintainer discipline needed to keep it healthy is this:

**change the correct source of truth first, then regenerate CI documentation, then let the self-check lane prove the system is still synchronized.**
