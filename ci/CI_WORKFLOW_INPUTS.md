# CI workflow inputs

This file is generated from workflow YAML and summarizes reusable-workflow defaults plus manual entrypoint inputs.

## Reusable workflow inputs

### reusable airflow integration

- workflow: `reusable_airflow_integration`
- path: `.github/workflows/reusable_airflow_integration.yml`

| Input | Type | Required | Default | Description |
| --- | --- | --- | --- | --- |
| airflow-version | string | false | 3.1.8 | Airflow version to install |
| package-name | string | false | rbac_providers_auth_manager | Python package name |
| python-version | string | true |  | Python version for integration test |

### reusable airflow suite

- workflow: `reusable_airflow_suite`
- path: `.github/workflows/reusable_airflow_suite.yml`

| Input | Type | Required | Default | Description |
| --- | --- | --- | --- | --- |
| airflow-version | string | false | 3.1.8 | Airflow version to install |
| package-name | string | false | rbac_providers_auth_manager | Python package name |
| py312-version | string | false | 3.12 | Python version for the first Airflow integration lane |
| py313-version | string | false | 3.13 | Python version for the second Airflow integration lane |

### reusable CI self check

- workflow: `reusable_ci_self_check`
- path: `.github/workflows/reusable_ci_self_check.yml`

| Input | Type | Required | Default | Description |
| --- | --- | --- | --- | --- |
| python-version | string | false | 3.13 |  |

### reusable deep validation

- workflow: `reusable_deep_validation`
- path: `.github/workflows/reusable_deep_validation.yml`

| Input | Type | Required | Default | Description |
| --- | --- | --- | --- | --- |
| coverage-min | number | false | 25 | Minimum acceptable line coverage percent for unit/mock tests |
| package-name | string | false | rbac_providers_auth_manager | Python package name |
| python-versions | string | false | ["3.12", "3.13"] | JSON array of Python versions for the unit/mock test matrix |

### reusable external real validation

- workflow: `reusable_external_real_validation`
- path: `.github/workflows/reusable_external_real_validation.yml`

| Input | Type | Required | Default | Description |
| --- | --- | --- | --- | --- |
| airflow-version | string | false | 3.1.8 | Airflow version to install for DB-backed validation |
| fab-provider-version | string | false | 3.5.0 | FAB provider version for DB-backed validation |
| package-name | string | false | rbac_providers_auth_manager | Python package name |
| python-version | string | false | 3.13 | Python version for external validation |
| require-external-secrets | boolean | false | false | Fail instead of skip when external LDAP/Entra secrets are missing |

### reusable FAB provider validation suite

- workflow: `reusable_fab_provider_suite`
- path: `.github/workflows/reusable_fab_provider_suite.yml`

| Input | Type | Required | Default | Description |
| --- | --- | --- | --- | --- |
| airflow-version | string | false | 3.1.8 | Airflow version to install for provider mirror validation |
| fab-provider-version | string | false | 3.5.0 | apache-airflow-providers-fab version to validate against |
| package-name | string | false | rbac_providers_auth_manager | Python package name |
| py312-version | string | false | 3.12 | Python version for first FAB provider validation lane |
| py313-version | string | false | 3.13 | Python version for second FAB provider validation lane |

### reusable FAB provider mirror validation

- workflow: `reusable_fab_provider_validation`
- path: `.github/workflows/reusable_fab_provider_validation.yml`

| Input | Type | Required | Default | Description |
| --- | --- | --- | --- | --- |
| airflow-version | string | false | 3.1.8 | Airflow version to install for provider mirror validation |
| fab-provider-version | string | false | 3.5.0 | apache-airflow-providers-fab version to validate against |
| package-name | string | false | rbac_providers_auth_manager | Python package name |
| python-version | string | false | 3.13 | Python version for provider mirror validation |

### reusable identity provider integration

- workflow: `reusable_identity_provider_integration`
- path: `.github/workflows/reusable_identity_provider_integration.yml`

| Input | Type | Required | Default | Description |
| --- | --- | --- | --- | --- |
| package-name | string | false | rbac_providers_auth_manager | Python package name |
| python-version | string | false | 3.13 | Python version for identity-provider integration tests |

### reusable license compliance

- workflow: `reusable_license_compliance`
- path: `.github/workflows/reusable_license_compliance.yml`

| Input | Type | Required | Default | Description |
| --- | --- | --- | --- | --- |
| package-name | string | false | rbac_providers_auth_manager | Python package name |
| python-version | string | false | 3.13 | Python version for compliance tooling |

### reusable nightly compatibility

- workflow: `reusable_nightly_compatibility`
- path: `.github/workflows/reusable_nightly_compatibility.yml`

| Input | Type | Required | Default | Description |
| --- | --- | --- | --- | --- |
| airflow-versions | string | false | ["3.1.8"] | JSON array of Airflow versions |
| fab-provider-versions | string | false | ["3.5.0"] | JSON array of FAB provider versions |
| package-name | string | false | rbac_providers_auth_manager | Python package name |
| python-versions | string | false | ["3.12", "3.13"] | JSON array of Python versions |

### reusable open pr

- workflow: `reusable_open_pr`
- path: `.github/workflows/reusable_open_pr.yml`

| Input | Type | Required | Default | Description |
| --- | --- | --- | --- | --- |
| airflow_result | string | false | unknown |  |
| base_branch | string | false | main |  |
| core_only_manifest | string | false | ci/config/core_promotion_allowlist.txt |  |
| deep_validation_result | string | false | unknown |  |
| external_real_validation_result | string | false | unknown |  |
| fab_provider_result | string | false | unknown |  |
| idp_result | string | false | unknown |  |
| license_compliance_result | string | false | unknown |  |
| nightly_compatibility_result | string | false | unknown |  |
| pr_title | string | false | Review: feature-branch ready for main |  |
| quality_result | string | false | unknown |  |
| review_branch_prefix | string | false | ready/feature-branch |  |
| run_url | string | false |  |  |
| source_branch | string | false | feature-branch |  |
| source_sha | string | false |  |  |

### reusable quality

- workflow: `reusable_quality`
- path: `.github/workflows/reusable_quality.yml`

| Input | Type | Required | Default | Description |
| --- | --- | --- | --- | --- |
| package-name | string | false | rbac_providers_auth_manager | Python package name |
| python-version | string | false | 3.13 | Python version for the quality lane |

### reusable review PR gate

- workflow: `reusable_review_pr_gate`
- path: `.github/workflows/reusable_review_pr_gate.yml`

| Input | Type | Required | Default | Description |
| --- | --- | --- | --- | --- |
| airflow-enabled | boolean | false | false |  |
| airflow-result | string | false | skipped |  |
| airflow-suite-result | string | false | skipped |  |
| base-branch | string | false | main |  |
| create-review-pr | boolean | false | true |  |
| deep-validation-enabled | boolean | false | false |  |
| deep-validation-result | string | false | skipped |  |
| external-real-validation-enabled | boolean | false | false |  |
| external-real-validation-result | string | false | skipped |  |
| fab-provider-enabled | boolean | false | false |  |
| fab-provider-result | string | false | skipped |  |
| fab-provider-suite-result | string | false | skipped |  |
| idp-enabled | boolean | false | false |  |
| idp-result | string | false | skipped |  |
| license-compliance-enabled | boolean | false | false |  |
| license-compliance-result | string | false | skipped |  |
| nightly-compatibility-enabled | boolean | false | false |  |
| nightly-compatibility-result | string | false | skipped |  |
| pr-title | string | false | Promotion: core-only plugin ready for main |  |
| quality-result | string | false | unknown |  |
| review-branch-prefix | string | false | ready/core |  |
| run-url | string | false |  |  |
| source-branch | string | false | feature-branch |  |
| source-sha | string | false |  |  |

## Manual entrypoint inputs

### manual CI gate

- workflow: `ci`
- path: `.github/workflows/ci.yml`

| Input | Type | Required | Default | Description |
| --- | --- | --- | --- | --- |
| create_review_pr | boolean | true | true | Create a new core-only promotion branch and PR to main only after all enabled gates succeed |
| require_external_secrets | boolean | true | false | Fail instead of skip when external LDAP/Entra variables are missing |
| run_airflow | boolean | true | true | Run Airflow installation and integration smoke tests |
| run_deep_validation | boolean | true | true | Run deep validation unit, mock, coverage, and dead-code jobs |
| run_external_real_validation | boolean | true | false | Run optional DB-backed and real external identity validation lane |
| run_fab_provider_validation | boolean | true | true | Run official FAB provider 3.5.0 mirror validation |
| run_idp_integration | boolean | true | true | Run LDAP and Entra integration-style tests |
| run_license_compliance | boolean | true | true | Run OSS license, SBOM, and static security compliance lane |
| run_nightly_compatibility | boolean | true | false | Run scheduled-style compatibility matrix in manual CI |

### nightly compatibility

- workflow: `nightly_compatibility`
- path: `.github/workflows/nightly_compatibility.yml`

| Input | Type | Required | Default | Description |
| --- | --- | --- | --- | --- |
| - | - | - | - | No workflow_dispatch inputs declared. |
