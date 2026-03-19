# permissions.ini scenario corpus

This directory contains fixture-driven permissions.ini scenarios used by
`tests/ci/test_permissions_ini_scenarios.py`.

Structure:
- `load_config/`: fixtures validated through `load_config()`
- `role_mapping/`: fixtures validated through `parse_role_mapping_raw()`

Each `.ini` file has a sidecar `.json` metadata file with:
- `kind`: `load_config` or `role_mapping`
- `expect`: `success` or `error`
- optional `env`: environment variables required by the scenario
- optional `assertions`: keys validated by the parametrized tests
