# permissions.ini scenario corpus

This directory contains fixture-driven `permissions.ini` scenarios used by the
CI contract tests.

Structure:
- `load_config/`: fixtures validated through `load_config()`
- `role_mapping/`: fixtures validated through `parse_role_mapping_raw()`

Each `.ini` file has a sidecar `.json` metadata file with:
- `kind`: `load_config` or `role_mapping`
- `expect`: `success` or `error`
- optional `env`: environment variables required by the scenario
- optional `assertions`: keys validated by the parametrized tests

Current load-config coverage includes:
- LDAP-only strict mode
- Entra-only strict mode
- dual-provider strict mode
- dual-provider permissive/fallback mode
- admin wildcard role behavior
- redis backend selection
- JWT cookie aliases
- UI status customization
- role filters
- self-signed LDAP override guardrails
