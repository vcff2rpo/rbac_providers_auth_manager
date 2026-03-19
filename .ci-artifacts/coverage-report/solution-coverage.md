# Solution coverage report

- covered capabilities: 32/32
- coverage percent: 100.0%

## Coverage families and thresholds
- config-runtime: threshold 45% across 6 file(s)
- rbac-mirror: threshold 35% across 4 file(s)
- browser-flows: threshold 40% across 3 file(s)
- provider-simulations: threshold 35% across 2 file(s)
- bootstrap-imports: threshold 5% across 1 file(s)

## Covered capability areas
- Import/bootstrap smoke
- Config matrix parsing
- Config runtime loading
- permissions.ini scenario matrix
- RBAC authorization policy
- API surface contracts (HTML, JSON, cookie behavior)
- Browser login/logout/token routes
- JWT/token flow
- LDAP backend simulation
- LDAP live bind/search integration
- Entra backend simulation
- Entra callback/browser flow integration
- Identity mapping matrix
- FAB static mirror
- FAB official provider mirror
- Runtime security/logging behavior
- Negative-path runtime behavior
- Airflow auth manager import
- Airflow DB migrate smoke
- Airflow API health/version
- Protected Airflow API rejects anonymous access
- Hello-world DAG discovery
- Hello-world DAG execution
- Nightly rolling compatibility matrix
- Artifact summarization per CI lane
- Coverage thresholds per test family
- CI runtime logic centralized in reusable repo scripts
- permissions.ini fixture corpus and parametrized scenario tests
- Role vocabulary drift guard
- Real DB-backed role persistence integration
- Real Entra tenant callback
- Real enterprise LDAP/AD schema validation

## Remaining gaps
- none
