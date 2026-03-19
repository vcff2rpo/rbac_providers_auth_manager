#!/usr/bin/env bash
set -euo pipefail

LOGIN_HTTP_CODE=$(curl -sS -o "$AIRFLOW_CI_ARTIFACTS/auth-login.html" -w "%{http_code}" http://127.0.0.1:8080/auth/login/)
PROTECTED_HTTP_CODE=$(curl -sS -o "$AIRFLOW_CI_ARTIFACTS/protected-dags.txt" -w "%{http_code}" http://127.0.0.1:8080/api/v2/dags)
LOGOUT_HTTP_CODE=$(curl -sS -o /dev/null -w "%{http_code}" http://127.0.0.1:8080/auth/logout)

echo "login_http_code=${LOGIN_HTTP_CODE}" | tee "$AIRFLOW_CI_ARTIFACTS/auth-surface.log"
echo "protected_http_code=${PROTECTED_HTTP_CODE}" | tee -a "$AIRFLOW_CI_ARTIFACTS/auth-surface.log"
echo "logout_http_code=${LOGOUT_HTTP_CODE}" | tee -a "$AIRFLOW_CI_ARTIFACTS/auth-surface.log"

test "$LOGIN_HTTP_CODE" = "200"
grep -E "Sign In|LOGIN|login" "$AIRFLOW_CI_ARTIFACTS/auth-login.html"
case "$PROTECTED_HTTP_CODE" in
  401|403) ;;
  *) echo "Expected 401 or 403 for anonymous protected endpoint, got ${PROTECTED_HTTP_CODE}" >&2; exit 1 ;;
esac
case "$LOGOUT_HTTP_CODE" in
  302|307) ;;
  *) echo "Expected redirect status for logout, got ${LOGOUT_HTTP_CODE}" >&2; exit 1 ;;
esac
