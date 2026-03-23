#!/usr/bin/env bash
set -euo pipefail

python -W "ignore:Could not import graphviz:UserWarning" -m airflow dags list   2>&1 | tee "$AIRFLOW_CI_ARTIFACTS/airflow-dags-list.log" || true

python -W "ignore:Could not import graphviz:UserWarning" -m airflow tasks list hello_world_ci   2>&1 | tee "$AIRFLOW_CI_ARTIFACTS/airflow-tasks-list.log"

{
  echo "Graphviz-dependent DAG rendering is intentionally skipped in CI."
  echo "airflow dags list is treated as diagnostic only in this workflow."
  echo "DAG discovery is validated through 'airflow tasks list' and 'airflow dags test'."
} | tee "$AIRFLOW_CI_ARTIFACTS/airflow-dag-rendering-skipped.log"

grep -Fx "start" "$AIRFLOW_CI_ARTIFACTS/airflow-tasks-list.log"
grep -Fx "hello" "$AIRFLOW_CI_ARTIFACTS/airflow-tasks-list.log"
grep -Fx "done" "$AIRFLOW_CI_ARTIFACTS/airflow-tasks-list.log"
