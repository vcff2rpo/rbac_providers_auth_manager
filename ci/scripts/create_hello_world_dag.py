from __future__ import annotations

import os
from pathlib import Path

DAG_TEXT = """from __future__ import annotations
from datetime import datetime
from airflow import DAG
from airflow.operators.empty import EmptyOperator

with DAG(
    dag_id="hello_world_ci",
    start_date=datetime(2024, 1, 1),
    schedule=None,
    catchup=False,
    tags=["ci", "hello-world"],
) as dag:
    start = EmptyOperator(task_id="start")
    hello = EmptyOperator(task_id="hello")
    done = EmptyOperator(task_id="done")
    start >> hello >> done
"""


def main() -> None:
    dags_dir = Path(os.environ["AIRFLOW_DAGS_DIR"])
    dags_dir.mkdir(parents=True, exist_ok=True)
    dag_path = dags_dir / "hello_world_ci.py"
    dag_path.write_text(DAG_TEXT, encoding="utf-8")
    print(f"wrote DAG fixture to {dag_path}")
    print(dag_path.read_text(encoding="utf-8"))


if __name__ == "__main__":
    main()
