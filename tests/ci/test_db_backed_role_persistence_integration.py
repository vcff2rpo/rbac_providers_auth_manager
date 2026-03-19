from __future__ import annotations

import os
import sqlite3
from pathlib import Path

import pytest


EXPECTED_TABLES = {
    "ab_role",
    "ab_permission",
    "ab_view_menu",
    "ab_permission_view",
    "ab_permission_view_role",
}


def _sqlite_path_from_env() -> Path:
    raw = os.environ.get("REAL_AIRFLOW_DB_URI") or os.environ.get("AIRFLOW__DATABASE__SQL_ALCHEMY_CONN")
    if raw and raw.startswith("sqlite:///"):
        return Path(raw.removeprefix("sqlite:///"))
    path = os.environ.get("AIRFLOW_DB_PATH")
    if path:
        return Path(path)
    pytest.skip("No sqlite-backed Airflow metadata DB path is available for DB persistence validation")


def test_db_backed_roles_are_persisted_in_airflow_metadata_db() -> None:
    db_path = _sqlite_path_from_env()
    assert db_path.exists(), f"Airflow DB does not exist: {db_path}"

    conn = sqlite3.connect(db_path)
    try:
        table_rows = conn.execute(
            "SELECT name FROM sqlite_master WHERE type='table'"
        ).fetchall()
        tables = {row[0] for row in table_rows}
        print("sqlite_tables=", sorted(tables))
        assert EXPECTED_TABLES.issubset(tables)

        role_rows = conn.execute("SELECT name FROM ab_role ORDER BY name").fetchall()
        roles = {row[0] for row in role_rows}
        print("persisted_roles=", sorted(roles))

        expected_roles = {
            item.strip()
            for item in os.environ.get("REAL_EXPECTED_DB_ROLES", "Admin,Op,User,Viewer").split(",")
            if item.strip()
        }
        assert expected_roles.issubset(roles)

        association_count = conn.execute(
            "SELECT COUNT(*) FROM ab_permission_view_role"
        ).fetchone()[0]
        print("permission_view_role_count=", association_count)
        assert association_count > 0
    finally:
        conn.close()
