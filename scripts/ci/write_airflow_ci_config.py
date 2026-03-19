from __future__ import annotations

import configparser
import os
from pathlib import Path


def main() -> None:
    cfg_path = Path(os.environ["AIRFLOW_CONFIG"])
    cfg_path.parent.mkdir(parents=True, exist_ok=True)

    cfg = configparser.ConfigParser()
    if cfg_path.exists():
        cfg.read(cfg_path)

    for section in ("core", "database", "api_auth", "api", "logging"):
        if section not in cfg:
            cfg[section] = {}

    cfg["core"]["auth_manager"] = (
        "rbac_providers_auth_manager.auth_manager.RbacAuthManager"
    )
    cfg["core"]["itim_ldap_permissions_ini"] = os.environ["AIRFLOW_PERMISSIONS_INI"]
    cfg["core"]["plugins_folder"] = os.environ["AIRFLOW_PLUGINS_DIR"]
    cfg["core"]["dags_folder"] = os.environ["AIRFLOW_DAGS_DIR"]
    cfg["core"]["lazy_load_plugins"] = "False"
    cfg["core"]["load_examples"] = "False"
    cfg["database"]["sql_alchemy_conn"] = f"sqlite:///{os.environ['AIRFLOW_DB_PATH']}"
    cfg["api"]["base_url"] = "http://127.0.0.1:8080"
    cfg["logging"]["logging_level"] = "DEBUG"

    cfg["api_auth"]["jwt_secret"] = (
        "ci-only-jwt-secret-not-for-production-change-me-0123456789"
    )
    cfg["api_auth"]["jwt_algorithm"] = "HS512"
    cfg["api_auth"]["jwt_audience"] = "urn:airflow.apache.org:task"

    with cfg_path.open("w", encoding="utf-8") as fh:
        cfg.write(fh)

    print(f"patched airflow.cfg at {cfg_path}")
    print(cfg_path.read_text(encoding="utf-8"))


if __name__ == "__main__":
    main()
