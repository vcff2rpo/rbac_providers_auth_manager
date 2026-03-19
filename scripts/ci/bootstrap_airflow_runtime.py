from __future__ import annotations

import os
import shutil
import zipfile
from pathlib import Path

ALLOWED_TOP_LEVEL = (
    "__init__.py",
    "auth_manager.py",
    "config.py",
    "api",
    "authorization",
    "compatibility",
    "config_runtime",
    "core",
    "entrypoints",
    "identity",
    "providers",
    "runtime",
    "services",
    "ui",
)


def main() -> None:
    pkg = os.environ["PACKAGE_NAME"]
    zip_path = Path(os.environ["AIRFLOW_PLUGIN_ZIP"])
    permissions_dst = Path(os.environ["AIRFLOW_PERMISSIONS_INI"])
    build_root = Path(os.environ["RUNNER_TEMP"]) / "plugin-build" / pkg

    if build_root.exists():
        shutil.rmtree(build_root)
    build_root.mkdir(parents=True, exist_ok=True)

    for name in ALLOWED_TOP_LEVEL:
        src = Path(name)
        if not src.exists():
            continue
        dst = build_root / name
        if src.is_dir():
            shutil.copytree(src, dst, dirs_exist_ok=True)
        else:
            dst.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(src, dst)

    permission_candidates = (
        Path("config_runtime/permissions.ini"),
        Path("permissions.ini"),
        build_root / "config_runtime" / "permissions.ini",
    )
    for candidate in permission_candidates:
        if candidate.exists():
            permissions_dst.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(candidate, permissions_dst)
            break
    else:
        raise SystemExit("Could not locate permissions.ini for staging")

    zip_path.parent.mkdir(parents=True, exist_ok=True)
    with zipfile.ZipFile(zip_path, "w", compression=zipfile.ZIP_DEFLATED) as zf:
        for path in sorted(build_root.rglob("*")):
            arcname = Path(pkg) / path.relative_to(build_root)
            zf.write(path, arcname)

    print(f"staged plugin archive into {zip_path}")
    print(f"staged permissions.ini into {permissions_dst}")


if __name__ == "__main__":
    main()
