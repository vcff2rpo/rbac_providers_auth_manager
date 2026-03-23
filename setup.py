# mypy: ignore-errors
from __future__ import annotations

from pathlib import Path

from setuptools import setup

ROOT = Path(__file__).resolve().parent


def discover_packages() -> list[str]:
    packages = ["rbac_providers_auth_manager"]
    for init_file in sorted(ROOT.glob("*/__init__.py")):
        package_name = init_file.parent.name
        if package_name == "tests":
            continue
        packages.append(f"rbac_providers_auth_manager.{package_name}")
    return packages


setup(
    packages=discover_packages(),
    package_dir={"rbac_providers_auth_manager": "."},
    package_data={
        "rbac_providers_auth_manager": [
            "py.typed",
            "config_runtime/permissions.ini",
            "ui/templates/*.html",
            "ui/static/*.css",
        ]
    },
    include_package_data=True,
)
