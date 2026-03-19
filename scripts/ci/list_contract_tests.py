from __future__ import annotations

import argparse
import importlib
import sys
from pathlib import Path
from types import ModuleType

REPO_ROOT = Path(__file__).resolve().parents[2]


def _load_contract_manifest() -> ModuleType:
    if str(REPO_ROOT) not in sys.path:
        sys.path.insert(0, str(REPO_ROOT))
    return importlib.import_module("tests.ci.contract_manifest")


SUITES = [
    "quality",
    "airflow_integration",
    "identity_provider_integration",
    "fab_provider_validation",
    "external_real_validation",
]
GROUPS = ["config-runtime", "authorization-routes", "provider-simulations"]


def main() -> None:
    manifest = _load_contract_manifest()

    parser = argparse.ArgumentParser()
    parser.add_argument("--suite", choices=SUITES)
    parser.add_argument("--group", choices=GROUPS)
    parser.add_argument("--family", choices=list(manifest.coverage_family_names()))
    parser.add_argument("--threshold", action="store_true")
    args = parser.parse_args()

    if args.family and args.threshold:
        print(manifest.coverage_family_threshold(args.family))
        return
    if args.suite:
        print(" ".join(manifest.suite_files(args.suite)))
        return
    if args.group:
        print(" ".join(manifest.deep_validation_group_files(args.group)))
        return
    if args.family:
        print(" ".join(manifest.coverage_family_files(args.family)))
        return
    raise SystemExit("Either --suite, --group, or --family must be provided")


if __name__ == "__main__":
    main()
