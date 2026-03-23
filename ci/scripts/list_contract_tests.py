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


def main() -> None:
    manifest = _load_contract_manifest()

    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--suite",
        choices=sorted({contract.suite for contract in manifest.CONTRACTS}),
    )
    parser.add_argument(
        "--group",
        choices=list(manifest.DEEP_VALIDATION_GROUPS.keys()),
    )
    parser.add_argument("--family", choices=list(manifest.coverage_family_names()))
    parser.add_argument("--threshold", action="store_true")
    parser.add_argument("--cov-targets", action="store_true")
    args = parser.parse_args()

    selector = args.family or args.group
    if selector and args.threshold:
        print(manifest.coverage_family_threshold(selector))
        return
    if selector and args.cov_targets:
        cov_targets = tuple(manifest.COVERAGE_FAMILIES[selector]["cov_targets"])
        print(" ".join(cov_targets))
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
