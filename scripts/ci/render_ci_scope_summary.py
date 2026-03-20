from __future__ import annotations

import argparse
import importlib
import sys
from pathlib import Path
from types import ModuleType

REPO_ROOT = Path(__file__).resolve().parents[2]


def _load_manifest() -> ModuleType:
    if str(REPO_ROOT) not in sys.path:
        sys.path.insert(0, str(REPO_ROOT))
    return importlib.import_module("tests.ci.contract_manifest")


def _contracts_for_selector(
    manifest: ModuleType,
    *,
    suite: str | None,
    group: str | None,
    family: str | None,
) -> list[object]:
    if suite:
        files = set(manifest.suite_files(suite))
    elif group:
        files = set(manifest.deep_validation_group_files(group))
    elif family:
        files = set(manifest.coverage_family_files(family))
    else:
        raise SystemExit("A selector is required")

    return [contract for contract in manifest.CONTRACTS if contract.path in files]


def _capability_names(manifest: ModuleType, tags: set[str]) -> list[str]:
    names: list[str] = []
    for item in manifest.CAPABILITY_CATALOG:
        if item["tag"] in tags:
            names.append(str(item["name"]))
    return sorted(names)


def _write_summary(title: str, selected: list[object], manifest: ModuleType) -> str:
    tags: set[str] = set()
    tests: list[str] = []
    tiers: set[str] = set()
    for contract in selected:
        tags.update(getattr(contract, "capability_tags", ()))
        tests.append(getattr(contract, "path"))
        tiers.add(getattr(contract, "primary_tier"))

    covered = _capability_names(manifest, tags)
    all_names = [str(item["name"]) for item in manifest.CAPABILITY_CATALOG]
    not_covered = sorted(name for name in all_names if name not in covered)

    lines = [f"# {title}", "", "## What was tested", ""]
    lines.append(f"- contract tiers: {', '.join(sorted(tiers)) if tiers else 'n/a'}")
    lines.append(f"- test files: {len(tests)}")
    for path in sorted(tests):
        lines.append(f"- `{path}`")

    lines.extend(["", "## Covered by this job", ""])
    if covered:
        for name in covered:
            lines.append(f"- {name}")
    else:
        lines.append("- No manifest capabilities mapped for this selector")

    lines.extend(["", "## Not covered by this job", ""])
    for name in not_covered:
        lines.append(f"- {name}")

    return "\n".join(lines) + "\n"


def main() -> None:
    manifest = _load_manifest()
    parser = argparse.ArgumentParser(
        description="Render human-readable CI scope summary"
    )
    parser.add_argument("--title", required=True)
    parser.add_argument("--suite")
    parser.add_argument("--group")
    parser.add_argument("--family")
    parser.add_argument("--output")
    args = parser.parse_args()

    selectors = [bool(args.suite), bool(args.group), bool(args.family)]
    if sum(selectors) != 1:
        raise SystemExit(
            "Exactly one of --suite, --group, or --family must be provided"
        )

    selected = _contracts_for_selector(
        manifest,
        suite=args.suite,
        group=args.group,
        family=args.family,
    )
    text = _write_summary(args.title, selected, manifest)
    if args.output:
        Path(args.output).write_text(text, encoding="utf-8")
    else:
        print(text, end="")


if __name__ == "__main__":
    main()
