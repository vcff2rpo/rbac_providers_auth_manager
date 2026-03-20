from __future__ import annotations

import argparse
import importlib
import sys
from pathlib import Path
from types import ModuleType
from typing import Iterable, Sequence

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


def _table(
    lines: list[str], headers: Sequence[str], rows: Sequence[Sequence[str]]
) -> None:
    lines.append("| " + " | ".join(headers) + " |")
    lines.append("| " + " | ".join("---" for _ in headers) + " |")
    if rows:
        for row in rows:
            lines.append("| " + " | ".join(row) + " |")
    else:
        lines.append("| " + " | ".join("-" for _ in headers) + " |")


def _strings(items: Iterable[object]) -> str:
    values = [str(item) for item in items]
    return ", ".join(values) if values else "-"


def _write_summary(title: str, selected: list[object], manifest: ModuleType) -> str:
    tags: set[str] = set()
    tiers: set[str] = set()
    tests: list[tuple[str, str, str, str]] = []
    for contract in selected:
        contract_tags = tuple(getattr(contract, "capability_tags", ()))
        contract_markers = tuple(getattr(contract, "extra_markers", ()))
        tags.update(contract_tags)
        tiers.add(str(getattr(contract, "primary_tier")))
        tests.append(
            (
                str(getattr(contract, "path")),
                str(getattr(contract, "primary_tier")),
                _strings(contract_markers),
                _strings(contract_tags),
            )
        )

    covered = _capability_names(manifest, tags)
    all_names = [str(item["name"]) for item in manifest.CAPABILITY_CATALOG]
    not_covered = sorted(name for name in all_names if name not in covered)

    lines = [f"# {title}", "", "## Summary", ""]
    _table(
        lines,
        ("Metric", "Value"),
        [
            ("Contract tiers", _strings(sorted(tiers))),
            ("Test files", str(len(tests))),
            ("Covered capabilities", str(len(covered))),
            ("Not covered capabilities", str(len(not_covered))),
        ],
    )

    lines.extend(["", "## What was tested", ""])
    _table(lines, ("Test file", "Tier", "Markers", "Capability tags"), tests)

    lines.extend(["", "## Covered by this job", ""])
    _table(lines, ("Capability",), [(name,) for name in covered])

    lines.extend(["", "## Not covered by this job", ""])
    _table(lines, ("Capability",), [(name,) for name in not_covered])

    lines.extend(["", "## Result interpretation", ""])
    lines.append("- success: all tests in this scope passed")
    lines.append("- failed: at least one test or gate in this scope failed")
    lines.append("- skipped: intentionally out of scope for this selector")
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
        out = Path(args.output)
        out.parent.mkdir(parents=True, exist_ok=True)
        out.write_text(text, encoding="utf-8")
    else:
        print(text, end="")


if __name__ == "__main__":
    main()
