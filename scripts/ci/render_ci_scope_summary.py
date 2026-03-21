from __future__ import annotations

import argparse
import importlib
import sys
from pathlib import Path
from types import ModuleType
from typing import Iterable, Sequence

from ci_summary_catalog import SUITE_SOURCE_AREAS

REPO_ROOT = Path(__file__).resolve().parents[2]
SUITE_FILE_OVERRIDES = {
    "identity_provider_integration": {
        "tests/ci/test_ldap_live_container_integration.py",
        "tests/ci/test_entra_browser_flow_integration.py",
    },
}


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
        files.update(SUITE_FILE_OVERRIDES.get(suite, set()))
    elif group:
        files = set(manifest.deep_validation_group_files(group))
    elif family:
        files = set(manifest.coverage_family_files(family))
    else:
        raise SystemExit("A selector is required")
    return [contract for contract in manifest.CONTRACTS if contract.path in files]


def _capability_catalog(manifest: ModuleType) -> dict[str, str]:
    catalog: dict[str, str] = {}
    for item in manifest.CAPABILITY_CATALOG:
        tag = str(item["tag"])
        catalog[tag] = str(item["name"])
    return catalog


def _source_areas(
    manifest: ModuleType,
    *,
    suite: str | None,
    group: str | None,
    family: str | None,
    selected_files: set[str],
) -> list[str]:
    if family:
        targets = tuple(manifest.COVERAGE_FAMILIES[family]["cov_targets"])
        return sorted(str(item) for item in targets)

    inferred: set[str] = set()
    for family_name, meta in manifest.COVERAGE_FAMILIES.items():
        family_files = set(meta["files"])
        if selected_files & family_files:
            inferred.update(str(item) for item in meta["cov_targets"])

    if suite and suite in SUITE_SOURCE_AREAS:
        inferred.update(SUITE_SOURCE_AREAS[suite])
    if group:
        inferred.update(SUITE_SOURCE_AREAS.get("deep_validation", ()))
    return sorted(inferred)


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


def _selector_name(*, suite: str | None, group: str | None, family: str | None) -> str:
    if suite:
        return f"suite={suite}"
    if group:
        return f"group={group}"
    if family:
        return f"family={family}"
    return "selector=unknown"


def _write_summary(
    title: str,
    selected: list[object],
    manifest: ModuleType,
    *,
    suite: str | None,
    group: str | None,
    family: str | None,
) -> str:
    tags: set[str] = set()
    tiers: set[str] = set()
    files: set[str] = set()
    tests: list[tuple[str, str, str, str]] = []
    detailed: list[tuple[str, str, str]] = []
    tag_names = _capability_catalog(manifest)

    for contract in selected:
        path = str(getattr(contract, "path"))
        files.add(path)
        contract_tags = tuple(getattr(contract, "capability_tags", ()))
        contract_markers = tuple(getattr(contract, "extra_markers", ()))
        tags.update(contract_tags)
        tiers.add(str(getattr(contract, "primary_tier")))
        tests.append(
            (
                path,
                str(getattr(contract, "primary_tier")),
                _strings(contract_markers),
                _strings(contract_tags),
            )
        )
        for tag in contract_tags:
            detailed.append(
                (path, tag_names.get(str(tag), str(tag)), _strings(contract_markers))
            )

    covered = sorted(tag_names[tag] for tag in tags if tag in tag_names)
    source_areas = _source_areas(
        manifest,
        suite=suite,
        group=group,
        family=family,
        selected_files=files,
    )

    lines = [f"# {title}", "", "## High-level execution view", ""]
    _table(
        lines,
        ("Metric", "Value"),
        [
            ("Selector", _selector_name(suite=suite, group=group, family=family)),
            ("Contract tiers", _strings(sorted(tiers))),
            ("Selected test files", str(len(tests))),
            ("Primary source/package areas exercised", str(len(source_areas))),
            ("Capability areas covered by this selector", str(len(covered))),
        ],
    )

    lines.extend(["", "## Job-task executed and files used", ""])
    _table(
        lines,
        ("Task slice", "Files used", "What this slice validates"),
        [
            (
                _selector_name(suite=suite, group=group, family=family),
                "<br>".join(sorted(files)) or "-",
                "Executes the selected pytest contract set and reports the matching capability areas.",
            )
        ],
    )

    lines.extend(["", "## Selected source/package areas", ""])
    _table(lines, ("Area",), [(item,) for item in source_areas])

    lines.extend(["", "## Selected test files", ""])
    _table(lines, ("Test file", "Tier", "Markers", "Capability tags"), tests)

    lines.extend(["", "## What was tested", ""])
    _table(lines, ("Test file", "Capability area", "Markers"), detailed)

    lines.extend(["", "## Covered by this selector", ""])
    _table(lines, ("Capability area",), [(name,) for name in covered])

    lines.extend(["", "## Result interpretation", ""])
    lines.append("- success: all tests in this selector passed")
    lines.append(
        "- failed: at least one test or validation step in this selector failed"
    )
    lines.append(
        "- skipped: selector was intentionally not executed in this workflow run"
    )
    lines.append(
        "- note: the file and source-area lists describe the planned scope for this selector; runtime stack traces still come from the produced artifacts and logs"
    )
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
    text = _write_summary(
        args.title,
        selected,
        manifest,
        suite=args.suite,
        group=args.group,
        family=args.family,
    )
    if args.output:
        out = Path(args.output)
        out.parent.mkdir(parents=True, exist_ok=True)
        out.write_text(text, encoding="utf-8")
    else:
        print(text, end="")


if __name__ == "__main__":
    main()
