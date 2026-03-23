from __future__ import annotations

import importlib
import json
import sys
from pathlib import Path
from types import ModuleType

from ci_summary_catalog import SUPPLEMENTAL_AREAS, checkbox

REPO_ROOT = Path(__file__).resolve().parents[2]


def _load_contract_manifest() -> ModuleType:
    if str(REPO_ROOT) not in sys.path:
        sys.path.insert(0, str(REPO_ROOT))
    return importlib.import_module("tests.ci.contract_manifest")


def main() -> None:
    manifest = _load_contract_manifest()
    artifact_dir = REPO_ROOT / ".ci-artifacts" / "coverage-report"
    artifact_dir.mkdir(parents=True, exist_ok=True)

    covered = [
        item for item in manifest.CAPABILITY_CATALOG if item["status"] == "covered"
    ]
    gaps = [item for item in manifest.CAPABILITY_CATALOG if item["status"] != "covered"]
    supplemental_covered = [
        item for item in SUPPLEMENTAL_AREAS if item["status"] == "covered"
    ]
    supplemental_gaps = [
        item for item in SUPPLEMENTAL_AREAS if item["status"] != "covered"
    ]
    total = len(manifest.CAPABILITY_CATALOG) + len(SUPPLEMENTAL_AREAS)
    covered_count = len(covered) + len(supplemental_covered)
    percent = round((covered_count / total) * 100, 1) if total else 0.0

    payload = {
        "total_capabilities": total,
        "covered_capabilities": covered_count,
        "coverage_percent": percent,
        "covered": covered,
        "gaps": gaps,
        "supplemental_covered": supplemental_covered,
        "supplemental_gaps": supplemental_gaps,
        "coverage_families": {
            family: {
                "threshold": int(meta["threshold"]),
                "file_count": len(tuple(meta["files"])),
            }
            for family, meta in manifest.COVERAGE_FAMILIES.items()
        },
    }
    (artifact_dir / "solution-coverage.json").write_text(
        json.dumps(payload, indent=2) + "\n",
        encoding="utf-8",
    )

    lines = [
        "# Solution coverage report",
        "",
        f"- covered capability areas: {covered_count}/{total}",
        f"- coverage percent: {percent}%",
        "",
        "## Coverage families and thresholds",
    ]
    lines.extend(
        f"- {family}: threshold {int(meta['threshold'])}% across {len(tuple(meta['files']))} file(s)"
        for family, meta in manifest.COVERAGE_FAMILIES.items()
    )
    lines.extend(["", "## Repository-level capability matrix", ""])
    lines.append("| Tested in repository CI catalog | Capability area | Source |")
    lines.append("|---|---|---|")
    for item in covered:
        lines.append(f"| {checkbox(True)} | {item['name']} | contract manifest |")
    for item in gaps:
        lines.append(f"| {checkbox(False)} | {item['name']} | contract manifest |")
    for item in supplemental_covered:
        lines.append(f"| {checkbox(True)} | {item['name']} | supplemental CI catalog |")
    for item in supplemental_gaps:
        lines.append(
            f"| {checkbox(False)} | {item['name']} | supplemental CI catalog |"
        )

    lines.extend(["", "## Missing from the repository CI catalog", ""])
    if gaps or supplemental_gaps:
        for item in [*gaps, *supplemental_gaps]:
            reason = item.get("reason", "not yet assigned to an implemented CI check")
            lines.append(f"- {item['name']}: {reason}")
    else:
        lines.append("- none")

    (artifact_dir / "solution-coverage.md").write_text(
        "\n".join(lines) + "\n",
        encoding="utf-8",
    )

    print(json.dumps(payload, indent=2))


if __name__ == "__main__":
    main()
