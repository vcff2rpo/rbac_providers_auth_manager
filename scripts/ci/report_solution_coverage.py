from __future__ import annotations

import importlib
import json
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
    artifact_dir = REPO_ROOT / ".ci-artifacts" / "coverage-report"
    artifact_dir.mkdir(parents=True, exist_ok=True)

    covered = [
        item for item in manifest.CAPABILITY_CATALOG if item["status"] == "covered"
    ]
    gaps = [item for item in manifest.CAPABILITY_CATALOG if item["status"] != "covered"]
    total = len(manifest.CAPABILITY_CATALOG)
    covered_count = len(covered)
    percent = round((covered_count / total) * 100, 1) if total else 0.0

    payload = {
        "total_capabilities": total,
        "covered_capabilities": covered_count,
        "coverage_percent": percent,
        "covered": covered,
        "gaps": gaps,
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
        f"- covered capabilities: {covered_count}/{total}",
        f"- coverage percent: {percent}%",
        "",
        "## Coverage families and thresholds",
    ]
    lines.extend(
        f"- {family}: threshold {int(meta['threshold'])}% across {len(tuple(meta['files']))} file(s)"
        for family, meta in manifest.COVERAGE_FAMILIES.items()
    )
    lines.extend(["", "## Covered capability areas"])
    lines.extend(f"- {item['name']}" for item in covered)
    lines.extend(["", "## Remaining gaps"])
    if gaps:
        lines.extend(f"- {item['name']}" for item in gaps)
    else:
        lines.append("- none")
    (artifact_dir / "solution-coverage.md").write_text(
        "\n".join(lines) + "\n",
        encoding="utf-8",
    )

    print(json.dumps(payload, indent=2))


if __name__ == "__main__":
    main()
