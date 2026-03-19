from __future__ import annotations

import json
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[2]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from rbac_providers_auth_manager.tests.ci.contract_manifest import CAPABILITY_CATALOG, COVERAGE_FAMILIES


def main() -> None:
    artifact_dir = REPO_ROOT / ".ci-artifacts" / "coverage-report"
    artifact_dir.mkdir(parents=True, exist_ok=True)

    covered = [item for item in CAPABILITY_CATALOG if item["status"] == "covered"]
    gaps = [item for item in CAPABILITY_CATALOG if item["status"] != "covered"]
    total = len(CAPABILITY_CATALOG)
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
            for family, meta in COVERAGE_FAMILIES.items()
        },
    }
    (artifact_dir / "solution-coverage.json").write_text(
        json.dumps(payload, indent=2) + "\n", encoding="utf-8"
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
        for family, meta in COVERAGE_FAMILIES.items()
    )
    lines.extend(["", "## Covered capability areas"])
    lines.extend(f"- {item['name']}" for item in covered)
    lines.extend(["", "## Remaining gaps"])
    if gaps:
        lines.extend(f"- {item['name']}" for item in gaps)
    else:
        lines.append("- none")
    (artifact_dir / "solution-coverage.md").write_text(
        "\n".join(lines) + "\n", encoding="utf-8"
    )

    print(json.dumps(payload, indent=2))


if __name__ == "__main__":
    main()
