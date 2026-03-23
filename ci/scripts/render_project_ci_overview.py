from __future__ import annotations

import argparse
from pathlib import Path
from typing import Any

from ci_lane_policy import LANE_POLICIES
from ci_path_filters import load_path_filters
from ci_versions import load_versions
from render_ci_inventory import build_inventory


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Render maintainer-facing CI overview outside the ci/ subtree"
    )
    parser.add_argument("--repo-root", default=".")
    parser.add_argument("--output-md", required=True)
    return parser.parse_args()


def build_payload(repo_root: Path) -> dict[str, Any]:
    return {
        "versions": load_versions(),
        "path_filters": load_path_filters(),
        "lane_policies": [policy.__dict__ for policy in LANE_POLICIES],
        "inventory": build_inventory(repo_root),
    }


def render_markdown(payload: dict[str, Any]) -> str:
    versions = payload["versions"]
    filters = payload["path_filters"]["workflows"]
    lane_policies = payload["lane_policies"]
    inventory = payload["inventory"]

    lightweight = sorted(filters)

    lines = [
        "# CI overview",
        "",
        "This document is generated from the CI-owned registries and is intended for maintainers who need the high-level operating model without reading each workflow file.",
        "",
        "## Architecture at a glance",
        "",
        "The CI setup is intentionally layered:",
        "",
        "- top-level entrypoints in `.github/workflows/` decide when CI runs and which reusable workflows are called",
        "- reusable workflows own lane-level execution such as quality, deep validation, Airflow integration, identity validation, and compliance",
        "- composite actions under `ci/actions/` centralize repeated bootstrap, rendering, and upload steps",
        "- CI registries under `ci/config/` and `ci/scripts/` provide the single source of truth for versions, path filters, lane policy, ownership, and generated documentation",
        "",
        "This split follows GitHub's distinction between reusable workflows for whole-job reuse and composite actions for repeated step bundles.",
        "",
        "## Key defaults",
        "",
        f"- primary Python: `{versions['python']['primary']}`",
        f"- secondary Python: `{versions['python']['secondary']}`",
        f"- default Airflow: `{versions['airflow']['default']}`",
        f"- default FAB provider: `{versions['fab_provider']['default']}`",
        "",
        "These defaults are exported into top-level workflows through the `export-ci-context` composite action, so version drift is reduced.",
        "",
        "## Main CI lanes",
        "",
        "| Lane | Blocking | Cadence | Secrets profile | Purpose |",
        "| --- | --- | --- | --- | --- |",
    ]
    for lane in lane_policies:
        lines.append(
            f"| {lane['lane']} | {'yes' if lane['blocking'] else 'no'} | {lane['cadence']} | {lane['secrets_profile']} | {lane['notes']} |"
        )

    lines.extend(
        [
            "",
            "## Lightweight path-aware workflows",
            "",
            "These workflows exist mainly for performance and FinOps control on private repositories:",
            "",
            "| Workflow | Triggered when these areas change |",
            "| --- | --- |",
        ]
    )
    for workflow in lightweight:
        paths: list[str] = []
        for event_paths in filters[workflow].values():
            paths.extend(str(item) for item in event_paths)
        deduped = list(dict.fromkeys(paths))
        lines.append(f"| {workflow} | {'<br>'.join(deduped)} |")

    lines.extend(
        [
            "",
            "## CI-owned support layout",
            "",
            f"- workflows: {len(inventory['workflows'])}",
            f"- composite actions: {len(inventory['actions'])}",
            f"- Python helpers: {len(inventory['python_helpers'])}",
            f"- bash helpers: {len(inventory['bash_helpers'])}",
            f"- requirement sets: {len(inventory['requirements'])}",
            "",
            "## Extend this CI safely",
            "",
            "1. Add or update the lane/workflow in the appropriate reusable workflow file.",
            "2. Register version pins or path filters in `ci/config/` instead of hardcoding them in YAML.",
            "3. Reuse an existing composite action before adding inline shell glue.",
            "4. Update `tests/ci/contract_manifest.py` when new CI self-check tests are added.",
            "5. Regenerate the committed CI reference documents so the self-check lane stays green.",
            "",
            "## Complexity assessment",
            "",
            "The setup is now moderately sophisticated, but it is not unmanageably overcomplicated for a project that combines plugin runtime tests, Airflow integration, identity-provider validation, compliance, generated documentation, and private-repo minute controls. The main reason it remains maintainable is that metadata and repeated logic have been moved out of workflow YAML and into registries, scripts, and reusable actions.",
        ]
    )

    return "\n".join(lines) + "\n"


def main() -> int:
    args = parse_args()
    repo_root = Path(args.repo_root).resolve()
    out = Path(args.output_md)
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(render_markdown(build_payload(repo_root)), encoding="utf-8")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
