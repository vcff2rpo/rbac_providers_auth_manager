from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any

from ci_lane_policy import LANE_POLICIES
from ci_path_filters import load_path_filters


def build_ownership_payload() -> dict[str, Any]:
    path_filters = load_path_filters().get("workflows", {})
    lanes = []
    workflows = []
    for policy in LANE_POLICIES:
        workflow_key = Path(policy.workflow).stem.removeprefix("reusable_")
        filter_entry = path_filters.get(workflow_key)
        lanes.append(
            {
                "lane": policy.lane,
                "workflow": policy.workflow,
                "blocking": policy.blocking,
                "summary_group": policy.summary_group,
                "artifact_prefix": policy.artifact_prefix,
                "cadence": policy.cadence,
                "secrets_profile": policy.secrets_profile,
                "path_filter_workflow": workflow_key if filter_entry else None,
                "path_filtered": filter_entry is not None,
            }
        )
        workflows.append(
            {
                "workflow": policy.workflow,
                "lane": policy.lane,
                "path_filter_workflow": workflow_key if filter_entry else None,
                "path_filter_events": tuple(sorted(filter_entry.keys()))
                if filter_entry
                else (),
            }
        )
    return {
        "lanes": lanes,
        "workflows": workflows,
    }


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Render committed CI ownership metadata"
    )
    parser.add_argument("--output-json", required=True)
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    payload = build_ownership_payload()
    out = Path(args.output_json)
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(
        json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
