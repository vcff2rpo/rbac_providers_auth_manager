from __future__ import annotations

import argparse
from pathlib import Path

from rbac_providers_auth_manager.compatibility.fab_provider_support import (
    render_support_markdown,
    write_support_artifacts,
)


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Validate official FAB provider permission support"
    )
    parser.add_argument(
        "--artifact-dir",
        default=".ci-artifacts/fab-provider",
        help="Directory where support artifacts should be written",
    )
    args = parser.parse_args()

    artifact_dir = Path(args.artifact_dir)
    report = write_support_artifacts(artifact_dir=artifact_dir)
    print(render_support_markdown(report), end="")
    if report.has_blocking_gaps:
        raise SystemExit(
            "Official FAB provider permissions are not fully supported by the custom plugin design"
        )


if __name__ == "__main__":
    main()
