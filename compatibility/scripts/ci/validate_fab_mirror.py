from __future__ import annotations

import json
from pathlib import Path

from rbac_providers_auth_manager.compatibility.fab_provider_support import (
    write_support_artifacts,
)


def main() -> None:
    artifact_dir = Path(".ci-artifacts/fab-provider")
    report = write_support_artifacts(artifact_dir=artifact_dir)
    print(json.dumps(report.as_dict(), indent=2, sort_keys=True))
    if report.has_blocking_gaps:
        raise SystemExit(
            "Official FAB provider permissions are not fully supported by the custom plugin design"
        )


if __name__ == "__main__":
    main()
