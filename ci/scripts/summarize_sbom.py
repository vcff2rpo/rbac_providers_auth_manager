from __future__ import annotations

import argparse
import json
from pathlib import Path


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--sbom-json", required=True)
    parser.add_argument("--output-md", required=True)
    args = parser.parse_args()

    data = json.loads(Path(args.sbom_json).read_text(encoding="utf-8"))
    components = data.get("components") or []
    lines = [
        "# SBOM summary",
        "",
        f"- Components: {len(components)}",
        f"- Serial number: {data.get('serialNumber', '—')}",
        "",
        "| Name | Version | Type |",
        "|---|---|---|",
    ]
    for item in components[:100]:
        lines.append(
            f"| {item.get('name', '')} | {item.get('version', '')} | {item.get('type', '')} |"
        )
    Path(args.output_md).write_text("\n".join(lines) + "\n", encoding="utf-8")
    print("\n".join(lines))


if __name__ == "__main__":
    main()
