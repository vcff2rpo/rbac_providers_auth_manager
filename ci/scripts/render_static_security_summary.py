from __future__ import annotations

import argparse
import json
import re
from pathlib import Path

BANDIT_BLOCK_RE = re.compile(
    r">> Issue: \[(?P<test>[A-Z0-9]+):(?P<plugin>[^\]]+)\].*?"
    r"Severity: (?P<severity>[A-Za-z]+).*?"
    r"Location: (?P<location>[^\n]+)",
    re.DOTALL,
)


def parse_bandit(path: Path) -> dict[str, object]:
    if not path.exists():
        return {"exists": False, "count": 0, "findings": []}
    text = path.read_text(encoding="utf-8", errors="replace")
    findings = []
    for match in BANDIT_BLOCK_RE.finditer(text):
        findings.append(
            {
                "test": match.group("test"),
                "plugin": match.group("plugin").strip(),
                "severity": match.group("severity").strip(),
                "location": match.group("location").strip(),
            }
        )
    return {"exists": True, "count": len(findings), "findings": findings[:20]}


def parse_gitleaks(path: Path) -> dict[str, object]:
    if not path.exists():
        return {"exists": False, "count": 0, "findings": []}
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except json.JSONDecodeError:
        return {"exists": True, "count": 0, "findings": []}
    findings = []
    if isinstance(data, list):
        for item in data[:20]:
            if isinstance(item, dict):
                findings.append(
                    {
                        "rule": str(item.get("RuleID", "")),
                        "file": str(item.get("File", "")),
                        "description": str(item.get("Description", "")),
                    }
                )
        return {"exists": True, "count": len(data), "findings": findings}
    return {"exists": True, "count": 0, "findings": []}


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--bandit", required=True)
    parser.add_argument("--gitleaks", required=True)
    parser.add_argument("--bandit-rc", required=True)
    parser.add_argument("--gitleaks-rc", required=True)
    parser.add_argument("--output-md", required=True)
    parser.add_argument("--output-json", required=True)
    args = parser.parse_args()

    bandit = parse_bandit(Path(args.bandit))
    gitleaks = parse_gitleaks(Path(args.gitleaks))
    payload = {
        "bandit_rc": int(args.bandit_rc),
        "gitleaks_rc": int(args.gitleaks_rc),
        "bandit": bandit,
        "gitleaks": gitleaks,
    }

    lines = ["# Static security summary", ""]
    lines.append("| Check | Exit code | Findings detected |")
    lines.append("|---|---|---|")
    lines.append(f"| Bandit | {args.bandit_rc} | {bandit['count']} |")
    lines.append(f"| Gitleaks | {args.gitleaks_rc} | {gitleaks['count']} |")

    lines.extend(["", "## Bandit highlights", ""])
    bandit_findings = bandit.get("findings", [])
    if isinstance(bandit_findings, list) and bandit_findings:
        lines.append("| Test ID | Plugin | Severity | Location |")
        lines.append("|---|---|---|---|")
        for item in bandit_findings:
            if isinstance(item, dict):
                lines.append(
                    "| {test} | {plugin} | {severity} | {location} |".format(
                        test=item.get("test", ""),
                        plugin=item.get("plugin", ""),
                        severity=item.get("severity", ""),
                        location=item.get("location", ""),
                    )
                )
    else:
        lines.append("No Bandit findings were parsed from bandit.txt.")

    lines.extend(["", "## Gitleaks highlights", ""])
    gitleaks_findings = gitleaks.get("findings", [])
    if isinstance(gitleaks_findings, list) and gitleaks_findings:
        lines.append("| Rule | File | Description |")
        lines.append("|---|---|---|")
        for item in gitleaks_findings:
            if isinstance(item, dict):
                lines.append(
                    "| {rule} | {file} | {description} |".format(
                        rule=item.get("rule", ""),
                        file=item.get("file", ""),
                        description=item.get("description", ""),
                    )
                )
    else:
        lines.append("No Gitleaks findings were parsed from gitleaks.json.")

    Path(args.output_md).write_text("\n".join(lines) + "\n", encoding="utf-8")
    Path(args.output_json).write_text(
        json.dumps(payload, indent=2) + "\n", encoding="utf-8"
    )
    print(Path(args.output_md).read_text(encoding="utf-8"), end="")


if __name__ == "__main__":
    main()
