from __future__ import annotations

import argparse
import json
import os
import re
import subprocess
from pathlib import Path

DENIED_PATTERNS = [
    re.compile(r"\bGPL\b", re.I),
    re.compile(r"\bAGPL\b", re.I),
    re.compile(r"\bLGPL\b", re.I),
    re.compile(r"\bEUPL\b", re.I),
]
COPyleft_HINTS = [
    re.compile(r"GNU GENERAL PUBLIC LICENSE", re.I),
    re.compile(r"Affero", re.I),
    re.compile(r"Lesser General Public License", re.I),
]


def run(cmd: list[str], cwd: Path) -> tuple[int, str]:
    proc = subprocess.run(cmd, cwd=cwd, capture_output=True, text=True)
    return proc.returncode, (proc.stdout + proc.stderr).strip()


def collect_pip_licenses(repo_root: Path) -> list[dict[str, str]]:
    code, output = run(
        [
            "python",
            "-m",
            "piplicenses",
            "--format=json",
            "--with-license-file",
            "--with-urls",
        ],
        repo_root,
    )
    if code != 0:
        return []
    try:
        data = json.loads(output)
    except json.JSONDecodeError:
        return []
    return [
        {
            "name": str(item.get("Name", "")),
            "version": str(item.get("Version", "")),
            "license": str(item.get("License", "")),
        }
        for item in data
    ]


def classify_license(name: str) -> str:
    if not name.strip():
        return "review"
    for pattern in DENIED_PATTERNS:
        if pattern.search(name):
            return "denied"
    if any(
        token in name
        for token in ["Apache", "BSD", "MIT", "PSF", "ISC", "MPL", "Python"]
    ):
        return "allowed"
    return "review"


def scan_sources(repo_root: Path) -> list[str]:
    findings: list[str] = []
    for path in repo_root.rglob("*.py"):
        if any(part.startswith(".") for part in path.parts):
            continue
        text = path.read_text(encoding="utf-8", errors="ignore")
        for pattern in COPyleft_HINTS:
            if pattern.search(text):
                findings.append(path.relative_to(repo_root).as_posix())
                break
    return sorted(set(findings))


def render_md(
    root_license_ok: bool,
    packages: list[dict[str, str]],
    source_hits: list[str],
    reuse_output: str,
) -> str:
    lines = ["# License compliance report", ""]
    lines += [
        f"- Root Apache-2.0 license present: {'yes' if root_license_ok else 'no'}",
        f"- Source copyleft indicators found: {len(source_hits)}",
        "",
    ]
    lines += [
        "## Dependency license classification",
        "",
        "| Package | Version | License | Classification |",
        "|---|---|---|---|",
    ]
    for item in packages:
        lic = item["license"]
        lines.append(
            f"| {item['name']} | {item['version']} | {lic or '—'} | {classify_license(lic)} |"
        )
    if source_hits:
        lines += ["", "## Source findings", ""]
        lines += [f"- `{hit}`" for hit in source_hits]
    if reuse_output:
        lines += [
            "",
            "## REUSE lint (advisory)",
            "",
            "```text",
            reuse_output[:12000],
            "```",
        ]
    return "\n".join(lines) + "\n"


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--repo-root", required=True)
    parser.add_argument("--output-md", required=True)
    parser.add_argument("--output-json", required=True)
    args = parser.parse_args()

    repo_root = Path(args.repo_root).resolve()
    root_license_ok = (repo_root / "LICENSE").exists() and "Apache License" in (
        repo_root / "LICENSE"
    ).read_text(encoding="utf-8", errors="ignore")
    packages = collect_pip_licenses(repo_root)
    source_hits = scan_sources(repo_root)
    _, reuse_output = run(["python", "-m", "reuse", "lint"], repo_root)
    data = {
        "root_apache_license": root_license_ok,
        "packages": packages,
        "source_copyleft_hits": source_hits,
        "reuse_output": reuse_output,
    }
    Path(args.output_md).write_text(
        render_md(root_license_ok, packages, source_hits, reuse_output),
        encoding="utf-8",
    )
    Path(args.output_json).write_text(
        json.dumps(data, indent=2) + "\n", encoding="utf-8"
    )
    print(render_md(root_license_ok, packages, source_hits, reuse_output))
    denied = [pkg for pkg in packages if classify_license(pkg["license"]) == "denied"]
    if not root_license_ok or denied or source_hits:
        raise SystemExit(1)


if __name__ == "__main__":
    main()
