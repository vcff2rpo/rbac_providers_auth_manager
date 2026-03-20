from __future__ import annotations

import argparse
import json
import re
import subprocess
from pathlib import Path

DENIED_PATTERNS = [
    re.compile(r"\bGPL\b", re.I),
    re.compile(r"\bAGPL\b", re.I),
    re.compile(r"\bLGPL\b", re.I),
    re.compile(r"\bEUPL\b", re.I),
    re.compile(r"\bSSPL\b", re.I),
]
ALLOWED_HINTS = (
    "Apache",
    "BSD",
    "MIT",
    "PSF",
    "ISC",
    "MPL",
    "Python",
    "Zlib",
    "Unlicense",
    "CC0",
)
COPyleft_HINTS = [
    re.compile(r"GNU GENERAL PUBLIC LICENSE", re.I),
    re.compile(r"Affero", re.I),
    re.compile(r"Lesser General Public License", re.I),
]
SCAN_EXTENSIONS = {
    ".py",
    ".md",
    ".txt",
    ".ini",
    ".cfg",
    ".toml",
    ".yaml",
    ".yml",
    ".json",
    ".html",
    ".css",
    ".sh",
}


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
    if any(token in name for token in ALLOWED_HINTS):
        return "allowed"
    return "review"


def scan_sources(repo_root: Path) -> dict[str, list[str]]:
    copyleft_hits: list[str] = []
    copyright_hits: list[str] = []
    for path in repo_root.rglob("*"):
        if not path.is_file():
            continue
        if any(part.startswith(".git") for part in path.parts):
            continue
        if path.suffix.lower() not in SCAN_EXTENSIONS and path.name not in {
            "LICENSE",
            "NOTICE",
            "REUSE.toml",
        }:
            continue
        rel = path.relative_to(repo_root).as_posix()
        text = path.read_text(encoding="utf-8", errors="ignore")
        if rel == "scripts/ci/check_license_compliance.py":
            continue
        for pattern in COPyleft_HINTS:
            if pattern.search(text):
                copyleft_hits.append(path.relative_to(repo_root).as_posix())
                break
        if re.search(r"copyright", text, re.I):
            copyright_hits.append(path.relative_to(repo_root).as_posix())
    return {
        "copyleft_hits": sorted(set(copyleft_hits)),
        "copyright_mentions": sorted(set(copyright_hits)),
    }


def render_md(
    *,
    root_license_ok: bool,
    notice_ok: bool,
    license_text_ok: bool,
    reuse_config_ok: bool,
    packages: list[dict[str, str]],
    scan_result: dict[str, list[str]],
    reuse_exit_code: int,
    reuse_output: str,
) -> str:
    lines = ["# License compliance report", ""]
    lines += [
        f"- Root Apache-2.0 license present: {'yes' if root_license_ok else 'no'}",
        f"- NOTICE present: {'yes' if notice_ok else 'no'}",
        f"- LICENSES/Apache-2.0.txt present: {'yes' if license_text_ok else 'no'}",
        f"- REUSE configuration present: {'yes' if reuse_config_ok else 'no'}",
        f"- REUSE lint exit code: {reuse_exit_code}",
        f"- Source copyleft indicators found: {len(scan_result['copyleft_hits'])}",
        "- Important: this is a repository heuristic scan. It can flag obvious licensing risks, but it cannot prove original authorship or guarantee non-infringement by itself.",
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
    if scan_result["copyleft_hits"]:
        lines += ["", "## Source copyleft indicators", ""]
        lines += [f"- `{hit}`" for hit in scan_result["copyleft_hits"]]
    if scan_result["copyright_mentions"]:
        lines += ["", "## Files mentioning copyright or licensing text", ""]
        lines += [f"- `{hit}`" for hit in scan_result["copyright_mentions"][:200]]
    if reuse_output:
        lines += [
            "",
            "## REUSE lint output",
            "",
            "```text",
            reuse_output[:16000],
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
    root_license = repo_root / "LICENSE"
    notice = repo_root / "NOTICE"
    license_text = repo_root / "LICENSES" / "Apache-2.0.txt"
    reuse_config = repo_root / "REUSE.toml"

    root_license_ok = (
        root_license.exists()
        and "Apache License"
        in root_license.read_text(encoding="utf-8", errors="ignore")
    )
    notice_ok = (
        notice.exists()
        and notice.read_text(encoding="utf-8", errors="ignore").strip() != ""
    )
    license_text_ok = (
        license_text.exists()
        and "Apache License"
        in license_text.read_text(encoding="utf-8", errors="ignore")
    )
    reuse_config_ok = reuse_config.exists()
    packages = collect_pip_licenses(repo_root)
    scan_result = scan_sources(repo_root)
    reuse_exit_code, reuse_output = run(["python", "-m", "reuse", "lint"], repo_root)
    denied = [pkg for pkg in packages if classify_license(pkg["license"]) == "denied"]
    review = [pkg for pkg in packages if classify_license(pkg["license"]) == "review"]

    data = {
        "root_apache_license": root_license_ok,
        "notice_present": notice_ok,
        "apache_license_text_present": license_text_ok,
        "reuse_config_present": reuse_config_ok,
        "packages": packages,
        "denied_packages": denied,
        "review_packages": review,
        "source_copyleft_hits": scan_result["copyleft_hits"],
        "source_copyright_mentions": scan_result["copyright_mentions"],
        "reuse_exit_code": reuse_exit_code,
        "reuse_output": reuse_output,
        "assessment_note": "Heuristic scan only; does not prove original authorship or non-infringement.",
    }
    Path(args.output_md).write_text(
        render_md(
            root_license_ok=root_license_ok,
            notice_ok=notice_ok,
            license_text_ok=license_text_ok,
            reuse_config_ok=reuse_config_ok,
            packages=packages,
            scan_result=scan_result,
            reuse_exit_code=reuse_exit_code,
            reuse_output=reuse_output,
        ),
        encoding="utf-8",
    )
    Path(args.output_json).write_text(
        json.dumps(data, indent=2) + "\n", encoding="utf-8"
    )
    print(Path(args.output_md).read_text(encoding="utf-8"), end="")
    if (
        not root_license_ok
        or not notice_ok
        or not license_text_ok
        or not reuse_config_ok
    ):
        raise SystemExit(1)
    if denied or scan_result["copyleft_hits"] or reuse_exit_code != 0:
        raise SystemExit(1)


if __name__ == "__main__":
    main()
