from __future__ import annotations

import argparse
import json
from pathlib import Path

CACHE_DIR_NAMES = {
    ".ruff_cache",
    ".mypy_cache",
    ".pytest_cache",
    "__pycache__",
    "build",
    "dist",
}


def find_problem_paths(repo_root: Path) -> list[str]:
    hits: list[str] = []
    for path in repo_root.rglob("*"):
        if path.name in CACHE_DIR_NAMES:
            hits.append(path.relative_to(repo_root).as_posix())
    return sorted(set(hits))


def detect_package_root(repo_root: Path) -> Path | None:
    if (repo_root / "__init__.py").exists():
        return repo_root
    candidate = repo_root / "rbac_providers_auth_manager"
    if candidate.is_dir() and (candidate / "__init__.py").exists():
        return candidate
    return None


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--repo-root", required=True)
    parser.add_argument("--output-md", required=True)
    parser.add_argument("--output-json", required=True)
    args = parser.parse_args()

    repo_root = Path(args.repo_root).resolve()
    package_root = detect_package_root(repo_root)

    checks = {
        "package_directory_present": package_root is not None,
        "package_init_present": package_root is not None
        and (package_root / "__init__.py").exists(),
        "readme_present": (repo_root / "README.md").exists(),
        "license_present": (repo_root / "LICENSE").exists(),
        "notice_present": (repo_root / "NOTICE").exists(),
        "typed_marker_present": package_root is not None
        and (package_root / "py.typed").exists(),
        "build_metadata_present": (repo_root / "pyproject.toml").exists()
        or (repo_root / "setup.py").exists(),
    }
    problem_paths = find_problem_paths(repo_root)
    checks["committed_cache_or_build_dirs_absent"] = len(problem_paths) == 0

    status = "success" if all(checks.values()) else "failed"
    payload = {
        "status": status,
        "checks": checks,
        "package_root": package_root.relative_to(repo_root).as_posix()
        if package_root
        else None,
        "problem_paths": problem_paths,
        "note": "This is a release-readiness heuristic; it does not publish a package.",
    }

    lines = ["# Release readiness report", ""]
    lines.append("| Check | Result |")
    lines.append("|---|---|")
    for name, ok in checks.items():
        lines.append(f"| {name} | {'yes' if ok else 'no'} |")
    lines.extend(["", "## Package layout", ""])
    lines.append(f"- detected package root: `{payload['package_root'] or 'not found'}`")
    lines.extend(["", "## Problem paths", ""])
    if problem_paths:
        for item in problem_paths:
            lines.append(f"- `{item}`")
    else:
        lines.append("- none")
    lines.extend(
        [
            "",
            "## Interpretation",
            "",
            "- build_metadata_present requires either `pyproject.toml` or `setup.py` at repository root.",
            "- committed_cache_or_build_dirs_absent flags checked-in cache or build artefacts that should normally stay out of source control.",
            "- Package layout supports either a flat package-at-root repository or a repository with a nested `rbac_providers_auth_manager/` package directory.",
            "- This report is intentionally strict because releasable community packages should be buildable and clean from cache cruft.",
        ]
    )

    Path(args.output_md).write_text("\n".join(lines) + "\n", encoding="utf-8")
    Path(args.output_json).write_text(
        json.dumps(payload, indent=2) + "\n", encoding="utf-8"
    )
    print(Path(args.output_md).read_text(encoding="utf-8"), end="")
    if status != "success":
        raise SystemExit(1)


if __name__ == "__main__":
    main()
