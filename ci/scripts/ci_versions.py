from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any, Final

REPO_ROOT: Final[Path] = Path(__file__).resolve().parents[2]
VERSIONS_PATH: Final[Path] = REPO_ROOT / "ci" / "config" / "versions.json"


def load_versions() -> dict[str, Any]:
    return json.loads(VERSIONS_PATH.read_text(encoding="utf-8"))


def dotted_get(data: dict[str, Any], key: str) -> Any:
    current: Any = data
    for part in key.split("."):
        if not isinstance(current, dict) or part not in current:
            raise KeyError(key)
        current = current[part]
    return current


def build_ci_context(data: dict[str, Any]) -> dict[str, str]:
    return {
        "python_primary": str(data["python"]["primary"]),
        "python_secondary": str(data["python"]["secondary"]),
        "python_deep_validation": json.dumps(data["python"]["deep_validation"]),
        "python_nightly": json.dumps(data["python"]["nightly"]),
        "airflow_default": str(data["airflow"]["default"]),
        "airflow_nightly": json.dumps(data["airflow"]["nightly"]),
        "fab_provider_default": str(data["fab_provider"]["default"]),
        "fab_provider_nightly": json.dumps(data["fab_provider"]["nightly"]),
        "requirements_dev": str(data["requirements"]["dev"]),
        "requirements_airflow_integration": str(
            data["requirements"]["airflow_integration"]
        ),
        "requirements_external_real_validation": str(
            data["requirements"]["external_real_validation"]
        ),
        "requirements_fab_provider_validation": str(
            data["requirements"]["fab_provider_validation"]
        ),
    }


def write_github_output(path: Path, payload: dict[str, str]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    lines = [f"{key}={value}" for key, value in payload.items()]
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")


def emit_markdown(data: dict[str, Any]) -> str:
    py = data["python"]
    airflow = data["airflow"]
    fab = data["fab_provider"]
    req = data["requirements"]
    lines = [
        "# CI versions registry",
        "",
        "| Area | Value |",
        "| --- | --- |",
        f"| Python primary | {py['primary']} |",
        f"| Python secondary | {py['secondary']} |",
        f"| Deep-validation Python matrix | {', '.join(py['deep_validation'])} |",
        f"| Nightly Python matrix | {', '.join(py['nightly'])} |",
        f"| Airflow default | {airflow['default']} |",
        f"| Airflow nightly matrix | {', '.join(airflow['nightly'])} |",
        f"| FAB provider default | {fab['default']} |",
        f"| FAB provider nightly matrix | {', '.join(fab['nightly'])} |",
        f"| Dev requirements | {req['dev']} |",
        f"| Airflow integration requirements | {req['airflow_integration']} |",
        f"| External real validation requirements | {req['external_real_validation']} |",
        f"| FAB provider validation requirements | {req['fab_provider_validation']} |",
        "",
        "This file is the CI-owned source of truth for version pins and requirement paths. Workflows may still declare mirrored defaults, and tests verify they stay synchronized.",
        "",
    ]
    return "\n".join(lines)


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Read or render the CI versions registry"
    )
    parser.add_argument("--key")
    parser.add_argument("--output")
    parser.add_argument("--markdown", action="store_true")
    parser.add_argument("--json", action="store_true")
    parser.add_argument("--github-output")
    args = parser.parse_args()

    data = load_versions()
    if args.key:
        value = dotted_get(data, args.key)
        if isinstance(value, list):
            print(json.dumps(value))
        else:
            print(value)
        return

    if args.github_output:
        write_github_output(Path(args.github_output), build_ci_context(data))
        return

    if args.markdown:
        text = emit_markdown(data)
    else:
        text = (
            json.dumps(data, indent=2, sort_keys=True)
            if args.json or args.output
            else json.dumps(data, indent=2, sort_keys=True)
        )

    if args.output:
        out = Path(args.output)
        out.parent.mkdir(parents=True, exist_ok=True)
        out.write_text(text + ("" if text.endswith("\n") else "\n"), encoding="utf-8")
    else:
        print(text)


if __name__ == "__main__":
    main()
