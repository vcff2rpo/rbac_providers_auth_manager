"""Runtime version policy and compatibility reporting helpers.

This module centralizes the plugin's runtime-version view so compatibility
checks do not get scattered across auth-manager, config, and operator tooling.
It intentionally uses only the standard library to stay import-light during
plugin discovery.
"""

from __future__ import annotations

from dataclasses import dataclass
from importlib import metadata
import sys
import re

TESTED_AIRFLOW_BASELINE = "3.1.8"
LATEST_FAB_BASELINE = "3.5.0"
SUPPORTED_AIRFLOW_MAJOR = 3
SUPPORTED_PYTHON_MINORS = (10, 11, 12, 13)
RECOMMENDED_PYTHON_MINOR = 13

_VERSION_PART_RE = re.compile(r"(\d+)")


@dataclass(frozen=True, slots=True)
class RuntimeVersionPolicyReport:
    """Describe the active Airflow/FAB/Python runtime against plugin policy."""

    airflow_version: str | None
    fab_provider_version: str | None
    python_version: str
    airflow_status: str
    fab_provider_status: str
    python_status: str
    advisories: tuple[str, ...]

    def as_dict(self) -> dict[str, str]:
        """Return a flat dictionary representation suitable for structured logs."""
        return {
            "airflow_runtime_version": self.airflow_version or "unavailable",
            "fab_provider_version": self.fab_provider_version or "unavailable",
            "python_runtime_version": self.python_version,
            "airflow_version_status": self.airflow_status,
            "fab_provider_version_status": self.fab_provider_status,
            "python_version_status": self.python_status,
            "version_advisories": str(len(self.advisories)),
        }


def _distribution_version(distribution_name: str) -> str | None:
    """Return the installed version for a distribution, if available."""
    try:
        return metadata.version(distribution_name)
    except metadata.PackageNotFoundError:
        return None
    except Exception:
        return None


def _parse_numeric_version(version: str | None) -> tuple[int, ...]:
    """Return numeric version parts for tolerant semantic comparisons."""
    if not version:
        return ()
    return tuple(int(part) for part in _VERSION_PART_RE.findall(version))


def _version_at_least(actual: str | None, minimum: str) -> bool:
    """Return whether ``actual`` is greater than or equal to ``minimum``."""
    actual_parts = _parse_numeric_version(actual)
    minimum_parts = _parse_numeric_version(minimum)
    if not actual_parts:
        return False
    padded_length = max(len(actual_parts), len(minimum_parts))
    actual_padded = actual_parts + (0,) * (padded_length - len(actual_parts))
    minimum_padded = minimum_parts + (0,) * (padded_length - len(minimum_parts))
    return actual_padded >= minimum_padded


def build_runtime_version_policy_report() -> RuntimeVersionPolicyReport:
    """Build a compatibility report for the active runtime versions."""
    airflow_version = _distribution_version("apache-airflow")
    fab_provider_version = _distribution_version("apache-airflow-providers-fab")
    python_version = (
        f"{sys.version_info.major}.{sys.version_info.minor}.{sys.version_info.micro}"
    )

    advisories: list[str] = []

    airflow_status = "supported"
    airflow_parts = _parse_numeric_version(airflow_version)
    if not airflow_version:
        airflow_status = "unknown"
        advisories.append("Apache Airflow distribution version could not be detected.")
    elif not airflow_parts or airflow_parts[0] != SUPPORTED_AIRFLOW_MAJOR:
        airflow_status = "unsupported_major"
        advisories.append(
            f"Apache Airflow runtime {airflow_version} is outside the supported major line {SUPPORTED_AIRFLOW_MAJOR}.x."
        )
    elif not _version_at_least(airflow_version, TESTED_AIRFLOW_BASELINE):
        airflow_status = "older_than_tested_baseline"
        advisories.append(
            f"Apache Airflow runtime {airflow_version} predates the tested baseline {TESTED_AIRFLOW_BASELINE}."
        )
    elif airflow_parts[:2] >= (3, 3):
        airflow_status = "future_minor"
        advisories.append(
            f"Apache Airflow runtime {airflow_version} is in a future minor line; keep adapter-boundary tests active."
        )
    elif airflow_parts[:2] >= (3, 2):
        airflow_status = "next_minor"
        advisories.append(
            f"Apache Airflow runtime {airflow_version} is in the 3.2+ line; validate auth-manager adapters against milestone drift."
        )

    fab_status = "unknown"
    if not fab_provider_version:
        advisories.append(
            "apache-airflow-providers-fab is not installed or its version could not be detected."
        )
    elif not _version_at_least(fab_provider_version, LATEST_FAB_BASELINE):
        fab_status = "older_than_latest_baseline"
        advisories.append(
            f"FAB provider runtime {fab_provider_version} predates the latest baseline {LATEST_FAB_BASELINE}; review provider upgrade notes and run fab-db migrations if required."
        )
    else:
        fab_status = "current_or_newer"

    python_status = "supported"
    if (
        sys.version_info.major != 3
        or sys.version_info.minor not in SUPPORTED_PYTHON_MINORS
    ):
        python_status = "unsupported"
        advisories.append(
            f"Python runtime {python_version} is outside the supported Airflow 3.1 range 3.10-3.13."
        )
    elif sys.version_info.minor < RECOMMENDED_PYTHON_MINOR:
        python_status = "supported_but_not_latest_baseline"
        advisories.append(
            f"Python runtime {python_version} is supported, but 3.{RECOMMENDED_PYTHON_MINOR} is the current optimization baseline."
        )
    elif sys.version_info.minor > RECOMMENDED_PYTHON_MINOR:
        python_status = "future_minor"
        advisories.append(
            f"Python runtime {python_version} is newer than the current optimization baseline 3.{RECOMMENDED_PYTHON_MINOR}."
        )

    return RuntimeVersionPolicyReport(
        airflow_version=airflow_version,
        fab_provider_version=fab_provider_version,
        python_version=python_version,
        airflow_status=airflow_status,
        fab_provider_status=fab_status,
        python_status=python_status,
        advisories=tuple(advisories),
    )


__all__ = (
    "LATEST_FAB_BASELINE",
    "RECOMMENDED_PYTHON_MINOR",
    "RuntimeVersionPolicyReport",
    "SUPPORTED_AIRFLOW_MAJOR",
    "SUPPORTED_PYTHON_MINORS",
    "TESTED_AIRFLOW_BASELINE",
    "build_runtime_version_policy_report",
)
