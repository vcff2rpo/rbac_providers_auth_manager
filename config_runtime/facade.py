"""Public configuration entrypoints for the auth-manager runtime.

This module remains the stable import surface for the rest of the plugin while
keeping the implementation split across smaller runtime units:

- ``config_models`` for typed configuration objects
- ``config_parser`` for INI parsing and validation
- ``config_advisories`` for operator diagnostics and capability reporting
"""

from __future__ import annotations

import configparser
import logging
import threading
import time
from pathlib import Path

try:
    from airflow.configuration import conf as airflow_conf  # type: ignore
except Exception:  # pragma: no cover  # noqa: BLE001
    airflow_conf = None  # type: ignore[assignment]

from rbac_providers_auth_manager.config_runtime.advisories import (
    airflow_worker_count,
    build_runtime_capability_report,
    collect_config_advisories,
    effective_auth_state_backend,
    effective_rate_limit_backend,
)
from rbac_providers_auth_manager.config_runtime.models import (
    EXPECTED_PLUGIN_FAMILY,
    SUPPORTED_SCHEMA_VERSION,
    AuthConfig,
    AuthConfigValidation,
    ConfigAdvisory,
    EntraIdConfig,
    EntraRoleMappingConfig,
    GeneralConfig,
    JwtCookieConfig,
    LdapConfig,
    MetaConfig,
    RoleFiltersConfig,
    RoleMappingConfig,
    RolesConfig,
    SecurityConfig,
    UiConfig,
)
from rbac_providers_auth_manager.config_runtime.parser import load_config
from rbac_providers_auth_manager.config_runtime.parse_helpers import (
    default_permissions_path,
)

log = logging.getLogger(__name__)

__all__ = [
    "EXPECTED_PLUGIN_FAMILY",
    "SUPPORTED_SCHEMA_VERSION",
    "AuthConfig",
    "AuthConfigValidation",
    "ConfigAdvisory",
    "ConfigLoader",
    "EntraIdConfig",
    "EntraRoleMappingConfig",
    "GeneralConfig",
    "JwtCookieConfig",
    "LdapConfig",
    "MetaConfig",
    "RoleFiltersConfig",
    "RoleMappingConfig",
    "RolesConfig",
    "SecurityConfig",
    "UiConfig",
    "airflow_worker_count",
    "build_runtime_capability_report",
    "collect_config_advisories",
    "effective_auth_state_backend",
    "effective_rate_limit_backend",
    "load_config",
]


class ConfigLoader:
    """Cache and hot-reload ``permissions.ini``.

    Reload checks are throttled by ``config_reload_seconds``. On subsequent
    reload failures the loader keeps the last-known-good configuration.
    """

    def __init__(self, ini_path: Path | None = None) -> None:
        self._ini_path = ini_path or self._resolve_ini_path()
        self._cfg: AuthConfig | None = None
        self._mtime_ns: int | None = None
        self._lock = threading.Lock()
        self._last_check_monotonic: float = 0.0

    @staticmethod
    def _resolve_ini_path() -> Path:
        """Resolve the configured or default ``permissions.ini`` path."""
        override = None
        if airflow_conf is not None:
            override = airflow_conf.get(
                "core", "itim_ldap_permissions_ini", fallback=None
            )
        if override:
            return Path(override).expanduser().resolve()
        return default_permissions_path()

    def get_config(self) -> AuthConfig:
        """Return the current config, reloading when the file changed."""
        with self._lock:
            if self._cfg is None:
                self._reload(force=True)
                if self._cfg is None:
                    raise RuntimeError(
                        "Configuration reload completed without a loaded configuration"
                    )
                return self._cfg

            reload_seconds = max(0, int(self._cfg.general.config_reload_seconds))
            if (
                reload_seconds > 0
                and (time.monotonic() - self._last_check_monotonic) < reload_seconds
            ):
                return self._cfg

            self._reload(force=False)
            if self._cfg is None:
                raise RuntimeError(
                    "Configuration reload completed without a loaded configuration"
                )
            return self._cfg

    def _reload(self, force: bool) -> None:
        """Reload configuration if needed.

        First load must succeed. Later failures keep the previous config.
        Filesystem problems such as a temporarily missing or unreadable
        ``permissions.ini`` are treated the same way: fail closed on first load,
        keep last-known-good afterwards.
        """
        self._last_check_monotonic = time.monotonic()

        try:
            stat_result = self._ini_path.stat()
        except OSError:
            if self._cfg is None:
                raise
            log.exception(
                "Failed to stat permissions.ini; keeping last-known-good (%s)",
                self._ini_path,
            )
            return

        if not force and self._mtime_ns == stat_result.st_mtime_ns:
            return

        try:
            new_cfg = load_config(self._ini_path)
        except (OSError, ValueError, configparser.Error):
            if self._cfg is None:
                raise
            log.exception(
                "Failed to reload permissions.ini; keeping last-known-good (%s)",
                self._ini_path,
            )
            return

        self._cfg = new_cfg
        self._mtime_ns = stat_result.st_mtime_ns
        log.info(
            "Loaded permissions.ini from %s (mtime_ns=%s)",
            self._ini_path,
            self._mtime_ns,
        )
