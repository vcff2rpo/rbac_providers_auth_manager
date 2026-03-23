"""Logging helpers for the custom Airflow auth manager.

The plugin intentionally avoids taking over Airflow's logging configuration.
Instead it adjusts logger levels under a dedicated namespace and adds a small
fallback handler only when DEBUG troubleshooting is requested but Airflow's root
logger would otherwise suppress those records.
"""

from __future__ import annotations

import logging
import sys

LOGGER_NAMESPACE = "rbac_providers_auth_manager"
LEGACY_LOGGER_NAMESPACE = "airflow.itim_ldap_auth"
_FALLBACK_HANDLER: logging.Handler | None = None


class _BelowRootLevelFilter(logging.Filter):
    """Allow only records that the root logger would normally suppress.

    This prevents duplicate messages when the fallback handler is attached only
    to surface DEBUG logs that would otherwise be lost.
    """

    def __init__(self, root_level: int) -> None:
        super().__init__()
        self._root_level = int(root_level)

    def filter(self, record: logging.LogRecord) -> bool:  # noqa: A003
        """Return ``True`` only for records below the current root level."""
        return int(record.levelno) < self._root_level


def get_logger(name: str) -> logging.Logger:
    """Return a logger under the plugin namespace.

    Args:
        name: Short logical logger name such as ``auth_manager`` or ``config``.

    Returns:
        Logger instance namespaced under ``rbac_providers_auth_manager``.
    """
    normalized = (name or "").strip() or "root"
    return logging.getLogger(f"{LOGGER_NAMESPACE}.{normalized}")


def _remove_fallback_handler(namespace_logger: logging.Logger) -> None:
    """Detach the fallback handler if it is currently attached."""
    global _FALLBACK_HANDLER  # noqa: PLW0603

    if _FALLBACK_HANDLER is None:
        return
    namespace_logger.removeHandler(_FALLBACK_HANDLER)
    _FALLBACK_HANDLER = None


def _ensure_debug_visibility(
    namespace_logger: logging.Logger, *, desired_level: int
) -> None:
    """Attach or refresh the fallback DEBUG handler when needed.

    Args:
        namespace_logger: Plugin namespace logger.
        desired_level: Effective plugin log level requested by configuration.
    """
    global _FALLBACK_HANDLER  # noqa: PLW0603

    root_logger = logging.getLogger()
    root_effective_level = int(root_logger.getEffectiveLevel())

    if desired_level > logging.DEBUG:
        _remove_fallback_handler(namespace_logger)
        return

    if root_effective_level <= logging.DEBUG:
        _remove_fallback_handler(namespace_logger)
        return

    if _FALLBACK_HANDLER is not None:
        _FALLBACK_HANDLER.filters.clear()
        _FALLBACK_HANDLER.addFilter(_BelowRootLevelFilter(root_effective_level))
        return

    handler = logging.StreamHandler(stream=sys.stderr)
    handler.setLevel(logging.DEBUG)
    handler.addFilter(_BelowRootLevelFilter(root_effective_level))
    handler.setFormatter(
        logging.Formatter("%(asctime)s %(levelname)s %(name)s: %(message)s")
    )

    namespace_logger.addHandler(handler)
    _FALLBACK_HANDLER = handler


def configure(level: str | None = None) -> None:
    """Configure plugin logger levels without overriding Airflow handlers.

    The function updates both the current logger namespace and the older legacy
    namespace used by earlier releases of this plugin.

    Args:
        level: Desired log level name. Invalid values fall back to ``INFO``.
    """
    resolved_level = getattr(logging, (level or "INFO").upper(), logging.INFO)

    namespace_logger = logging.getLogger(LOGGER_NAMESPACE)
    namespace_logger.setLevel(resolved_level)
    logging.getLogger(LEGACY_LOGGER_NAMESPACE).setLevel(resolved_level)

    _ensure_debug_visibility(namespace_logger, desired_level=resolved_level)


def configure_logging(level: str | None = None) -> None:
    """Backward-compatible wrapper for :func:`configure`."""
    configure(level)
