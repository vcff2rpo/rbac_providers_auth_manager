"""UI rendering helpers for browser-facing auth pages."""

from __future__ import annotations

from importlib import import_module
from typing import Any

__all__ = ("UIRenderer",)


def __getattr__(name: str) -> Any:
    """Resolve the renderer lazily to keep package imports predictable."""
    if name == "UIRenderer":
        return import_module("rbac_providers_auth_manager.ui.renderer").UIRenderer
    raise AttributeError(name)
