"""Runtime configuration implementation package.

This package contains the actual configuration parsing, model, and advisory
implementation modules. The legacy root-level ``config`` module remains as a
thin compatibility facade so existing imports continue to work.
"""

from __future__ import annotations

__all__ = (
    "facade",
    "models",
    "advisories",
    "advisory_rules",
    "parse_helpers",
    "section_parsers",
    "provider_parsers",
    "mapping_parsers",
    "parser",
)
