"""Shared internal models for provider and identity orchestration.

These models intentionally avoid Airflow imports so provider flows, role mapping,
and intermediate auth decisions stay testable without a running Airflow runtime.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Mapping


@dataclass(frozen=True, slots=True)
class ExternalIdentity:
    """Normalized identity emitted by an authentication provider.

    The same model is used for LDAP and Entra identities so downstream mapping
    and session code can operate on one stable shape.
    """

    provider: str
    user_id: str
    username: str
    first_name: str | None = None
    last_name: str | None = None
    email: str | None = None
    display_name: str | None = None
    group_dns: tuple[str, ...] = ()
    claim_values: tuple[str, ...] = ()
    claims: Mapping[str, Any] = field(default_factory=dict)


@dataclass(frozen=True, slots=True)
class RoleMappingResult:
    """Result of translating external identity attributes into Airflow roles."""

    roles: tuple[str, ...]
    dropped_roles: tuple[str, ...] = ()
    mapping_hits: tuple[tuple[str, tuple[str, ...]], ...] = ()
    external_values_count: int = 0
    mapped_values_count: int = 0


@dataclass(frozen=True, slots=True)
class OAuthFlowState:
    """Short-lived browser SSO state kept across redirect/callback round trips."""

    state: str
    nonce: str
    next_url: str
    code_verifier: str | None = None
