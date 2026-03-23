from __future__ import annotations

from dataclasses import dataclass
from types import SimpleNamespace

from rbac_providers_auth_manager.config_runtime.models import (
    AuthConfig,
    AuthConfigValidation,
    EntraRoleMappingConfig,
    GeneralConfig,
    JwtCookieConfig,
    MetaConfig,
    RoleFiltersConfig,
    RoleMappingConfig,
    RolesConfig,
    SecurityConfig,
    UiConfig,
)
from rbac_providers_auth_manager.runtime.session_revocation_backends import (
    build_session_revocation_store,
)
from rbac_providers_auth_manager.services.provider_runtime_service import (
    ProviderRuntimeService,
)
from rbac_providers_auth_manager.services.session_revocation_service import (
    SessionRevocationService,
)
from rbac_providers_auth_manager.services.user_session_service import UserSessionService


@dataclass(frozen=True, slots=True)
class DummyUser:
    user_id: str
    username: str
    first_name: str | None
    last_name: str | None
    email: str | None
    roles: tuple[str, ...]

    @property
    def is_anonymous(self) -> bool:
        return False


@dataclass(frozen=True, slots=True)
class DummyAnonymousUser:
    @property
    def is_anonymous(self) -> bool:
        return True


class DummyAuditService:
    def __init__(self) -> None:
        self.events: list[dict[str, object]] = []

    def log_flow_event(self, **payload):
        self.events.append(payload)


class DummyLoader:
    def __init__(self, cfg):
        self.cfg = cfg

    def get_config(self):
        return self.cfg


class DummyManager:
    def __init__(self, cfg) -> None:
        self._cfg_loader = DummyLoader(cfg)
        self._audit_service = DummyAuditService()
        self._session_revocation_service = SessionRevocationService(self)
        self._config_error_message = None

    @staticmethod
    def _user_model():
        return DummyUser

    @staticmethod
    def _anonymous_user():
        return DummyAnonymousUser()


def build_cfg(
    *,
    auth_user_registration_role: str = "Public",
    public_permissions: set[tuple[str, str]] | None = None,
) -> AuthConfig:
    return AuthConfig(
        meta=MetaConfig(),
        general=GeneralConfig(
            config_reload_seconds=30,
            strict_permissions=True,
            deny_if_no_roles=True,
            auth_user_registration=True,
            auth_user_registration_role=auth_user_registration_role,
            enable_ldap=True,
            enable_entra_id=False,
        ),
        security=SecurityConfig(
            enable_session_revocation_on_sensitive_reload=True,
            session_revocation_backend="memory",
        ),
        jwt_cookie=JwtCookieConfig(
            cookie_httponly=True,
            cookie_samesite="lax",
            cookie_path="/",
            cookie_domain=None,
            cookie_secure=None,
        ),
        ldap=None,
        entra_id=None,
        role_mapping=RoleMappingConfig(dn_to_roles={}),
        entra_role_mapping=EntraRoleMappingConfig(claim_value_to_roles={}),
        roles=RolesConfig(
            role_to_permissions={
                "Public": public_permissions or {("can_read", "Website")},
                "Admin": {("*", "*")},
            }
        ),
        role_filters=RoleFiltersConfig(role_to_filters={}),
        ui=UiConfig(),
        validation=AuthConfigValidation(),
        advisories=(),
    )


def test_memory_session_revocation_store_bumps_epoch() -> None:
    store = build_session_revocation_store(
        backend_name="memory",
        redis_url=None,
        redis_prefix="airflow_auth_revocation",
    )
    assert store.get_epoch() == 0
    assert store.bump_epoch() == 1
    assert store.bump_epoch() == 2
    assert store.get_epoch() == 2


def test_user_session_service_rejects_stale_token_and_serializes_current_epoch() -> (
    None
):
    cfg = build_cfg()
    manager = DummyManager(cfg)
    session_revocation = manager._session_revocation_service
    assert session_revocation.current_epoch() == 0
    assert session_revocation.bump_epoch(reason="test_reload") == 1

    service = UserSessionService(manager)
    claims = service.serialize_user(
        DummyUser(
            user_id="u1",
            username="jsmith",
            first_name="John",
            last_name="Smith",
            email="john@example.com",
            roles=("Public",),
        )
    )
    assert claims["authz_epoch"] == 1

    stale_user = service.deserialize_user(
        {
            "sub": "u1",
            "username": "jsmith",
            "roles": ["Admin"],
            "authz_epoch": 0,
        }
    )
    assert isinstance(stale_user, DummyAnonymousUser)
    assert any(
        event.get("event") == "auth.session_revocation.rejected"
        for event in manager._audit_service.events
    )


def test_sensitive_reload_fingerprint_changes_when_fallback_or_role_permissions_change() -> (
    None
):
    baseline = build_cfg(auth_user_registration_role="Public")
    changed_fallback = build_cfg(auth_user_registration_role="Admin")
    changed_permissions = build_cfg(
        public_permissions={("can_read", "Website"), ("can_edit", "Variables")}
    )

    baseline_fp = SessionRevocationService.sensitive_reload_fingerprint(baseline)
    assert baseline_fp != SessionRevocationService.sensitive_reload_fingerprint(
        changed_fallback
    )
    assert baseline_fp != SessionRevocationService.sensitive_reload_fingerprint(
        changed_permissions
    )


class DummyProvider:
    def __init__(self, manager, client) -> None:
        self._enabled = False

    def is_enabled(self) -> bool:
        return self._enabled


class DummyRevocationService:
    def __init__(self) -> None:
        self.bump_calls: list[tuple[str, dict[str, object] | None]] = []

    @staticmethod
    def sensitive_reload_fingerprint(cfg) -> str:
        return SessionRevocationService.sensitive_reload_fingerprint(cfg)

    def bump_epoch(
        self, *, reason: str, details: dict[str, object] | None = None
    ) -> int:
        self.bump_calls.append((reason, details))
        return 7


class RefreshManager:
    def __init__(self, previous_cfg, new_cfg) -> None:
        self._cfg_loader = DummyLoader(new_cfg)
        self._config_error_message = None
        self._provider_load_errors: list[str] = []
        self._audit_service = DummyAuditService()
        self._session_revocation_service = DummyRevocationService()
        self._active_cfg = previous_cfg
        self._sensitive_reload_fingerprint = (
            SessionRevocationService.sensitive_reload_fingerprint(previous_cfg)
        )
        self._ldap_provider = None
        self._entra_provider = None
        self._policy = None
        self._ldap_rate_limiter = None
        self._oauth_rate_limiter = None
        self.runtime_reports: list[object] = []

    def _log_runtime_capability_report(self, cfg) -> None:
        self.runtime_reports.append(cfg)


def test_provider_runtime_refresh_bumps_epoch_on_sensitive_change(monkeypatch) -> None:
    previous_cfg = build_cfg(auth_user_registration_role="Public")
    new_cfg = build_cfg(auth_user_registration_role="Admin")
    manager = RefreshManager(previous_cfg, new_cfg)
    service = ProviderRuntimeService(manager)

    monkeypatch.setattr(
        "rbac_providers_auth_manager.services.provider_runtime_service.LdapAuthProvider",
        DummyProvider,
    )
    monkeypatch.setattr(
        "rbac_providers_auth_manager.services.provider_runtime_service.EntraAuthProvider",
        DummyProvider,
    )
    monkeypatch.setattr(
        "rbac_providers_auth_manager.services.provider_runtime_service.RbacPolicy",
        lambda cfg: SimpleNamespace(cfg=cfg),
    )
    monkeypatch.setattr(
        service, "initialize_provider_clients", lambda cfg: (None, None, [])
    )
    monkeypatch.setattr(service, "configure_rate_limiters", lambda cfg: None)

    service.refresh_if_needed()

    assert manager._active_cfg is new_cfg
    assert manager._session_revocation_service.bump_calls == [
        (
            "sensitive_config_reload",
            {
                "config_reload_seconds": 30,
                "session_revocation_backend": "memory",
            },
        )
    ]
