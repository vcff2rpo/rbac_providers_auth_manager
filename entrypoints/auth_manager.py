"""Custom Airflow auth manager for LDAP/ITIM and Azure Entra ID.

This module is the runtime entry point configured in ``[core] auth_manager``.
It implements a single pluggable Airflow auth manager that can expose one or
both of these authentication methods:

- LDAP username/password login
- Azure Entra ID SSO

Authorization remains file-driven and FAB-style:
- external identity attributes are mapped to Airflow role names
- Airflow roles expand into action/resource permissions from ``permissions.ini``
- request-level checks then mirror FAB semantics as closely as practical

Design goals
------------
- keep authentication providers loosely coupled
- centralize shared cookie/redirect/security helpers
- preserve Airflow 3.x auth-manager compatibility through adapter modules
- keep provider-specific logic readable enough for future extension
"""

from __future__ import annotations

from collections.abc import Sequence
from dataclasses import dataclass
from typing import TYPE_CHECKING, Any, cast
from fastapi import FastAPI, Request
from fastapi.responses import RedirectResponse

from rbac_providers_auth_manager.compatibility.airflow_public_api import (
    BaseAuthManager,
    BaseUser,
    ExtraMenuItem,
    MenuItem,
    NEW_SESSION,
    ResourceMethod,
    provide_session,
)
from rbac_providers_auth_manager.config import (
    ConfigLoader,
    build_runtime_capability_report,
)
from rbac_providers_auth_manager.identity.mapper import IdentityMapper
from rbac_providers_auth_manager.compatibility.internal_shims import (
    IsAuthorizedConnectionRequest,
    IsAuthorizedDagRequest,
    IsAuthorizedPoolRequest,
    IsAuthorizedVariableRequest,
)
from rbac_providers_auth_manager.core.logging_utils import configure_logging, get_logger
from rbac_providers_auth_manager.identity.models import ExternalIdentity
from rbac_providers_auth_manager.providers.entra_provider import EntraAuthProvider
from rbac_providers_auth_manager.providers.ldap_provider import LdapAuthProvider
from rbac_providers_auth_manager.authorization.rbac import RbacPolicy
from rbac_providers_auth_manager.services.audit_service import AuditService
from rbac_providers_auth_manager.services.auth_flow_service import AuthFlowService
from rbac_providers_auth_manager.services.authorization_service import (
    AuthorizationService,
)
from rbac_providers_auth_manager.services.entrypoint_app_service import (
    EntrypointAppService,
)
from rbac_providers_auth_manager.services.identity_auth_service import (
    IdentityAuthService,
)
from rbac_providers_auth_manager.services.provider_runtime_service import (
    ProviderRuntimeService,
)
from rbac_providers_auth_manager.services.redirect_service import RedirectService
from rbac_providers_auth_manager.services.runtime_context_service import (
    RuntimeContextService,
)
from rbac_providers_auth_manager.services.session_service import SessionService
from rbac_providers_auth_manager.services.user_session_service import UserSessionService
from rbac_providers_auth_manager.ui.renderer import (
    UIRenderer,
    validate_ui_renderer_bindings,
)
from rbac_providers_auth_manager.runtime.compat_governance import (
    build_operator_doctor_report,
)
from rbac_providers_auth_manager.runtime.version_policy import (
    build_runtime_version_policy_report,
)

if TYPE_CHECKING:
    from airflow.api_fastapi.auth.managers.models.resource_details import (
        BackfillDetails,
        ConfigurationDetails,
        ConnectionDetails,
        DagDetails,
        PoolDetails,
        VariableDetails,
    )
    from airflow.providers.common.compat.assets import AssetAliasDetails, AssetDetails

log = get_logger("auth_manager")


@dataclass(frozen=True, slots=True)
class RbacAuthUser(BaseUser):
    """User object stored in JWT claims and attached to request context."""

    user_id: str
    username: str
    first_name: str | None
    last_name: str | None
    email: str | None
    roles: tuple[str, ...]

    @property
    def is_anonymous(self) -> bool:
        return False

    @property
    def is_active(self) -> bool:
        return True

    def get_id(self) -> str:
        return self.user_id


@dataclass(frozen=True, slots=True)
class ItimAnonymousUser(BaseUser):
    """Anonymous fallback user returned when no authenticated JWT exists."""

    @property
    def is_anonymous(self) -> bool:
        return True

    @property
    def is_active(self) -> bool:
        return False

    def get_id(self) -> str:  # pragma: no cover
        return "anonymous"


class RbacAuthManager(BaseAuthManager[RbacAuthUser]):
    """LDAP + Entra auth manager with file-driven FAB-style RBAC."""

    def __init__(self, context: Any | None = None) -> None:
        super().__init__(context=context)

        validate_ui_renderer_bindings()

        self._cfg_loader = ConfigLoader()
        self._config_error_message: str | None = None
        self._provider_load_errors: list[str] = []
        self._audit_service = AuditService()
        self._redirect_service = RedirectService()
        self._session_service = SessionService(
            config_loader=self._cfg_loader,
            redirect_service=self._redirect_service,
            audit_service=self._audit_service,
        )
        self._runtime_context_service = RuntimeContextService(self)
        self._user_session_service = UserSessionService(self)
        self._entrypoint_app_service = EntrypointAppService(self)
        self._authorization_service = AuthorizationService(self)
        self._provider_runtime_service = ProviderRuntimeService(self)
        self._identity_auth_service = IdentityAuthService(self)
        self._identity_mapper = IdentityMapper(self)
        self._auth_flow_service = AuthFlowService(self)
        self._ui_renderer = UIRenderer(self)
        self._runtime_version_policy = build_runtime_version_policy_report()
        self._ldap_provider: LdapAuthProvider | None = None
        self._entra_provider: EntraAuthProvider | None = None
        self._policy: RbacPolicy | None = None
        self._ldap_rate_limiter = None
        self._oauth_rate_limiter = None

        try:
            cfg = self._cfg_loader.get_config()
        except Exception as exc:  # pragma: no cover  # noqa: BLE001
            self._config_error_message = (
                str(exc) or "Authentication configuration error"
            )
            log.error(
                "Auth manager started in degraded mode due to configuration error: %s",
                self._config_error_message,
            )
            return

        configure_logging(cfg.general.log_level)

        ldap_client, entra_client, self._provider_load_errors = (
            self._provider_runtime_service.initialize_provider_clients(cfg)
        )
        self._ldap_provider = LdapAuthProvider(self, ldap_client)
        self._entra_provider = EntraAuthProvider(self, entra_client)
        self._policy = RbacPolicy(cfg)

        self._provider_runtime_service.configure_rate_limiters(cfg)

        methods: list[str] = []
        if self._ldap_provider is not None and self._ldap_provider.is_enabled():
            methods.append("ldap")
        if self._entra_provider is not None and self._entra_provider.is_enabled():
            methods.append("entra_id")

        if self._provider_load_errors and not methods:
            self._config_error_message = " | ".join(self._provider_load_errors)

        log.info(
            "Initialized ITIM auth manager; methods=%s strict_permissions=%s reload=%ss schema_version=%s advisories=%d",
            methods,
            cfg.general.strict_permissions,
            cfg.general.config_reload_seconds,
            cfg.meta.schema_version,
            len(cfg.advisories),
        )
        self._log_runtime_capability_report(cfg)

    def _user_model(self) -> type[RbacAuthUser]:
        """Return the concrete authenticated user model."""
        return RbacAuthUser

    @staticmethod
    def _anonymous_user() -> ItimAnonymousUser:
        """Return the anonymous user placeholder."""
        return ItimAnonymousUser()

    def _log_runtime_capability_report(self, cfg: Any) -> None:
        """Log startup capability, version-policy, and compatibility governance reports."""
        capability_report = build_runtime_capability_report(cfg)
        log.info(
            "Runtime capability report: %s",
            ", ".join(
                f"{key}={value}" for key, value in sorted(capability_report.items())
            ),
        )
        self._runtime_version_policy = build_runtime_version_policy_report()
        log.info(
            "Runtime version policy: %s",
            ", ".join(
                f"{key}={value}"
                for key, value in sorted(self._runtime_version_policy.as_dict().items())
            ),
        )
        for advisory in self._runtime_version_policy.advisories:
            log.warning("Runtime version advisory: %s", advisory)

        doctor_report = build_operator_doctor_report(cfg)
        log.info(
            "Compatibility doctor report: %s",
            ", ".join(
                f"{key}={value}"
                for key, value in sorted(doctor_report.as_dict().items())
            ),
        )
        for recommendation in doctor_report.recommendations:
            log.info("Compatibility doctor recommendation: %s", recommendation)
        for advisory in doctor_report.advisories:
            log.warning("Compatibility doctor advisory: %s", advisory)

    # ------------------------------------------------------------------
    # Shared context and request helpers
    # ------------------------------------------------------------------

    def _get_context(self) -> Any | None:
        """Return the Airflow request context object across supported variants."""
        return self._runtime_context_service.get_context()

    @staticmethod
    def _client_ip(request: Request | None) -> str:
        """Return the client IP or an empty string."""
        return RuntimeContextService.client_ip(request)

    def _env_override(self, name: str, default: str = "") -> str:
        """Return a trimmed environment override string."""
        return self._runtime_context_service.env_override(name, default)

    def _ui_environment_label(self) -> str:
        """Return a short environment label shown in the login-page header."""
        return self._runtime_context_service.ui_environment_label()

    def _support_contact_label(self) -> str:
        """Return support contact text shown in the help panel."""
        return self._runtime_context_service.support_contact_label()

    @staticmethod
    def _default_success_redirect_path() -> str:
        """Return the safe default destination after successful authentication."""
        return RuntimeContextService.default_success_redirect_path()

    def _resolve_post_login_redirect_target(
        self,
        *,
        request: Request,
        next_url: str | None,
        trusted_proxies: tuple[str, ...],
    ) -> str:
        """Resolve the final post-login redirect target."""
        return self._runtime_context_service.resolve_post_login_redirect_target(
            request=request,
            next_url=next_url,
            trusted_proxies=trusted_proxies,
        )

    def _auth_config_broken(self) -> bool:
        """Return whether auth manager is running in degraded config-error mode."""
        return self._runtime_context_service.auth_config_broken()

    def _auth_config_error_text(self) -> str:
        """Return the operator-facing configuration error text for login UI."""
        return self._runtime_context_service.auth_config_error_text()

    def _config_error_lines(self) -> list[str]:
        """Split config error text into user-visible lines."""
        return self._runtime_context_service.config_error_lines()

    @staticmethod
    def _make_ui_reference() -> str:
        """Return a short reference token shown in auth UI messages."""
        return RuntimeContextService.make_ui_reference()

    @staticmethod
    def _limit_key(*parts: str) -> str:
        """Build a compact rate-limiter key from logical key parts."""
        return "|".join((part or "-") for part in parts)

    @staticmethod
    def _summarize_list(values: list[str] | tuple[str, ...], limit: int = 6) -> str:
        """Return a readable preview of a list for debug/audit logging."""
        return IdentityAuthService.summarize_list(values, limit)

    def _log_sensitive_values(
        self,
        *,
        label: str,
        principal: str,
        values: list[str] | tuple[str, ...],
    ) -> None:
        """Log raw and fingerprinted external values when sensitive debug is enabled."""
        self._identity_auth_service.log_sensitive_values(
            label=label,
            principal=principal,
            values=values,
        )

    def _configure_rate_limiters(self, cfg: Any) -> None:
        """Create rate limiter backends for LDAP and OAuth flows."""
        self._provider_runtime_service.configure_rate_limiters(cfg)

    def _check_ldap_rate_limit(
        self, *, username: str, request: Request | None
    ) -> tuple[bool, int]:
        """Return whether the LDAP login attempt is allowed."""
        return self._provider_runtime_service.check_ldap_rate_limit(
            username=username, request=request
        )

    def _record_ldap_failure(self, *, username: str, request: Request | None) -> int:
        """Record a failed LDAP login attempt and return any retry-after value."""
        return self._provider_runtime_service.record_ldap_failure(
            username=username, request=request
        )

    def _clear_ldap_failures(self, *, username: str, request: Request | None) -> None:
        """Clear rate-limit state after a successful LDAP login."""
        self._provider_runtime_service.clear_ldap_failures(
            username=username, request=request
        )

    def _check_oauth_rate_limit(self, *, request: Request | None) -> tuple[bool, int]:
        """Return whether the OAuth/SSO start attempt is allowed."""
        return self._provider_runtime_service.check_oauth_rate_limit(request=request)

    def _record_oauth_start(self, *, request: Request | None) -> int:
        """Record an OAuth/SSO login start and return any retry-after value."""
        return self._provider_runtime_service.record_oauth_start(request=request)

    def _debug_log_role_permissions(self, *, username: str, roles: list[str]) -> None:
        """Log final mapped roles and permission expansion for debugging/audit."""
        self._identity_auth_service.debug_log_role_permissions(
            username=username, roles=roles
        )

    def _refresh_if_needed(self) -> None:
        """Refresh providers, policy, and logging when config changes on disk."""
        self._provider_runtime_service.refresh_if_needed()

    @staticmethod
    def _sanitize_next(
        next_url: str | None,
        request: Request,
        *,
        trusted_proxies: tuple[str, ...],
    ) -> str:
        """Return a same-origin safe redirect target."""
        return RuntimeContextService.sanitize_next(
            next_url,
            request,
            trusted_proxies=trusted_proxies,
        )

    @staticmethod
    def _is_secure_request(
        request: Request,
        *,
        trusted_proxies: tuple[str, ...],
    ) -> bool:
        """Determine whether the request should be treated as HTTPS."""
        return RuntimeContextService.is_secure_request(
            request,
            trusted_proxies=trusted_proxies,
        )

    @staticmethod
    def _normalize_entra_claim_value(value: str) -> str:
        """Normalize an Entra role/group claim value for dictionary lookup."""
        return " ".join((value or "").strip().split()).casefold()

    def _effective_external_base(
        self,
        request: Request,
        *,
        trusted_proxies: tuple[str, ...],
    ) -> str:
        """Return the externally visible base URL for callback generation."""
        return self._runtime_context_service.effective_external_base(
            request,
            trusted_proxies=trusted_proxies,
        )

    def _entra_callback_url(self, request: Request) -> str:
        """Return the externally reachable Azure callback URL."""
        return self._runtime_context_service.entra_callback_url(request)

    def _set_auth_cookie(
        self,
        response: RedirectResponse,
        *,
        jwt_token: str,
        secure: bool,
    ) -> None:
        """Write the Airflow auth token cookie."""
        self._runtime_context_service.set_auth_cookie(
            response,
            jwt_token=jwt_token,
            secure=secure,
        )

    def _delete_auth_cookie(self, response: RedirectResponse, *, secure: bool) -> None:
        """Delete the Airflow auth token cookie."""
        self._runtime_context_service.delete_auth_cookie(response, secure=secure)

    # ------------------------------------------------------------------
    # JWT integration and Airflow entrypoint helpers
    # ------------------------------------------------------------------

    def serialize_user(self, user: RbacAuthUser) -> dict[str, Any]:
        """Serialize the current user into JWT claims."""
        return self._user_session_service.serialize_user(user)

    def deserialize_user(self, token: dict[str, Any]) -> RbacAuthUser:
        """Rebuild a request user object from decoded JWT claims."""
        return cast(RbacAuthUser, self._user_session_service.deserialize_user(token))

    def get_user(self) -> RbacAuthUser:
        """Return the authenticated request user or an anonymous placeholder."""
        return cast(RbacAuthUser, self._user_session_service.get_user())

    def is_logged_in(self) -> bool:
        """Return whether the current request contains an authenticated user."""
        return self._user_session_service.is_logged_in()

    def _issue_jwt(self, *, user: RbacAuthUser, expiration_time_in_seconds: int) -> str:
        """Delegate JWT creation to Airflow's configured signing implementation."""
        return self._user_session_service.issue_jwt(
            user=user,
            expiration_time_in_seconds=expiration_time_in_seconds,
        )

    # ------------------------------------------------------------------
    # Role mapping helpers
    # ------------------------------------------------------------------

    def _apply_default_role_if_allowed(
        self, *, principal: str, subject: str, ip_address: str
    ) -> set[str]:
        """Apply the default self-registration role when allowed by config."""
        return self._identity_auth_service.apply_default_role_if_allowed(
            principal=principal,
            subject=subject,
            ip_address=ip_address,
        )

    def _map_ldap_roles(
        self, *, identity: ExternalIdentity, ip_address: str
    ) -> list[str]:
        """Map normalized LDAP groups to Airflow roles with audit logging."""
        return self._identity_auth_service.map_ldap_roles(
            identity=identity, ip_address=ip_address
        )

    def _map_entra_roles(
        self, *, identity: ExternalIdentity, ip_address: str
    ) -> list[str]:
        """Map normalized Entra role/group claims to Airflow roles with audit logging."""
        return self._identity_auth_service.map_entra_roles(
            identity=identity, ip_address=ip_address
        )

    def _authenticate_ldap(
        self,
        *,
        username: str,
        password: str,
        request: Request | None,
    ) -> RbacAuthUser:
        """Authenticate via LDAP provider and return the resolved user object."""
        return self._identity_auth_service.authenticate_ldap(
            username=username,
            password=password,
            request=request,
        )

    def _authenticate_entra_identity(
        self,
        *,
        identity: ExternalIdentity,
        request: Request | None,
    ) -> RbacAuthUser:
        """Resolve an Entra external identity into an authenticated user."""
        return self._identity_auth_service.authenticate_entra_identity(
            identity=identity,
            request=request,
        )

    @property
    def apiserver_endpoint(self) -> str:
        """Return the configured API server base URL."""
        return self._entrypoint_app_service.apiserver_endpoint

    @staticmethod
    def get_cli_commands() -> list[Any]:
        """This auth manager does not expose extra Airflow CLI commands."""
        return EntrypointAppService.get_cli_commands()

    def get_api_endpoints(self) -> None:
        """No legacy Flask API endpoints are registered by this auth manager."""
        return self._entrypoint_app_service.get_api_endpoints()

    @staticmethod
    def get_db_manager() -> str | None:
        """This auth manager does not manage custom DB models."""
        return EntrypointAppService.get_db_manager()

    def register_views(self) -> None:
        """No Flask FAB views are registered; this is a FastAPI auth manager."""
        return self._entrypoint_app_service.register_views()

    def get_extra_menu_items(self, *, user: RbacAuthUser) -> list[ExtraMenuItem]:
        """Return extra UI menu items. None are added by this plugin."""
        return self._entrypoint_app_service.get_extra_menu_items()

    def get_url_login(self, **kwargs: Any) -> str:
        """Return the login URL used by Airflow UI redirection."""
        return self._entrypoint_app_service.get_url_login()

    def get_url_logout(self) -> str | None:
        """Return the logout URL used by Airflow UI."""
        return self._entrypoint_app_service.get_url_logout()

    def create_token(
        self, headers: dict[str, str], body: dict[str, Any]
    ) -> RbacAuthUser:
        """Authenticate username/password for API token issuance."""
        return cast(
            RbacAuthUser, self._entrypoint_app_service.create_token(headers, body)
        )

    def get_fastapi_app(self) -> FastAPI:
        """Expose the auth-manager FastAPI app."""
        return self._entrypoint_app_service.get_fastapi_app()

    # ------------------------------------------------------------------
    # Authorization helpers
    # ------------------------------------------------------------------

    @staticmethod
    def _fab_action(method: ResourceMethod | str) -> str:
        """Map HTTP or auth-manager methods to FAB-style action strings."""
        return AuthorizationService.fab_action(method)

    def _allowed(
        self,
        *,
        user: RbacAuthUser,
        action: str,
        resource: str,
        context: object | None = None,
    ) -> bool:
        """Return whether the given user is allowed to access a resource."""
        return self._authorization_service.allowed(
            user=user,
            action=action,
            resource=resource,
            context=context,
        )

    def is_authorized_view(self, *, access_view: Any, user: RbacAuthUser) -> bool:
        """Authorize read-only UI views using FAB-style semantics."""
        return self._authorization_service.is_authorized_view(
            access_view=access_view, user=user
        )

    def is_authorized_custom_view(
        self,
        *,
        method: ResourceMethod | str,
        resource_name: str,
        user: RbacAuthUser,
    ) -> bool:
        """Authorize a custom Airflow view/resource pair."""
        return self._authorization_service.is_authorized_custom_view(
            method=method,
            resource_name=resource_name,
            user=user,
        )

    def _menu_item_resource(self, menu_item: Any) -> str:
        """Translate a menu item object into the underlying permission resource."""
        return self._authorization_service.menu_item_resource(menu_item)

    def filter_authorized_menu_items(
        self,
        menu_items: list[MenuItem],
        user: RbacAuthUser,
    ) -> list[MenuItem]:
        """Filter UI menu items according to the current RBAC policy."""
        return self._authorization_service.filter_authorized_menu_items(
            menu_items, user
        )

    @provide_session
    def get_authorized_connections(
        self,
        *,
        user: RbacAuthUser,
        method: ResourceMethod = "GET",
        session: Any = NEW_SESSION,
    ) -> set[str]:
        """Return visible connection IDs for the current user."""
        return self._authorization_service.get_authorized_connections(
            user=user,
            method=method,
            session=session,
        )

    @provide_session
    def get_authorized_dag_ids(
        self,
        *,
        user: RbacAuthUser,
        method: ResourceMethod = "GET",
        session: Any = NEW_SESSION,
    ) -> set[str]:
        """Return visible DAG IDs for the current user."""
        return self._authorization_service.get_authorized_dag_ids(
            user=user,
            method=method,
            session=session,
        )

    @provide_session
    def get_authorized_pools(
        self,
        *,
        user: RbacAuthUser,
        method: ResourceMethod = "GET",
        session: Any = NEW_SESSION,
    ) -> set[str]:
        """Return visible pool names for the current user."""
        return self._authorization_service.get_authorized_pools(
            user=user,
            method=method,
            session=session,
        )

    @provide_session
    def get_authorized_variables(
        self,
        *,
        user: RbacAuthUser,
        method: ResourceMethod = "GET",
        session: Any = NEW_SESSION,
    ) -> set[str]:
        """Return visible variable keys for the current user."""
        return self._authorization_service.get_authorized_variables(
            user=user,
            method=method,
            session=session,
        )

    def is_authorized_dag(
        self,
        *,
        method: ResourceMethod,
        user: RbacAuthUser,
        access_entity: Any | None = None,
        details: DagDetails | None = None,
    ) -> bool:
        """Authorize DAG access with FAB-style DAG and DAG-run semantics."""
        return self._authorization_service.is_authorized_dag(
            method=method,
            user=user,
            access_entity=access_entity,
            details=details,
        )

    def is_authorized_connection(
        self,
        *,
        method: ResourceMethod,
        user: RbacAuthUser,
        details: ConnectionDetails | None = None,
    ) -> bool:
        """Authorize access to Connection endpoints."""
        return self._authorization_service.is_authorized_connection(
            method=method,
            user=user,
            details=details,
        )

    def is_authorized_pool(
        self,
        *,
        method: ResourceMethod,
        user: RbacAuthUser,
        details: PoolDetails | None = None,
    ) -> bool:
        """Authorize access to Pool endpoints."""
        return self._authorization_service.is_authorized_pool(
            method=method, user=user, details=details
        )

    def is_authorized_variable(
        self,
        *,
        method: ResourceMethod,
        user: RbacAuthUser,
        details: VariableDetails | None = None,
    ) -> bool:
        """Authorize access to Variable endpoints."""
        return self._authorization_service.is_authorized_variable(
            method=method,
            user=user,
            details=details,
        )

    def is_authorized_configuration(
        self,
        *,
        method: ResourceMethod,
        user: RbacAuthUser,
        details: ConfigurationDetails | None = None,
    ) -> bool:
        """Authorize access to Configuration endpoints."""
        return self._authorization_service.is_authorized_configuration(
            method=method,
            user=user,
            details=details,
        )

    def is_authorized_backfill(
        self,
        *,
        method: ResourceMethod,
        user: RbacAuthUser,
        details: BackfillDetails | None = None,
    ) -> bool:
        """Authorize Backfill endpoints through DAG Run semantics.

        This hook remains for compatibility with current Airflow auth-manager
        surfaces, but the effective permission decision is delegated to DAG Run
        authorization rather than a distinct backfill permission path.
        """
        return self._authorization_service.is_authorized_backfill(
            method=method,
            user=user,
            details=details,
        )

    def is_authorized_asset(
        self,
        *,
        method: ResourceMethod,
        user: RbacAuthUser,
        details: AssetDetails | None = None,
    ) -> bool:
        """Authorize access to Asset endpoints."""
        return self._authorization_service.is_authorized_asset(
            method=method, user=user, details=details
        )

    def is_authorized_asset_alias(
        self,
        *,
        method: ResourceMethod,
        user: RbacAuthUser,
        details: AssetAliasDetails | None = None,
    ) -> bool:
        """Authorize access to Asset Alias endpoints."""
        return self._authorization_service.is_authorized_asset_alias(
            method=method,
            user=user,
            details=details,
        )

    def is_authorized_hitl_task(
        self, *, user: RbacAuthUser, task_instance: Any
    ) -> bool:
        """Authorize access to a HITL task using assigned-user semantics."""
        return self._authorization_service.is_authorized_hitl_task(
            user=user, task_instance=task_instance
        )

    def batch_is_authorized_dag(
        self,
        requests: Sequence[IsAuthorizedDagRequest],
        *,
        user: RbacAuthUser,
    ) -> bool:
        """Batch DAG authorization."""
        return self._authorization_service.batch_is_authorized_dag(requests, user=user)

    def batch_is_authorized_connection(
        self,
        requests: Sequence[IsAuthorizedConnectionRequest],
        *,
        user: RbacAuthUser,
    ) -> bool:
        """Batch authorization for Connection requests."""
        return self._authorization_service.batch_is_authorized_connection(
            requests, user=user
        )

    def batch_is_authorized_pool(
        self,
        requests: Sequence[IsAuthorizedPoolRequest],
        *,
        user: RbacAuthUser,
    ) -> bool:
        """Batch authorization for Pool requests."""
        return self._authorization_service.batch_is_authorized_pool(requests, user=user)

    def batch_is_authorized_variable(
        self,
        requests: Sequence[IsAuthorizedVariableRequest],
        *,
        user: RbacAuthUser,
    ) -> bool:
        """Batch authorization for Variable requests."""
        return self._authorization_service.batch_is_authorized_variable(
            requests, user=user
        )


RbacAuthManager = RbacAuthManager
