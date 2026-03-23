"""Query parsing and status-message resolution for auth UI flows."""

from __future__ import annotations

from typing import Any

from rbac_providers_auth_manager.core.util import parse_csv


class StatusQueryService:
    """Resolve login status values, titles, and messages from request inputs."""

    def __init__(self, manager: Any) -> None:
        self.manager = manager

    @staticmethod
    def retry_after_from_query(raw_value: str | None) -> int:
        """Parse retry-after seconds from query parameters safely."""
        if not raw_value:
            return 0
        try:
            value = int(str(raw_value).strip())
        except (TypeError, ValueError):
            return 0
        return max(0, value)

    @staticmethod
    def status_from_query(
        *, error: str | None, status_value: str | None
    ) -> tuple[str, str]:
        """Map query parameters into a status level and user-facing title."""
        if status_value == "logged_out":
            return "success", "Signed out successfully"
        if status_value == "expired":
            return "warning", "Session expired"
        if status_value == "redirected":
            return "info", "Authentication required"
        if status_value == "success":
            return "success", "Access granted"
        if error == "missing":
            return "warning", "Missing credentials"
        if error == "unauthorized":
            return "warning", "No Airflow access assigned"
        if error == "invalid":
            return "error", "Sign-in failed"
        if error == "csrf":
            return "warning", "Session expired"
        if error == "sso":
            return "error", "Single sign-on failed"
        if error == "ldap_disabled":
            return "warning", "Password login disabled"
        if error == "throttled":
            return "warning", "Too many attempts"
        if error == "config_disabled":
            return "error", "Authentication unavailable"
        return "info", "Sign in"

    @staticmethod
    def status_message_from_query(
        *, error: str | None, status_value: str | None
    ) -> str:
        """Return a polished user-facing status message."""
        if status_value == "logged_out":
            return "You have been signed out."
        if status_value == "expired":
            return "Your session expired. Please sign in again."
        if status_value == "redirected":
            return "Please sign in to continue."
        if status_value == "success":
            return "Authentication succeeded and access was granted."
        if error == "missing":
            return "Enter both username and password."
        if error == "unauthorized":
            return "Authentication succeeded, but no Airflow role is currently mapped to your account."
        if error == "invalid":
            return "Sign-in failed. Check your credentials or try Microsoft sign-in."
        if error == "csrf":
            return "The login session expired before submission. Retry sign-in."
        if error == "sso":
            return "Microsoft sign-in did not complete successfully. Retry once, then contact support."
        if error == "ldap_disabled":
            return "Username/password sign-in is disabled for this deployment."
        if error == "throttled":
            return "Too many sign-in attempts were detected. Wait before retrying or contact support."
        if error == "config_disabled":
            return "At least one authentication method must be enabled for this deployment."
        return ""

    def login_status_method_label(self, method: str | None) -> str:
        """Return a display label for an authentication method identifier."""
        try:
            cfg = self.manager._cfg_loader.get_config()
            ui_cfg = cfg.ui
        except (AssertionError, OSError, ValueError):  # pragma: no cover
            if (method or "").strip().lower() == "entra":
                return "Microsoft Sign-In"
            if (method or "").strip().lower() == "ldap":
                return "LDAP Sign-In"
            return "Authentication"

        normalized = (method or "").strip().lower()
        if normalized == "ldap":
            return ui_cfg.ldap_method_label
        if normalized == "entra":
            return ui_cfg.entra_method_label
        return "Authentication"

    @staticmethod
    def login_status_roles_from_query(raw_value: str | None) -> list[str]:
        """Parse a role summary from a query-string value."""
        if not raw_value:
            return []
        return [item for item in parse_csv(raw_value) if item]

    def login_status_title(
        self,
        *,
        error: str | None,
        status_value: str | None,
        method: str | None,
    ) -> str:
        """Return the rich-status title text for the login panel."""
        try:
            ui_cfg = self.manager._cfg_loader.get_config().ui
        except (AssertionError, OSError, ValueError):  # pragma: no cover
            return self.status_from_query(error=error, status_value=status_value)[1]

        if status_value == "success":
            if error == "unauthorized":
                return ui_cfg.title_no_roles
            return ui_cfg.title_success
        if error in {"invalid", "sso", "config_disabled"}:
            return ui_cfg.title_failure
        if error == "unauthorized":
            return ui_cfg.title_no_roles
        return self.status_from_query(error=error, status_value=status_value)[1]

    def login_status_message(
        self,
        *,
        error: str | None,
        status_value: str | None,
        method: str | None,
        stage: str | None,
    ) -> str:
        """Return the richer configured status message for the login panel."""
        try:
            ui_cfg = self.manager._cfg_loader.get_config().ui
        except (AssertionError, OSError, ValueError):  # pragma: no cover
            return self.status_message_from_query(
                error=error, status_value=status_value
            )

        normalized_method = (method or "").strip().lower()
        normalized_stage = (stage or "").strip().lower()

        if status_value == "success":
            if error == "unauthorized":
                if normalized_method == "ldap":
                    return ui_cfg.ldap_no_roles_text
                if normalized_method == "entra":
                    return ui_cfg.entra_no_roles_text
            else:
                if normalized_method == "ldap":
                    return ui_cfg.ldap_success_text
                if normalized_method == "entra":
                    return ui_cfg.entra_success_text

        if error is None and status_value in {None, "", "ready"}:
            if normalized_method == "ldap":
                return ui_cfg.ldap_ready_text
            if normalized_method == "entra":
                return ui_cfg.entra_ready_text

        if normalized_method == "entra" and normalized_stage in {
            "redirecting",
            "callback",
            "validating_token",
            "mapping_roles",
        }:
            return ui_cfg.entra_progress_text

        return self.status_message_from_query(error=error, status_value=status_value)
