"""Template-backed UI renderer for browser auth pages."""

from __future__ import annotations

import html
from importlib import resources
from string import Template
from typing import Any
from urllib.parse import quote

from fastapi import Request
from fastapi.responses import HTMLResponse

from rbac_providers_auth_manager.compatibility.airflow_public_api import (
    AUTH_MANAGER_FASTAPI_APP_PREFIX,
)
from rbac_providers_auth_manager.api.models import LoginStatusPayload
from rbac_providers_auth_manager.ui.status_presenter import LoginStatusPresenter


_REQUIRED_UI_RENDERER_METHODS: tuple[str, ...] = (
    "render_login_page",
    "render_intermediate_status_page",
    "_render_template",
    "_load_auth_css",
    "_render_help_panel",
)


def validate_ui_renderer_bindings() -> None:
    """Fail fast when required renderer methods are not bound on ``UIRenderer``.

    This protects the runtime package from indentation or refactor mistakes that
    can accidentally turn class methods into module-level functions. Compile-time
    checks will not catch that kind of defect, but the auth flow depends on
    these methods being available on the renderer instance.
    """
    missing = [
        name
        for name in _REQUIRED_UI_RENDERER_METHODS
        if not callable(getattr(UIRenderer, name, None))
    ]
    if missing:
        joined = ", ".join(missing)
        raise RuntimeError(f"UIRenderer is missing required bound methods: {joined}")


class UIRenderer:
    """Render browser-facing auth pages from templates and status helpers."""

    def __init__(self, manager: Any) -> None:
        self.manager = manager
        self._ui_package = resources.files("rbac_providers_auth_manager.ui")
        self._status_presenter = LoginStatusPresenter(manager)

    @property
    def status_presenter(self) -> LoginStatusPresenter:
        """Expose normalized status helpers shared with flow services."""
        return self._status_presenter

    def render_login_page(
        self,
        *,
        request: Request,
        next_url: str | None,
        error: str | None,
        status_value: str | None = None,
        reference: str | None = None,
        status_payload: LoginStatusPayload | None = None,
    ) -> HTMLResponse:
        """Render the interactive login page for LDAP and/or Entra ID."""
        degraded_mode = self.manager._auth_config_broken()

        if degraded_mode:
            ldap_enabled = False
            secure = False
            csrf = ""
            environment_label = self.manager._ui_environment_label()
            help_panel_html = """
            <div class="help-card">
              <div class="help-card-title">Authentication unavailable</div>
              <div class="help-card-section">
                <div class="help-card-subtitle">Configuration issue</div>
                <div>No usable authentication provider is currently available.</div>
              </div>
            </div>
            """
            items = "".join(
                f"<li>{html.escape(line)}</li>"
                for line in self.manager._config_error_lines()
            )
            status_banner_html = f"""
            <div id="itim-status-banner"
                 style="border:1px solid #f5c2c7;background:#f8d7da;color:#842029;
                        padding:12px 14px;border-radius:6px;margin:0 0 14px 0;font-size:13px;">
              <div style="font-weight:700;margin-bottom:6px;">Authentication unavailable</div>
              <ul style="margin:0 0 0 18px;padding:0;">{items}</ul>
            </div>
            """
            provider_note = "Authentication is currently unavailable because no usable login method is configured."
            ldap_form_html = ""
            entra_button_html = ""
            divider_html = ""
        else:
            cfg = self.manager._cfg_loader.get_config()

            ldap_enabled = (
                self.manager._ldap_provider is not None
                and self.manager._ldap_provider.is_enabled()
            )
            entra_enabled = (
                self.manager._entra_provider is not None
                and self.manager._entra_provider.is_enabled()
                and cfg.entra_id is not None
                and cfg.entra_id.enabled
            )

            requested_next = request.query_params.get("next") or next_url
            next_safe = self.manager._sanitize_next(
                requested_next,
                request,
                trusted_proxies=cfg.general.trusted_proxies,
            )
            success_next = self.manager._resolve_post_login_redirect_target(
                request=request,
                next_url=requested_next,
                trusted_proxies=cfg.general.trusted_proxies,
            )

            secure = self.manager._session_service.resolve_cookie_secure(
                request,
                trusted_proxies=cfg.general.trusted_proxies,
            )
            csrf = self.manager._session_service.generate_csrf_token()

            if status_value is None:
                status_value = request.query_params.get("status")
            if reference is None:
                reference = request.query_params.get("ref")

            if status_payload is None:
                retry_after = self.status_presenter.retry_after_from_query(
                    request.query_params.get("retry_after")
                )
                method = request.query_params.get("method")
                stage = request.query_params.get("stage")
                roles = self.status_presenter.login_status_roles_from_query(
                    request.query_params.get("roles")
                )
                auto_redirect_seconds = 1 if status_value == "success" else 0
            else:
                retry_after = status_payload.retry_after
                method = status_payload.method
                stage = status_payload.stage
                roles = list(status_payload.roles)
                status_value = status_payload.status_value
                reference = status_payload.reference
                auto_redirect_seconds = status_payload.auto_redirect_seconds

            status_banner_html = self.status_presenter.render_rich_status_panel(
                error=error,
                status_value=status_value,
                reference=reference,
                retry_after=retry_after,
                method=method,
                stage=stage,
                roles=roles,
                next_url=success_next,
                auto_redirect_seconds=auto_redirect_seconds,
            )
            environment_label = self.manager._ui_environment_label()
            help_panel_html = self._render_help_panel(
                ldap_enabled=ldap_enabled,
                entra_enabled=entra_enabled,
            )

            if ldap_enabled and entra_enabled:
                provider_note = "Use Username / Password for LDAP sign-in or Microsoft Sign-In for enterprise SSO."
            elif ldap_enabled:
                provider_note = "Use your enterprise LDAP credentials. Access is granted through mapped Airflow roles."
            elif entra_enabled:
                provider_note = "Use Microsoft Sign-In. Access is granted through mapped Airflow roles."
            else:
                provider_note = "No sign-in providers are currently enabled."

            ldap_form_html = ""
            if ldap_enabled:
                ldap_form_html = f"""
                <div class="help">
                  {html.escape(cfg.ui.ldap_ready_text)}
                </div>
                <form method="post" action="{AUTH_MANAGER_FASTAPI_APP_PREFIX}/login">
                  <input type="hidden" name="next" value="{html.escape(next_safe)}"/>
                  <input type="hidden" name="csrf" value="{html.escape(csrf)}"/>

                  <label for="username">Username:</label>
                  <div class="input-group">
                    <div class="addon" aria-hidden="true">
                      <svg viewBox="0 0 16 16" role="img" focusable="false">
                        <path fill="currentColor" d="M8 8a3 3 0 1 0-0.001-6A3 3 0 0 0 8 8zm0 1c-2.67 0-5 1.34-5 4v1h10v-1c0-2.66-2.33-4-5-4z"/>
                      </svg>
                    </div>
                    <input id="username" class="input" name="username" autocomplete="username" autofocus />
                  </div>

                  <label for="password">Password:</label>
                  <div class="input-group">
                    <div class="addon" aria-hidden="true">
                      <svg viewBox="0 0 16 16" role="img" focusable="false">
                        <path fill="currentColor" d="M6.5 10.5A3.5 3.5 0 1 1 9.9 6H16v3h-2v2h-2V9h-1V7h-1.1A3.5 3.5 0 0 1 6.5 10.5zm0-5A1.5 1.5 0 1 0 6.5 8a1.5 1.5 0 0 0 0-3z"/>
                      </svg>
                    </div>
                    <input id="password" class="input" type="password" name="password" autocomplete="current-password" />
                  </div>

                  <button class="btn" type="submit">Sign In</button>
                </form>
                """

            entra_button_html = ""
            if entra_enabled and cfg.entra_id is not None:
                oauth_url = (
                    f"{AUTH_MANAGER_FASTAPI_APP_PREFIX}/oauth-login/azure?next="
                    f"{quote(next_safe, safe='')}"
                )
                entra_help_html = ""
                if ldap_enabled:
                    entra_help_html = (
                        '<div class="help">'
                        + html.escape(cfg.ui.entra_ready_text)
                        + "</div>"
                    )

                entra_button_html = (
                    entra_help_html
                    + f'<a href="{html.escape(oauth_url)}" class="sso-btn">'
                    + html.escape(cfg.entra_id.button_text)
                    + "</a>"
                )

            divider_html = (
                '<div class="divider">or</div>'
                if ldap_enabled and entra_enabled
                else ""
            )

        body = self._render_template(
            "login.html",
            page_title="Sign In",
            auth_css=self._load_auth_css(),
            environment_label=html.escape(environment_label),
            provider_note=html.escape(provider_note),
            status_banner_html=status_banner_html,
            ldap_form_html=ldap_form_html,
            divider_html=divider_html,
            entra_button_html=entra_button_html,
            help_panel_html=help_panel_html,
        )

        response = HTMLResponse(body)
        if not degraded_mode and ldap_enabled:
            self.manager._session_service.set_ldap_csrf_cookie(
                response,
                token=csrf,
                secure=secure,
            )
        return response

    def render_intermediate_status_page(
        self,
        *,
        request: Request,
        next_url: str | None,
        title: str,
        message: str,
        method: str | None = None,
        stage: str | None = None,
        redirect_url: str | None = None,
        redirect_delay_seconds: int = 0,
    ) -> HTMLResponse:
        """Render the compact intermediate status page used during Entra redirects."""
        environment_label = self.manager._ui_environment_label()
        provider_note = "Microsoft sign-in is being prepared. Your Airflow access is granted through mapped roles."

        compact_segments: list[str] = []
        if method:
            compact_segments.append(
                "<strong>Method:</strong> "
                + html.escape(self.status_presenter.login_status_method_label(method))
            )
        if stage:
            compact_segments.append(
                "<strong>Step:</strong> "
                + html.escape(stage.replace("_", " ").strip().title())
            )
        compact_segments.append(
            "<strong>Environment:</strong> " + html.escape(environment_label)
        )

        redirect_html = ""
        if redirect_url and redirect_delay_seconds > 0:
            delay_ms = redirect_delay_seconds * 1000
            safe_redirect = html.escape(redirect_url)
            redirect_html = f"""
            <div style="margin-top:8px;font-size:13px;">
              Redirecting in <strong>{redirect_delay_seconds}s</strong>…
            </div>
            <script>
            window.setTimeout(function() {{
              window.location.replace("{safe_redirect}");
            }}, {delay_ms});
            </script>
            """

        status_banner_html = (
            '<div id="itim-status-banner" '
            'style="border:1px solid #b6d4fe;background:#cfe2ff;color:#084298;'
            'padding:12px 14px;border-radius:6px;margin:0 0 14px 0;font-size:13px;">'
            '<div id="itim-status-message" '
            'style="font-size:13px;line-height:1.45;white-space:nowrap;overflow-x:auto;overflow-y:hidden;">'
            f"<strong>{html.escape(title)}</strong>: {html.escape(message)}"
            "</div>"
            '<div style="margin-top:6px;font-size:13px;line-height:1.45;white-space:nowrap;overflow-x:auto;overflow-y:hidden;">'
            + " | ".join(compact_segments)
            + "</div>"
            + redirect_html
            + "</div>"
        )

        body = self._render_template(
            "intermediate.html",
            page_title="Sign In",
            auth_css=self._load_auth_css(),
            environment_label=html.escape(environment_label),
            provider_note=html.escape(provider_note),
            status_banner_html=status_banner_html,
        )
        return HTMLResponse(body)

    def _render_template(self, template_name: str, **context: str) -> str:
        """Render a file-backed HTML template using a string-safe mapping."""
        template = Template(self._read_ui_resource(f"templates/{template_name}"))
        return template.safe_substitute(context)

    def _load_auth_css(self) -> str:
        """Return the shared auth page stylesheet contents."""
        return self._read_ui_resource("static/auth.css")

    def _read_ui_resource(self, relative_path: str) -> str:
        """Read a packaged UI resource from the installed package."""
        return self._ui_package.joinpath(relative_path).read_text(encoding="utf-8")

    def _render_help_panel(self, *, ldap_enabled: bool, entra_enabled: bool) -> str:
        """Return the right-side help panel for the login page."""
        methods: list[str] = []
        if ldap_enabled:
            methods.append("Username / Password (LDAP)")
        if entra_enabled:
            methods.append("Microsoft Sign-In (Entra ID)")

        method_lines = "".join(f"<li>{html.escape(item)}</li>" for item in methods)
        if not method_lines:
            method_lines = "<li>No sign-in methods are currently enabled.</li>"

        return f"""
        <div class="help-card">
          <div class="help-card-title">Help</div>

          <div class="help-card-section">
            <div class="help-card-subtitle">Available sign-in methods</div>
            <ul>{method_lines}</ul>
          </div>

          <div class="help-card-section">
            <div class="help-card-subtitle">Access model</div>
            <div>Your effective access depends on mapped Airflow roles.</div>
          </div>

          <div class="help-card-section">
            <div class="help-card-subtitle">Support</div>
            <div>{html.escape(self.manager._support_contact_label())}</div>
          </div>
        </div>
        """
