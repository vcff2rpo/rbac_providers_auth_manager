"""HTML banner rendering for auth UI status panels."""

from __future__ import annotations

import html
from typing import Any


class StatusPanelRenderer:
    """Render rich and fallback status banners for the login UI."""

    def __init__(self, manager: Any, query_service: Any) -> None:
        self.manager = manager
        self.query_service = query_service

    def render_status_banner(
        self,
        *,
        error: str | None,
        status_value: str | None,
        reference: str | None,
        retry_after: int = 0,
    ) -> str:
        """Return a styled login-page banner for success, info, warning, or error states."""
        level, title = self.query_service.status_from_query(
            error=error, status_value=status_value
        )
        message = self.query_service.status_message_from_query(
            error=error, status_value=status_value
        )
        if not message:
            return ""

        styles = {
            "success": "border:1px solid #badbcc;background:#d1e7dd;color:#0f5132;",
            "info": "border:1px solid #b6d4fe;background:#cfe2ff;color:#084298;",
            "warning": "border:1px solid #ffecb5;background:#fff3cd;color:#664d03;",
            "error": "border:1px solid #f5c2c7;background:#f8d7da;color:#842029;",
        }

        banner_id = "itim-status-banner"
        message_id = "itim-status-message"
        countdown_wrapper_id = "itim-retry-wrapper"
        countdown_id = "itim-retry-after"
        reference_id = "itim-status-reference"

        countdown_html = ""
        if error == "throttled" and retry_after > 0:
            countdown_html = f"""
            <div id="{countdown_wrapper_id}" style="margin-top:8px;font-size:13px;">
              Retry available in
              <strong><span id="{countdown_id}">{retry_after}</span>s</strong>.
            </div>
            <script>
            (function() {{
              var banner = document.getElementById("{banner_id}");
              var messageEl = document.getElementById("{message_id}");
              var retryWrapper = document.getElementById("{countdown_wrapper_id}");
              var counterEl = document.getElementById("{countdown_id}");
              var referenceEl = document.getElementById("{reference_id}");
              if (!banner || !messageEl || !counterEl) return;
              var remaining = parseInt(counterEl.textContent || "0", 10);
              if (!Number.isFinite(remaining) || remaining <= 0) return;
              var timer = window.setInterval(function() {{
                remaining -= 1;
                if (remaining <= 0) {{
                  counterEl.textContent = "0";
                  window.clearInterval(timer);
                  banner.style.border = "1px solid #badbcc";
                  banner.style.background = "#d1e7dd";
                  banner.style.color = "#0f5132";
                  messageEl.textContent = "You can retry sign-in now. Reloading…";
                  if (retryWrapper) {{
                    retryWrapper.innerHTML = "<strong>Retry is now available.</strong>";
                  }}
                  if (referenceEl) {{
                    referenceEl.style.opacity = "0.85";
                  }}
                  window.setTimeout(function() {{
                    var url = new URL(window.location.href);
                    url.searchParams.delete("error");
                    url.searchParams.delete("ref");
                    url.searchParams.delete("retry_after");
                    url.searchParams.delete("status");
                    window.location.replace(url.pathname + (url.search ? url.search : ""));
                  }}, 1200);
                  return;
                }}
                counterEl.textContent = String(remaining);
              }}, 1000);
            }})();
            </script>
            """

        ref_html = (
            f'<div id="{reference_id}" style="margin-top:6px;font-size:12px;opacity:0.9;">Reference: {html.escape(reference)}</div>'
            if reference
            else ""
        )
        return (
            f'<div id="{banner_id}" style="{styles.get(level, styles["info"])}'
            'padding:12px 14px;border-radius:6px;margin:0 0 14px 0;font-size:13px;">'
            f'<div style="font-weight:700;margin-bottom:4px;">{html.escape(title)}</div>'
            f'<div id="{message_id}">{html.escape(message)}</div>'
            f"{countdown_html}"
            f"{ref_html}"
            "</div>"
        )

    def render_rich_status_panel(
        self,
        *,
        error: str | None,
        status_value: str | None,
        reference: str | None,
        retry_after: int = 0,
        method: str | None = None,
        stage: str | None = None,
        roles: list[str] | tuple[str, ...] = (),
        next_url: str | None = None,
        auto_redirect_seconds: int = 0,
    ) -> str:
        """Return the rich login-page status panel driven by UI config."""
        cfg = self.manager._cfg_loader.get_config()
        ui_cfg = cfg.ui

        if not ui_cfg.enable_rich_login_status:
            return self.render_status_banner(
                error=error,
                status_value=status_value,
                reference=reference,
                retry_after=retry_after,
            )

        level, fallback_title = self.query_service.status_from_query(
            error=error,
            status_value=status_value,
        )
        title = (
            self.query_service.login_status_title(
                error=error,
                status_value=status_value,
                method=method,
            )
            or fallback_title
        )
        message = self.query_service.login_status_message(
            error=error,
            status_value=status_value,
            method=method,
            stage=stage,
        )
        if not message and not roles:
            return ""

        styles = {
            "success": "border:1px solid #badbcc;background:#d1e7dd;color:#0f5132;",
            "info": "border:1px solid #b6d4fe;background:#cfe2ff;color:#084298;",
            "warning": "border:1px solid #ffecb5;background:#fff3cd;color:#664d03;",
            "error": "border:1px solid #f5c2c7;background:#f8d7da;color:#842029;",
        }

        role_items = [item.strip() for item in roles if item.strip()]
        compact_details_enabled = bool(ui_cfg.compact_status_details_line)
        compact_success_enabled = bool(ui_cfg.compact_success_status_line)
        use_compact_line = compact_details_enabled and (
            status_value != "success" or compact_success_enabled
        )

        compact_segments: list[str] = []
        if ui_cfg.show_auth_method and method:
            compact_segments.append(
                "<strong>Method:</strong> "
                + html.escape(self.query_service.login_status_method_label(method))
            )
        if stage:
            compact_segments.append(
                "<strong>Step:</strong> "
                + html.escape(stage.replace("_", " ").strip().title())
            )
        if ui_cfg.show_mapped_roles and role_items:
            compact_segments.append(
                "<strong>Mapped roles:</strong> " + html.escape(", ".join(role_items))
            )
        if ui_cfg.show_reference_id and reference:
            compact_segments.append(
                "<strong>Reference:</strong> " + html.escape(reference)
            )
        if ui_cfg.show_environment:
            compact_segments.append(
                "<strong>Environment:</strong> "
                + html.escape(self.manager._ui_environment_label())
            )

        details_html = ""
        method_html = ""
        stage_html = ""
        roles_html = ""
        environment_html = ""
        ref_html = ""

        if not use_compact_line:
            if ui_cfg.show_auth_method and method:
                method_html = (
                    '<div style="margin-top:6px;font-size:13px;"><strong>Method:</strong> '
                    + html.escape(self.query_service.login_status_method_label(method))
                    + "</div>"
                )
            if stage:
                stage_html = (
                    '<div style="margin-top:6px;font-size:13px;"><strong>Step:</strong> '
                    + html.escape(stage.replace("_", " ").strip().title())
                    + "</div>"
                )
            if ui_cfg.show_mapped_roles and role_items:
                roles_html = (
                    '<div style="margin-top:6px;font-size:13px;"><strong>Mapped roles:</strong> '
                    + html.escape(", ".join(role_items))
                    + "</div>"
                )
            if ui_cfg.show_environment:
                environment_html = (
                    '<div style="margin-top:6px;font-size:13px;"><strong>Environment:</strong> '
                    + html.escape(self.manager._ui_environment_label())
                    + "</div>"
                )
            if ui_cfg.show_reference_id and reference:
                ref_html = (
                    '<div id="itim-status-reference" style="margin-top:6px;font-size:12px;opacity:0.9;">Reference: '
                    + html.escape(reference)
                    + "</div>"
                )
        elif compact_segments:
            details_html = (
                '<div style="margin-top:6px;font-size:13px;line-height:1.45;white-space:nowrap;overflow-x:auto;overflow-y:hidden;">'
                + " | ".join(compact_segments)
                + "</div>"
            )

        countdown_html = ""
        if error == "throttled" and retry_after > 0:
            countdown_html = f"""
            <div id="itim-retry-wrapper" style="margin-top:8px;font-size:13px;">
              Retry available in
              <strong><span id="itim-retry-after">{retry_after}</span>s</strong>.
            </div>
            <script>
            (function() {{
              var banner = document.getElementById("itim-status-banner");
              var messageEl = document.getElementById("itim-status-message");
              var retryWrapper = document.getElementById("itim-retry-wrapper");
              var counterEl = document.getElementById("itim-retry-after");
              if (!banner || !messageEl || !counterEl) return;
              var remaining = parseInt(counterEl.textContent || "0", 10);
              if (!Number.isFinite(remaining) || remaining <= 0) return;
              var timer = window.setInterval(function() {{
                remaining -= 1;
                if (remaining <= 0) {{
                  counterEl.textContent = "0";
                  window.clearInterval(timer);
                  banner.style.border = "1px solid #badbcc";
                  banner.style.background = "#d1e7dd";
                  banner.style.color = "#0f5132";
                  messageEl.textContent = "You can retry sign-in now. Reloading…";
                  if (retryWrapper) {{
                    retryWrapper.innerHTML = "<strong>Retry is now available.</strong>";
                  }}
                  window.setTimeout(function() {{
                    var url = new URL(window.location.href);
                    url.searchParams.delete("error");
                    url.searchParams.delete("ref");
                    url.searchParams.delete("retry_after");
                    url.searchParams.delete("status");
                    window.location.replace(url.pathname + (url.search ? url.search : ""));
                  }}, 1200);
                  return;
                }}
                counterEl.textContent = String(remaining);
              }}, 1000);
            }})();
            </script>
            """

        redirect_html = ""
        if auto_redirect_seconds > 0 and next_url:
            delay_ms = auto_redirect_seconds * 1000
            safe_redirect = html.escape(next_url)
            redirect_html = f"""
            <div style="margin-top:8px;font-size:13px;">
              Redirecting in <strong>{auto_redirect_seconds}s</strong>…
            </div>
            <script>
            window.setTimeout(function() {{
              window.location.replace("{safe_redirect}");
            }}, {delay_ms});
            </script>
            """

        title_html = html.escape(title)
        message_html = html.escape(message)
        if use_compact_line:
            inline_segments = [f"<strong>{title_html}</strong>: {message_html}"]
            headline_html = (
                '<div id="itim-status-message" '
                'style="font-size:13px;line-height:1.45;white-space:nowrap;overflow-x:auto;overflow-y:hidden;">'
                + " | ".join(inline_segments)
                + "</div>"
            )
        else:
            headline_html = (
                f'<div style="font-weight:700;margin-bottom:4px;">{title_html}</div>'
                f'<div id="itim-status-message">{message_html}</div>'
            )

        return (
            f'<div id="itim-status-banner" style="{styles.get(level, styles["info"])}'
            'padding:12px 14px;border-radius:6px;margin:0 0 14px 0;font-size:13px;">'
            f"{headline_html}"
            f"{details_html}"
            f"{method_html}"
            f"{stage_html}"
            f"{roles_html}"
            f"{environment_html}"
            f"{countdown_html}"
            f"{ref_html}"
            f"{redirect_html}"
            "</div>"
        )
