"""Redirect and proxy-awareness helpers for authentication flows."""

from __future__ import annotations

from urllib.parse import unquote, urljoin, urlsplit

from fastapi import Request
from rbac_providers_auth_manager.compatibility.airflow_public_api import airflow_conf
from rbac_providers_auth_manager.core.util import ip_in_trusted_proxies

_WHATWG_C0_CONTROL_OR_SPACE = (
    "\x00\x01\x02\x03\x04\x05\x06\x07\x08\t\n\x0b\x0c"
    "\r\x0e\x0f\x10\x11\x12\x13\x14\x15\x16\x17\x18\x19\x1a\x1b\x1c\x1d\x1e\x1f "
)


class RedirectService:
    """Centralize redirect safety and proxy-aware URL calculations."""

    @staticmethod
    def sanitize_next(
        next_url: str | None,
        request: Request,
        *,
        trusted_proxies: tuple[str, ...],
    ) -> str:
        """Return a same-origin safe redirect target."""
        if not next_url:
            return "/"
        if ";" in unquote(next_url):
            return "/"

        cleaned = next_url.lstrip(_WHATWG_C0_CONTROL_OR_SPACE)

        client_ip = getattr(getattr(request, "client", None), "host", "") or ""
        trust_forwarded = bool(trusted_proxies) and ip_in_trusted_proxies(
            client_ip,
            trusted_proxies,
        )

        scheme = request.url.scheme
        host = request.url.netloc
        if trust_forwarded:
            forwarded_proto = (
                (request.headers.get("x-forwarded-proto") or "")
                .split(",")[0]
                .strip()
                .lower()
            )
            if forwarded_proto in {"http", "https"}:
                scheme = forwarded_proto

            forwarded_host = (
                (request.headers.get("x-forwarded-host") or "").split(",")[0].strip()
            )
            if forwarded_host:
                host = forwarded_host

        base_url = f"{scheme}://{host}/"
        host_parts = urlsplit(base_url)
        redirect_parts = urlsplit(urljoin(base_url, cleaned))

        if not (
            redirect_parts.scheme in {"http", "https"}
            and host_parts.netloc == redirect_parts.netloc
        ):
            return "/"

        output = redirect_parts.path or "/"
        if redirect_parts.query:
            output += "?" + redirect_parts.query
        if redirect_parts.fragment:
            output += "#" + redirect_parts.fragment

        return output if output.startswith("/") else "/"

    @staticmethod
    def is_secure_request(
        request: Request,
        *,
        trusted_proxies: tuple[str, ...],
    ) -> bool:
        """Determine whether the request should be treated as HTTPS."""
        client_ip = getattr(getattr(request, "client", None), "host", "") or ""
        trust_forwarded = bool(trusted_proxies) and ip_in_trusted_proxies(
            client_ip,
            trusted_proxies,
        )

        if trust_forwarded:
            forwarded_proto = (
                (
                    request.headers.get("x-forwarded-proto")
                    or request.headers.get("x-forwarded-protocol")
                    or ""
                )
                .split(",")[0]
                .strip()
                .lower()
            )
            if forwarded_proto == "https":
                return True

            if (request.headers.get("x-forwarded-ssl") or "").strip().lower() == "on":
                return True

        if request.base_url.scheme == "https":
            return True

        return bool(airflow_conf.get("api", "ssl_cert", fallback=""))

    @staticmethod
    def effective_external_base(
        request: Request,
        *,
        trusted_proxies: tuple[str, ...],
    ) -> str:
        """Return the externally visible base URL for callback generation."""
        client_ip = getattr(getattr(request, "client", None), "host", "") or ""
        trust_forwarded = bool(trusted_proxies) and ip_in_trusted_proxies(
            client_ip,
            trusted_proxies,
        )

        scheme = request.url.scheme
        host = request.url.netloc
        if trust_forwarded:
            forwarded_proto = (
                (request.headers.get("x-forwarded-proto") or "")
                .split(",")[0]
                .strip()
                .lower()
            )
            if forwarded_proto in {"http", "https"}:
                scheme = forwarded_proto

            forwarded_host = (
                (request.headers.get("x-forwarded-host") or "").split(",")[0].strip()
            )
            if forwarded_host:
                host = forwarded_host

        return f"{scheme}://{host}"
