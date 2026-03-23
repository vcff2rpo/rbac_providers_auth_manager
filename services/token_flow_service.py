"""Token-oriented auth flow execution helpers."""

from __future__ import annotations

from typing import Any

from fastapi import HTTPException, Request


class TokenFlowService:
    """Issue API and CLI JWT tokens through the normalized payload builder."""

    def __init__(self, manager: Any) -> None:
        self.manager = manager

    def handle_token(self, request: Request, *, body: dict[str, Any]) -> dict[str, str]:
        """Create an API JWT token for credential-based access."""
        return self._issue_token(request, body=body, cli=False)

    def handle_token_cli(
        self, request: Request, *, body: dict[str, Any]
    ) -> dict[str, str]:
        """Create a CLI JWT token using the CLI-specific expiry setting."""
        return self._issue_token(request, body=body, cli=True)

    def _issue_token(
        self, request: Request, *, body: dict[str, Any], cli: bool
    ) -> dict[str, str]:
        """Create a signed JWT token for API or CLI callers."""
        mode = "cli" if cli else "api"
        principal = str(body.get("username") or "").strip() or None
        ip_address = self.manager._client_ip(request)
        try:
            result = self.manager._flow_payload_builder.issue_token_result(
                request,
                body=body,
                cli=cli,
            )
        except HTTPException as exc:
            detail = exc.detail if isinstance(exc.detail, str) else str(exc.detail)
            self.manager._audit_service.log_token_issue(
                mode=mode,
                principal=principal,
                ip_address=ip_address,
                outcome="failure",
                detail=detail,
            )
            raise

        self.manager._audit_service.log_token_issue(
            mode=mode,
            principal=principal,
            ip_address=ip_address,
            outcome="success",
            detail=result.expiration_key,
        )
        return {"access_token": result.access_token}
