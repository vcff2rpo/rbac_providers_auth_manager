"""User/JWT/session helpers used by the Airflow auth-manager entrypoint."""

from __future__ import annotations

from typing import Any, cast


class UserSessionService:
    """Own user serialization, deserialization, and request-user reconstruction."""

    def __init__(self, manager: Any) -> None:
        self.manager = manager

    def serialize_user(self, user: Any) -> dict[str, Any]:
        """Serialize the current user into JWT claims."""
        return {
            "sub": user.user_id,
            "username": user.username,
            "first_name": user.first_name,
            "last_name": user.last_name,
            "email": user.email,
            "roles": list(user.roles),
        }

    def deserialize_user(self, token: dict[str, Any]) -> Any:
        """Rebuild a request user object from decoded JWT claims."""
        subject = str(token.get("sub") or token.get("user_id") or "")
        if not subject:
            return cast(Any, self.manager._anonymous_user())

        roles = token.get("roles") or []
        if isinstance(roles, str):
            roles = [role.strip() for role in roles.split(",") if role.strip()]

        return self.manager._user_model()(  # type: ignore[misc]
            user_id=subject,
            username=str(token.get("username") or subject),
            first_name=cast(str | None, token.get("first_name")),
            last_name=cast(str | None, token.get("last_name")),
            email=cast(str | None, token.get("email")),
            roles=tuple(sorted(str(role) for role in roles)),
        )

    def get_user(self) -> Any:
        """Return the authenticated request user or an anonymous placeholder."""
        context = self.manager._get_context()
        if context is not None:
            cached_user = getattr(context, "_itim_cached_user", None)
            if isinstance(cached_user, self.manager._user_model()):
                return cached_user

        user = getattr(context, "user", None) if context else None
        if isinstance(user, self.manager._user_model()):
            resolved_user = user
        else:
            resolved_user = cast(Any, self.manager._anonymous_user())

        if context is not None:
            setattr(context, "_itim_cached_user", resolved_user)
        return resolved_user

    def is_logged_in(self) -> bool:
        """Return whether the current request contains an authenticated user."""
        return not self.get_user().is_anonymous

    def issue_jwt(self, *, user: Any, expiration_time_in_seconds: int) -> str:
        """Delegate JWT creation to Airflow's configured signing implementation."""
        return self.manager.generate_jwt(
            user=user,
            expiration_time_in_seconds=expiration_time_in_seconds,
        )
