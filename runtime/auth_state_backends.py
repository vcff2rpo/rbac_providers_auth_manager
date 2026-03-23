"""Pluggable short-lived auth state stores for browser login flows.

The browser SSO flow needs to keep a small amount of transient state such as
OAuth state, nonce, PKCE verifier, and original redirect target. A cookie-only
approach works well for simple standalone deployments, while multi-worker or
multi-instance deployments benefit from a shared backend.
"""

from __future__ import annotations

import json
import time
from dataclasses import asdict
from threading import Lock

from rbac_providers_auth_manager.identity.models import OAuthFlowState


class MemoryAuthStateStore:
    """Process-local transient auth-state store with TTL-based expiration."""

    def __init__(self) -> None:
        self._items: dict[str, tuple[float, OAuthFlowState]] = {}
        self._lock = Lock()

    def put(self, *, key: str, value: OAuthFlowState, ttl_seconds: int) -> None:
        expires_at = time.time() + max(1, int(ttl_seconds))
        with self._lock:
            self._purge_expired_locked()
            self._items[key] = (expires_at, value)

    def get(self, *, key: str) -> OAuthFlowState | None:
        with self._lock:
            self._purge_expired_locked()
            item = self._items.get(key)
            if item is None:
                return None
            expires_at, value = item
            if expires_at <= time.time():
                self._items.pop(key, None)
                return None
            return value

    def delete(self, *, key: str) -> None:
        with self._lock:
            self._items.pop(key, None)

    def _purge_expired_locked(self) -> None:
        now = time.time()
        expired = [
            key for key, (expires_at, _) in self._items.items() if expires_at <= now
        ]
        for key in expired:
            self._items.pop(key, None)


class RedisAuthStateStore:
    """Redis-backed transient auth-state store for multi-worker deployments."""

    def __init__(self, *, redis_url: str, redis_prefix: str) -> None:
        self.redis_url = (redis_url or "").strip()
        self.redis_prefix = (redis_prefix or "airflow_auth").strip() or "airflow_auth"
        self._client = None
        self._lock = Lock()

    def _redis(self):
        with self._lock:
            if self._client is not None:
                return self._client
            if not self.redis_url:
                raise ValueError(
                    "Redis auth-state backend requires auth_state_redis_url to be configured"
                )
            try:
                import redis  # type: ignore
            except Exception as exc:  # pragma: no cover
                raise ValueError(
                    "Redis auth-state backend requires the redis package to be installed"
                ) from exc
            self._client = redis.Redis.from_url(self.redis_url, decode_responses=True)
            return self._client

    def _item_key(self, key: str) -> str:
        return f"{self.redis_prefix}:oauth_state:{key}"

    def put(self, *, key: str, value: OAuthFlowState, ttl_seconds: int) -> None:
        client = self._redis()
        client.set(
            self._item_key(key), json.dumps(asdict(value)), ex=max(1, int(ttl_seconds))
        )

    def get(self, *, key: str) -> OAuthFlowState | None:
        client = self._redis()
        raw_value = client.get(self._item_key(key))
        if not raw_value:
            return None
        payload = json.loads(raw_value)
        return OAuthFlowState(
            state=str(payload.get("state") or ""),
            nonce=str(payload.get("nonce") or ""),
            next_url=str(payload.get("next_url") or "/"),
            code_verifier=(
                str(payload["code_verifier"]) if payload.get("code_verifier") else None
            ),
        )

    def delete(self, *, key: str) -> None:
        client = self._redis()
        client.delete(self._item_key(key))


def build_auth_state_store(
    *, backend_name: str, redis_url: str | None, redis_prefix: str
):
    """Return a concrete transient auth-state store for the configured backend."""
    normalized_backend = (backend_name or "cookie").strip().lower()
    if normalized_backend in {"cookie", "browser_cookie"}:
        return None
    if normalized_backend in {"memory", "in_memory", "local"}:
        return MemoryAuthStateStore()
    if normalized_backend == "redis":
        return RedisAuthStateStore(redis_url=redis_url or "", redis_prefix=redis_prefix)
    raise ValueError(f"Unsupported auth-state backend: {backend_name}")
