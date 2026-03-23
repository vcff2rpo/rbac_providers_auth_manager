"""Session revocation backends used for forced logout on sensitive reload.

The auth manager issues stateless JWTs. To invalidate already-issued tokens after
security-sensitive configuration changes, the runtime maintains a monotonic
revocation epoch. Freshly issued tokens carry the current epoch and stale tokens
are rejected on their next use.
"""

from __future__ import annotations

from threading import Lock


class MemorySessionRevocationStore:
    """Process-local session revocation store backed by a monotonic counter."""

    def __init__(self) -> None:
        self._epoch = 0
        self._lock = Lock()

    def get_epoch(self) -> int:
        with self._lock:
            return int(self._epoch)

    def bump_epoch(self) -> int:
        with self._lock:
            self._epoch += 1
            return int(self._epoch)


class RedisSessionRevocationStore:
    """Redis-backed session revocation store for multi-worker deployments."""

    def __init__(self, *, redis_url: str, redis_prefix: str) -> None:
        self.redis_url = (redis_url or "").strip()
        self.redis_prefix = (
            redis_prefix or "airflow_auth_revocation"
        ).strip() or "airflow_auth_revocation"
        self._client = None
        self._lock = Lock()

    def _redis(self):
        with self._lock:
            if self._client is not None:
                return self._client
            if not self.redis_url:
                raise ValueError(
                    "Redis session revocation backend requires session_revocation_redis_url to be configured"
                )
            try:
                import redis  # type: ignore
            except Exception as exc:  # pragma: no cover
                raise ValueError(
                    "Redis session revocation backend requires the redis package to be installed"
                ) from exc
            self._client = redis.Redis.from_url(self.redis_url, decode_responses=True)
            return self._client

    def _item_key(self) -> str:
        return f"{self.redis_prefix}:session_revocation_epoch"

    def get_epoch(self) -> int:
        client = self._redis()
        raw_value = client.get(self._item_key())
        try:
            return int(raw_value or 0)
        except (TypeError, ValueError):
            return 0

    def bump_epoch(self) -> int:
        client = self._redis()
        return int(client.incr(self._item_key()))


def build_session_revocation_store(
    *, backend_name: str, redis_url: str | None, redis_prefix: str
):
    """Return a concrete session revocation store for the configured backend."""
    normalized_backend = (backend_name or "memory").strip().lower()
    if normalized_backend in {"memory", "in_memory", "local"}:
        return MemorySessionRevocationStore()
    if normalized_backend == "redis":
        return RedisSessionRevocationStore(
            redis_url=redis_url or "",
            redis_prefix=redis_prefix,
        )
    raise ValueError(f"Unsupported session revocation backend: {backend_name}")
