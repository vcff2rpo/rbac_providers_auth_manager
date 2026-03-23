"""Pluggable rate-limit backends for authentication flows.

This module provides a small abstraction layer over rate limiting so the plugin
can keep the simple in-memory behavior by default while also supporting a
shared Redis-backed implementation for multi-process deployments.
"""

from __future__ import annotations

import time
import uuid
from threading import Lock

from rbac_providers_auth_manager.runtime.security import (
    RateLimitDecision,
    SlidingWindowRateLimiter,
)


class RedisSlidingWindowRateLimiter:
    """Redis-backed sliding-window limiter with optional lockout."""

    def __init__(
        self,
        *,
        redis_url: str,
        redis_prefix: str,
        scope: str,
        max_events: int,
        window_seconds: int,
        lockout_seconds: int = 0,
    ) -> None:
        self.max_events = max(1, int(max_events))
        self.window_seconds = max(1, int(window_seconds))
        self.lockout_seconds = max(0, int(lockout_seconds))
        self.redis_url = (redis_url or "").strip()
        self.redis_prefix = (redis_prefix or "airflow_auth").strip() or "airflow_auth"
        self.scope = (scope or "auth").strip() or "auth"
        self._client = None
        self._lock = Lock()

    def _redis(self):
        with self._lock:
            if self._client is not None:
                return self._client
            if not self.redis_url:
                raise ValueError(
                    "Redis rate-limit backend requires redis_url to be configured"
                )
            try:
                import redis  # type: ignore
            except Exception as exc:  # pragma: no cover
                raise ValueError(
                    "Redis rate-limit backend requires the redis package to be installed"
                ) from exc
            self._client = redis.Redis.from_url(self.redis_url, decode_responses=True)
            return self._client

    def _events_key(self, key: str) -> str:
        return f"{self.redis_prefix}:{self.scope}:events:{key}"

    def _lock_key(self, key: str) -> str:
        return f"{self.redis_prefix}:{self.scope}:lock:{key}"

    def check(self, *, key: str) -> RateLimitDecision:
        client = self._redis()
        now = time.time()
        events_key = self._events_key(key)
        lock_key = self._lock_key(key)
        cutoff = now - self.window_seconds

        pipe = client.pipeline()
        pipe.zremrangebyscore(events_key, 0, cutoff)
        pipe.get(lock_key)
        pipe.zcard(events_key)
        pipe.zrange(events_key, 0, 0, withscores=True)
        _, lockout_until, count, oldest = pipe.execute()

        if lockout_until:
            try:
                locked_until = float(lockout_until)
            except (TypeError, ValueError):
                locked_until = 0.0
            if locked_until > now:
                return RateLimitDecision(
                    False, max(1, int(locked_until - now)), "locked"
                )
            client.delete(lock_key)

        if int(count or 0) >= self.max_events:
            oldest_score = float(oldest[0][1]) if oldest else now
            retry_after = max(1, int(oldest_score + self.window_seconds - now))
            return RateLimitDecision(False, retry_after, "rate_limited")

        return RateLimitDecision(True, 0, "allowed")

    def record_event(self, *, key: str) -> RateLimitDecision:
        client = self._redis()
        now = time.time()
        events_key = self._events_key(key)
        lock_key = self._lock_key(key)
        cutoff = now - self.window_seconds
        event_member = f"{now}:{uuid.uuid4().hex}"

        pipe = client.pipeline()
        pipe.zremrangebyscore(events_key, 0, cutoff)
        pipe.get(lock_key)
        pipe.zadd(events_key, {event_member: now})
        pipe.zcard(events_key)
        pipe.zrange(events_key, 0, 0, withscores=True)
        pipe.expire(events_key, max(self.window_seconds, self.lockout_seconds) + 60)
        _, lockout_until, _, count, oldest, _ = pipe.execute()

        if lockout_until:
            try:
                locked_until = float(lockout_until)
            except (TypeError, ValueError):
                locked_until = 0.0
            if locked_until > now:
                return RateLimitDecision(
                    False, max(1, int(locked_until - now)), "locked"
                )
            client.delete(lock_key)

        if int(count or 0) >= self.max_events:
            if self.lockout_seconds > 0:
                locked_until = now + self.lockout_seconds
                client.set(lock_key, str(locked_until), ex=self.lockout_seconds + 1)
                return RateLimitDecision(False, self.lockout_seconds, "locked")
            oldest_score = float(oldest[0][1]) if oldest else now
            retry_after = max(1, int(oldest_score + self.window_seconds - now))
            return RateLimitDecision(False, retry_after, "rate_limited")

        return RateLimitDecision(True, 0, "allowed")

    def reset(self, *, key: str) -> None:
        client = self._redis()
        client.delete(self._events_key(key), self._lock_key(key))


def build_rate_limiter(
    *,
    backend_name: str,
    redis_url: str | None,
    redis_prefix: str,
    scope: str,
    max_events: int,
    window_seconds: int,
    lockout_seconds: int,
):
    """Return a concrete rate limiter for the configured backend."""
    normalized_backend = (backend_name or "memory").strip().lower()
    if normalized_backend in {"memory", "in_memory", "local"}:
        return SlidingWindowRateLimiter(
            max_events=max_events,
            window_seconds=window_seconds,
            lockout_seconds=lockout_seconds,
        )
    if normalized_backend == "redis":
        return RedisSlidingWindowRateLimiter(
            redis_url=redis_url or "",
            redis_prefix=redis_prefix,
            scope=scope,
            max_events=max_events,
            window_seconds=window_seconds,
            lockout_seconds=lockout_seconds,
        )
    raise ValueError(f"Unsupported rate-limit backend: {backend_name}")
