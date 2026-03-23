"""In-process rate-limiter primitives for auth flows."""

from __future__ import annotations

import time
from collections import deque
from dataclasses import dataclass
from threading import Lock


@dataclass(slots=True)
class RateLimitDecision:
    """Structured result returned by the in-process rate limiter."""

    allowed: bool
    retry_after_seconds: int
    reason: str


class SlidingWindowRateLimiter:
    """Small in-process sliding-window rate limiter with optional lockout."""

    def __init__(
        self, *, max_events: int, window_seconds: int, lockout_seconds: int = 0
    ) -> None:
        self.max_events = max(1, int(max_events))
        self.window_seconds = max(1, int(window_seconds))
        self.lockout_seconds = max(0, int(lockout_seconds))
        self._events: dict[str, deque[float]] = {}
        self._locked_until: dict[str, float] = {}
        self._lock = Lock()

    def _prune(self, *, key: str, now: float) -> deque[float]:
        """Remove expired events and expired lockout state for ``key``."""
        queue = self._events.setdefault(key, deque())
        cutoff = now - self.window_seconds
        while queue and queue[0] < cutoff:
            queue.popleft()

        lockout_until = self._locked_until.get(key)
        if lockout_until is not None and lockout_until <= now:
            self._locked_until.pop(key, None)

        if not queue:
            self._events[key] = queue
        return queue

    def check(self, *, key: str) -> RateLimitDecision:
        """Check whether a new event would be allowed without recording it."""
        now = time.time()
        with self._lock:
            self._prune(key=key, now=now)

            lockout_until = self._locked_until.get(key)
            if lockout_until and lockout_until > now:
                retry_after = max(1, int(lockout_until - now))
                return RateLimitDecision(False, retry_after, "locked")

            queue = self._events.get(key) or deque()
            if len(queue) >= self.max_events:
                retry_after = max(1, int(queue[0] + self.window_seconds - now))
                return RateLimitDecision(False, retry_after, "rate_limited")

        return RateLimitDecision(True, 0, "allowed")

    def record_event(self, *, key: str) -> RateLimitDecision:
        """Record a new event and return the updated rate-limit decision."""
        now = time.time()
        with self._lock:
            queue = self._prune(key=key, now=now)

            lockout_until = self._locked_until.get(key)
            if lockout_until and lockout_until > now:
                retry_after = max(1, int(lockout_until - now))
                return RateLimitDecision(False, retry_after, "locked")

            queue.append(now)

            if len(queue) >= self.max_events:
                if self.lockout_seconds > 0:
                    self._locked_until[key] = now + self.lockout_seconds
                    return RateLimitDecision(False, self.lockout_seconds, "locked")

                retry_after = max(1, int(queue[0] + self.window_seconds - now))
                return RateLimitDecision(False, retry_after, "rate_limited")

        return RateLimitDecision(True, 0, "allowed")

    def reset(self, *, key: str) -> None:
        """Remove accumulated state for a key after successful authentication."""
        with self._lock:
            self._events.pop(key, None)
            self._locked_until.pop(key, None)
