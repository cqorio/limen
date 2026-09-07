"""In-process ``Store``: fixed-window counters + short-lived key/value.

Thread-safe (every access takes the lock). Expired entries are swept periodically, so memory is bounded by the
number of LIVE (unexpired) keys — an attacker who fans out over many distinct keys can only grow it in
proportion to their rate over one window, not without bound. Perfect for a single process and tests; use
``RedisStore`` to share state across workers/replicas. Monotonic clock (immune to wall-clock changes).

    >>> from limen.adapters.memory_store import MemoryStore
    >>> s = MemoryStore()
    >>> s.incr("k", 60), s.incr("k", 60), s.get("k")   # fixed-window counter
    (1, 2, 2)
    >>> s.set_str("v", "hello", 60)
    >>> s.get_str("v")
    'hello'
"""
from __future__ import annotations

import threading
import time


class MemoryStore:
    _PURGE_EVERY = 1024  # sweep expired keys once every N mutating ops (amortized O(1))

    def __init__(self) -> None:
        self._counters: dict[str, tuple[int, float]] = {}   # key -> (count, expires_at)
        self._kv: dict[str, tuple[str, float]] = {}          # key -> (value, expires_at)
        self._lock = threading.Lock()
        self._ops = 0

    def _maybe_purge(self, now: float) -> None:
        """Caller must hold the lock. Drop every expired entry once per _PURGE_EVERY mutations."""
        self._ops += 1
        if self._ops % self._PURGE_EVERY:
            return
        self._counters = {k: v for k, v in self._counters.items() if v[1] > now}
        self._kv = {k: v for k, v in self._kv.items() if v[1] > now}

    def incr(self, key: str, window_s: int) -> int:
        now = time.monotonic()
        with self._lock:
            self._maybe_purge(now)
            entry = self._counters.get(key)
            if entry is None or entry[1] <= now:
                self._counters[key] = (1, now + window_s)
                return 1
            count = entry[0] + 1
            self._counters[key] = (count, entry[1])
            return count

    def get(self, key: str) -> int:
        with self._lock:
            entry = self._counters.get(key)
            if entry is None or entry[1] <= time.monotonic():
                return 0
            return entry[0]

    def set_str(self, key: str, value: str, ttl_s: int) -> None:
        with self._lock:
            now = time.monotonic()
            self._maybe_purge(now)
            self._kv[key] = (value, now + ttl_s)

    def get_str(self, key: str) -> str | None:
        with self._lock:
            entry = self._kv.get(key)
            if entry is None or entry[1] <= time.monotonic():
                return None
            return entry[0]
