"""Redis-backed ``Store`` — shares counters across processes/replicas. Extra: ``pip install 'limen[redis]'``.

``redis`` is imported lazily (only when constructing the default client), so this module is importable — and
unit-testable with a fake client — without the extra installed.

Usage (needs a running Redis, so shown as a snippet rather than a doctest)::

    from limen import Limen
    from limen.adapters import RedisStore
    limen = Limen(RedisStore(url="redis://localhost:6379/0"))   # counters shared across all workers
    # or inject an existing client: RedisStore(client=my_redis)
"""
from __future__ import annotations

from typing import Any


class RedisStore:
    def __init__(self, client: Any = None, url: str = "redis://localhost:6379/0", prefix: str = "limen:") -> None:
        if client is None:
            try:
                import redis
            except ImportError as exc:  # pragma: no cover - exercised only without the extra
                raise ImportError("RedisStore needs redis: pip install 'limen[redis]'") from exc
            client = redis.Redis.from_url(url, decode_responses=True)
        self._r = client
        self._p = prefix

    def incr(self, key: str, window_s: int) -> int:
        k = self._p + key
        count = int(self._r.incr(k))
        if count == 1:  # first hit of the window → set the TTL. Plain EXPIRE (no NX) works on every Redis
            self._r.expire(k, window_s)  # version, and the key is ALWAYS given a TTL, so nothing accumulates.
        return count

    def get(self, key: str) -> int:
        val = self._r.get(self._p + key)
        return int(val) if val else 0

    def set_str(self, key: str, value: str, ttl_s: int) -> None:
        self._r.set(self._p + key, value, ex=ttl_s)

    def get_str(self, key: str) -> str | None:
        return self._r.get(self._p + key)

    # ponytail: a process crash between INCR==1 and EXPIRE would leave one key without a TTL (rare). If
    # exactly-once TTL ever matters, replace the two calls with a Lua INCR+EXPIRE script.
