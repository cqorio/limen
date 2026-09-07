"""Redis-backed stores — share counters across processes/replicas. Extra: ``pip install 'limen[redis]'``.

``RedisStore`` is the sync ``Store``; ``AsyncRedisStore`` is the ``AsyncStore`` (``redis.asyncio``) for async
apps. ``redis`` is imported lazily (only when constructing the default client), so both are importable — and
unit-testable with a fake client — without the extra installed.

Both `incr` the counter and set its TTL in ONE atomic Lua script: a plain ``INCR`` then ``EXPIRE`` can orphan a
TTL-less key if the process dies between the two calls, locking that bucket forever. One ``EVAL`` = both or
neither.

Usage (needs a running Redis, so shown as a snippet rather than a doctest)::

    from limen import Limen
    from limen.adapters import RedisStore, AsyncRedisStore
    limen = Limen(RedisStore(url="redis://localhost:6379/0"))          # sync: counters shared across workers
    alimen = Limen(AsyncRedisStore(url="redis://localhost:6379/0"))    # async: same, non-blocking
    # or inject an existing client: RedisStore(client=my_redis) / AsyncRedisStore(client=my_async_redis)
"""
from __future__ import annotations

from typing import Any

# Atomic INCR + first-hit EXPIRE. A plain INCR-then-EXPIRE can orphan a TTL-less key (crash between the two)
# and then lock the bucket forever; one EVAL is both or neither. Works on every Redis version.
_INCR_LUA = "local n = redis.call('incr', KEYS[1]); if n == 1 then redis.call('expire', KEYS[1], ARGV[1]) end; return n"


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
        return int(self._r.eval(_INCR_LUA, 1, self._p + key, window_s))

    def get(self, key: str) -> int:
        val = self._r.get(self._p + key)
        return int(val) if val else 0

    def set_str(self, key: str, value: str, ttl_s: int) -> None:
        self._r.set(self._p + key, value, ex=ttl_s)

    def get_str(self, key: str) -> str | None:
        return self._r.get(self._p + key)


class AsyncRedisStore:
    """The async ``AsyncStore`` twin — every method awaits a ``redis.asyncio`` client, so an async app never
    blocks the event loop on Redis. Same atomic Lua ``INCR``+``EXPIRE`` as ``RedisStore``."""

    def __init__(self, client: Any = None, url: str = "redis://localhost:6379/0", prefix: str = "limen:") -> None:
        if client is None:
            try:
                import redis.asyncio as aioredis
            except ImportError as exc:  # pragma: no cover - exercised only without the extra
                raise ImportError("AsyncRedisStore needs redis: pip install 'limen[redis]'") from exc
            client = aioredis.Redis.from_url(url, decode_responses=True)
        self._r = client
        self._p = prefix

    async def incr(self, key: str, window_s: int) -> int:
        return int(await self._r.eval(_INCR_LUA, 1, self._p + key, window_s))

    async def get(self, key: str) -> int:
        val = await self._r.get(self._p + key)
        return int(val) if val else 0

    async def set_str(self, key: str, value: str, ttl_s: int) -> None:
        await self._r.set(self._p + key, value, ex=ttl_s)

    async def get_str(self, key: str) -> str | None:
        return await self._r.get(self._p + key)
