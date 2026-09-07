"""RedisStore / AsyncRedisStore against tiny fake clients — no redis server or the [redis] extra needed."""
import asyncio

from limen.adapters.redis_store import AsyncRedisStore, RedisStore


class FakeRedis:
    def __init__(self):
        self.kv = {}
        self.ttl = {}

    # incr uses a single atomic EVAL now (INCR + first-hit EXPIRE in one script). The fake replicates that
    # script exactly, so the TTL is set on the first hit only — the property the store relies on.
    def eval(self, script, numkeys, *keys_and_args):
        key = keys_and_args[0]
        window = keys_and_args[numkeys]  # first ARGV after the keys
        self.kv[key] = int(self.kv.get(key, 0)) + 1
        n = self.kv[key]
        if n == 1:
            self.ttl[key] = window
        return n

    def get(self, k):
        return self.kv.get(k)

    def set(self, k, v, ex=None):
        self.kv[k] = v
        self.ttl[k] = ex


class FakeAsyncRedis:
    def __init__(self):
        self.kv = {}
        self.ttl = {}

    async def eval(self, script, numkeys, *keys_and_args):
        key = keys_and_args[0]
        window = keys_and_args[numkeys]
        self.kv[key] = int(self.kv.get(key, 0)) + 1
        n = self.kv[key]
        if n == 1:
            self.ttl[key] = window
        return n

    async def get(self, k):
        return self.kv.get(k)

    async def set(self, k, v, ex=None):
        self.kv[k] = v
        self.ttl[k] = ex


def test_ttl_is_set_on_first_hit_only():
    r = FakeRedis()
    s = RedisStore(client=r, prefix="p:")
    assert s.incr("a", 60) == 1
    assert r.ttl["p:a"] == 60          # TTL set on the first hit (atomic with the INCR)
    r.ttl["p:a"] = "sentinel"
    assert s.incr("a", 60) == 2
    assert r.ttl["p:a"] == "sentinel"  # NOT re-set on later hits (fixed window; no un-TTL'd key)


def test_get_and_kv():
    r = FakeRedis()
    s = RedisStore(client=r)
    assert s.get("x") == 0
    s.incr("x", 60)
    assert s.get("x") == 1
    s.set_str("y", "v", 30)
    assert s.get_str("y") == "v"


def test_async_redis_store_atomic_incr_expire_and_kv():
    """Plan test (e): AsyncRedisStore awaits everything, and INCR+EXPIRE is one atomic EVAL (TTL on first hit)."""
    r = FakeAsyncRedis()
    s = AsyncRedisStore(client=r, prefix="p:")
    assert asyncio.run(s.incr("a", 60)) == 1
    assert r.ttl["p:a"] == 60
    r.ttl["p:a"] = "sentinel"
    assert asyncio.run(s.incr("a", 60)) == 2
    assert r.ttl["p:a"] == "sentinel"          # not re-TTL'd on later hits
    assert asyncio.run(s.get("a")) == 2
    asyncio.run(s.set_str("y", "v", 30))
    assert asyncio.run(s.get_str("y")) == "v"
    assert asyncio.run(s.get("missing")) == 0
