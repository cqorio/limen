"""RedisStore against a tiny fake client — no redis server or the [redis] extra needed."""
from limen.adapters.redis_store import RedisStore


class FakeRedis:
    def __init__(self):
        self.kv = {}
        self.ttl = {}

    def incr(self, k):
        self.kv[k] = int(self.kv.get(k, 0)) + 1
        return self.kv[k]

    def expire(self, k, seconds):
        self.ttl[k] = seconds

    def get(self, k):
        return self.kv.get(k)

    def set(self, k, v, ex=None):
        self.kv[k] = v
        self.ttl[k] = ex


def test_ttl_is_set_on_first_hit_only():
    r = FakeRedis()
    s = RedisStore(client=r, prefix="p:")
    assert s.incr("a", 60) == 1
    assert r.ttl["p:a"] == 60          # TTL set on the first hit
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
