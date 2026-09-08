from limen.adapters import MemoryStore
from limen.core.types import Action, RequestContext
from limen.guards.rate_limit import RateLimit, by_account, by_ip, by_path, global_, per


def _req(**kw):
    kw.setdefault("method", "GET")
    kw.setdefault("path", "/x")
    return RequestContext(**kw)


def test_fires_over_limit_per_ip():
    g = RateLimit(name="ip", key=by_ip, limit=3, window_s=60)
    s = MemoryStore()
    r = _req(ip="1.1.1.1")
    assert [g.evaluate(r, s) for _ in range(3)] == [None, None, None]
    assert g.evaluate(r, s).action is Action.THROTTLE  # the 4th trips (429 at the edge)


def test_none_key_self_disables():
    g = RateLimit(name="ip", key=by_ip, limit=0, window_s=60)  # would trip immediately if it applied
    assert g.evaluate(_req(ip=None), MemoryStore()) is None  # no IP → bucket does not apply


def test_account_budget_equivalent_tarpits():
    """The folded `account_budget`: per-account budget that serves the abuser slowly."""
    g = RateLimit(name="account_budget", key=by_account, limit=3, window_s=60, action=Action.TARPIT)
    s = MemoryStore()
    out = [g.evaluate(_req(account_id="u1", auth_kind="session"), s) for _ in range(5)]
    assert out[2] is None
    assert out[3].action is Action.TARPIT


def test_per_account_isolation():
    g = RateLimit(name="b", key=by_account, limit=1, window_s=60)
    s = MemoryStore()
    assert g.evaluate(_req(account_id="a"), s) is None
    assert g.evaluate(_req(account_id="b"), s) is None  # separate bucket
    assert g.evaluate(_req(account_id="a"), s) is not None


def test_composite_key_is_per_ip_per_path():
    g = RateLimit(name="ip_path", key=per(by_ip, by_path), limit=1, window_s=60)
    s = MemoryStore()
    assert g.evaluate(_req(ip="1.1.1.1", path="/a"), s) is None
    assert g.evaluate(_req(ip="1.1.1.1", path="/b"), s) is None  # different path → separate bucket
    assert g.evaluate(_req(ip="1.1.1.1", path="/a"), s) is not None  # same → trips


def test_global_bucket_shares_across_callers():
    g = RateLimit(name="g", key=global_, limit=1, window_s=60)
    s = MemoryStore()
    assert g.evaluate(_req(ip="1"), s) is None
    assert g.evaluate(_req(ip="2"), s) is not None  # different caller, same global bucket
