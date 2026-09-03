from limen.adapters import MemoryStore
from limen.core.types import Action, RequestContext
from limen.guards.honeytoken import Honeytoken


def test_canary_hit_blocks():
    g = Honeytoken(paths=("/api/reports/__canary__",))
    sig = g.evaluate(RequestContext(method="GET", path="/api/reports/__canary__", ip="1.2.3.4"), MemoryStore())
    assert sig is not None and sig.action is Action.BLOCK


def test_normal_path_is_ignored():
    g = Honeytoken(paths=("/api/reports/__canary__",))
    assert g.evaluate(RequestContext(method="GET", path="/api/me"), MemoryStore()) is None


def test_unconfigured_is_noop():
    assert Honeytoken().evaluate(RequestContext(method="GET", path="/anything"), MemoryStore()) is None
