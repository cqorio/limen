from limen.adapters import MemoryStore
from limen.core.types import Action, RequestContext
from limen.guards.timing import Timing


def _req(ts, account="u1"):
    return RequestContext(method="GET", path="/api/x", account_id=account, ts=ts)


def test_metronomic_timing_fires():
    g = Timing(samples=5, max_stdev_s=0.5)
    store = MemoryStore()
    sig = None
    for i in range(5):  # exactly 1.0s apart → interval stdev 0
        sig = g.evaluate(_req(ts=float(i)), store)
    assert sig is not None and sig.action is Action.ALERT


def test_jittered_timing_does_not_fire():
    g = Timing(samples=5, max_stdev_s=0.2)
    store = MemoryStore()
    sig = None
    for t in (0.0, 1.0, 3.5, 4.0, 9.0):  # irregular
        sig = g.evaluate(_req(ts=t), store)
    assert sig is None


def test_silent_until_enough_samples():
    g = Timing(samples=5)
    store = MemoryStore()
    assert g.evaluate(_req(ts=0.0), store) is None


def test_no_caller_is_ignored():
    assert Timing().evaluate(RequestContext(method="GET", path="/x", ts=0.0), MemoryStore()) is None
