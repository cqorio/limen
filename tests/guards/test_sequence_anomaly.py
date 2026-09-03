from limen.adapters import MemoryStore
from limen.core.types import Action, RequestContext
from limen.guards.sequence_anomaly import SequenceAnomaly


def _req(path, account="u1", kind="session"):
    return RequestContext(method="GET", path=path, account_id=account, auth_kind=kind)


def test_fires_on_single_endpoint_loop():
    g = SequenceAnomaly(window_s=300, min_requests=10, dominance=0.9)
    store = MemoryStore()
    sig = None
    for _ in range(12):
        sig = g.evaluate(_req("/api/reports"), store)
    assert sig is not None and sig.action is Action.ALERT


def test_mixed_endpoints_do_not_fire():
    g = SequenceAnomaly(window_s=300, min_requests=5, dominance=0.9)
    store = MemoryStore()
    sig = None
    for i in range(10):  # 5 distinct templates → 20% each, never dominant
        sig = g.evaluate(_req(f"/api/page{i % 5}"), store)
    assert sig is None


def test_exempt_prefix_is_ignored():
    g = SequenceAnomaly(min_requests=2)
    store = MemoryStore()
    for _ in range(5):
        assert g.evaluate(_req("/api/v1/reports"), store) is None


def test_non_cookie_session_is_ignored():
    g = SequenceAnomaly(min_requests=2)
    store = MemoryStore()
    for _ in range(5):
        assert g.evaluate(_req("/api/data", kind="apikey"), store) is None
