from limen.adapters import MemoryStore
from limen.core.types import Action, RequestContext
from limen.guards.enumeration import Enumeration


def test_counts_404s_then_blocks_over_limit():
    g = Enumeration(window_s=60, limit=3)
    store = MemoryStore()
    ip = "1.1.1.1"
    for _ in range(4):  # observe phase: four 404s → count 4 > limit 3
        g.evaluate(RequestContext(method="GET", path="/api/reports/x", status=404, ip=ip), store)
    sig = g.evaluate(RequestContext(method="GET", path="/api/me", ip=ip), store)  # pre-request
    assert sig is not None and sig.action is Action.BLOCK


def test_under_limit_does_not_block():
    g = Enumeration(window_s=60, limit=10)
    store = MemoryStore()
    ip = "1.1.1.2"
    for _ in range(3):
        g.evaluate(RequestContext(method="GET", path="/api/reports/x", status=404, ip=ip), store)
    assert g.evaluate(RequestContext(method="GET", path="/api/me", ip=ip), store) is None


def test_no_trusted_ip_self_disables():
    g = Enumeration()
    store = MemoryStore()
    assert g.evaluate(RequestContext(method="GET", path="/x", status=404, ip=None), store) is None
    assert g.evaluate(RequestContext(method="GET", path="/x", ip=None), store) is None


def test_path_prefix_scoping_ignores_other_404s():
    g = Enumeration(window_s=60, limit=2, path_prefixes=("/api/reports/",))
    store = MemoryStore()
    ip = "2.2.2.2"
    for _ in range(5):  # 404s NOT under the scoped prefix → never counted
        g.evaluate(RequestContext(method="GET", path="/other", status=404, ip=ip), store)
    assert g.evaluate(RequestContext(method="GET", path="/x", ip=ip), store) is None


def test_account_keyed_isolates_users_on_a_shared_ip():
    # Two accounts share one NAT IP. Account A floods 404s; B does nothing. Keying on account (not IP) means A
    # is blocked and B is NOT — an innocent signed-in neighbour is never lumped in with A's enumeration.
    g = Enumeration(window_s=60, limit=3)
    store = MemoryStore()
    ip = "9.9.9.9"
    for _ in range(5):
        g.evaluate(RequestContext(method="GET", path="/api/reports/x", status=404, account_id="A", ip=ip), store)
    assert g.evaluate(RequestContext(method="GET", path="/api/me", account_id="A", ip=ip), store).action is Action.BLOCK
    assert g.evaluate(RequestContext(method="GET", path="/api/me", account_id="B", ip=ip), store) is None
