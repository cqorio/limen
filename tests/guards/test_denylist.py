from limen.adapters import MemoryStore
from limen.core.types import Action, RequestContext
from limen.guards.denylist import Denylist


def _req(**kw):
    kw.setdefault("method", "GET")
    kw.setdefault("path", "/x")
    return RequestContext(**kw)


def test_static_account_and_ip_are_blocked():
    g = Denylist(accounts=("bad",), ips=("6.6.6.6",))
    assert g.evaluate(_req(account_id="bad"), MemoryStore()).action is Action.BLOCK
    assert g.evaluate(_req(ip="6.6.6.6"), MemoryStore()).action is Action.BLOCK


def test_clean_traffic_passes():
    g = Denylist(accounts=("bad",))
    assert g.evaluate(_req(account_id="ok", ip="1.1.1.1"), MemoryStore()) is None


def test_default_instance_is_a_noop():
    assert Denylist().evaluate(_req(account_id="anyone", ip="1.2.3.4"), MemoryStore()) is None


def test_store_backed_runtime_ban():
    g = Denylist(store_backed=True)
    s = MemoryStore()
    assert g.evaluate(_req(account_id="u1"), s) is None
    s.set_str("limen:deny:account:u1", "1", 60)  # ops bans at runtime
    assert g.evaluate(_req(account_id="u1"), s).action is Action.BLOCK
