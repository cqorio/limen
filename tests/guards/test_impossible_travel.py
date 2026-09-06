from limen.adapters import MemoryStore
from limen.core.types import Action, RequestContext
from limen.guards.impossible_travel import ImpossibleTravel


class StubGeo:
    def __init__(self, mapping):
        self.mapping = mapping

    def locate(self, ip):
        return self.mapping.get(ip)


def _req(ip, ts, account="u1"):
    return RequestContext(method="GET", path="/x", account_id=account, ip=ip, ts=ts)


def test_region_change_within_window_challenges():
    geo = StubGeo({"1.1.1.1": "US", "2.2.2.2": "JP"})
    g = ImpossibleTravel(geo=geo, window_s=3600)
    s = MemoryStore()
    assert g.evaluate(_req("1.1.1.1", 1000.0), s) is None  # first sighting
    sig = g.evaluate(_req("2.2.2.2", 1100.0), s)           # 100s later, different country
    assert sig is not None and sig.action is Action.CHALLENGE


def test_same_region_is_fine():
    geo = StubGeo({"1.1.1.1": "US", "3.3.3.3": "US"})
    g = ImpossibleTravel(geo=geo, window_s=3600)
    s = MemoryStore()
    assert g.evaluate(_req("1.1.1.1", 1000.0), s) is None
    assert g.evaluate(_req("3.3.3.3", 1100.0), s) is None


def test_no_geo_self_disables():
    g = ImpossibleTravel(geo=None)
    assert g.evaluate(_req("1.1.1.1", 1000.0), MemoryStore()) is None


def test_unknown_region_is_skipped():
    geo = StubGeo({})  # locate returns None
    g = ImpossibleTravel(geo=geo)
    assert g.evaluate(_req("9.9.9.9", 1000.0), MemoryStore()) is None
