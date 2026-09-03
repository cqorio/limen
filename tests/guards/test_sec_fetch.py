from limen.adapters import MemoryStore
from limen.core.types import Action, RequestContext
from limen.guards.sec_fetch import SecFetch


def _req(site, kind="session"):
    return RequestContext(method="GET", path="/api/me", sec_fetch_site=site, auth_kind=kind)


def test_cross_site_cookie_session_is_flagged():
    sig = SecFetch().evaluate(_req("cross-site"), MemoryStore())
    assert sig is not None and sig.action is Action.CHALLENGE


def test_same_origin_and_site_and_none_are_ok():
    g = SecFetch()
    for site in ("same-origin", "same-site", "none"):
        assert g.evaluate(_req(site), MemoryStore()) is None


def test_absent_header_is_not_proof():
    assert SecFetch().evaluate(_req(None), MemoryStore()) is None


def test_non_cookie_session_is_ignored():
    assert SecFetch().evaluate(_req("cross-site", kind="apikey"), MemoryStore()) is None
