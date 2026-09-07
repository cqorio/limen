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


# --- CSRF extension: state-changing methods must POSITIVELY prove same-origin ---
def _post(**kw):
    kw.setdefault("auth_kind", "session")
    return RequestContext(method="POST", path="/api/pay", **kw)


def test_csrf_state_changing_without_any_proof_is_flagged():
    g = SecFetch(methods=("POST",), allowed_origins=("https://example.com",))
    assert g.evaluate(_post(), MemoryStore()).action is Action.CHALLENGE  # no Sec-Fetch, no Origin


def test_csrf_matching_origin_allows():
    g = SecFetch(methods=("POST",), allowed_origins=("https://example.com",))
    assert g.evaluate(_post(origin="https://example.com"), MemoryStore()) is None


def test_csrf_sec_fetch_same_origin_allows_even_without_configured_origins():
    g = SecFetch(methods=("POST",))
    assert g.evaluate(_post(sec_fetch_site="same-origin"), MemoryStore()) is None


def test_csrf_only_applies_to_configured_methods():
    g = SecFetch(methods=("POST",), allowed_origins=("https://example.com",))
    # a GET is a read: the CSRF branch does not apply, and an absent header is not proof either
    assert g.evaluate(RequestContext(method="GET", path="/api/pay", auth_kind="session"), MemoryStore()) is None


def test_csrf_ignores_non_session_traffic():
    g = SecFetch(methods=("POST",))
    assert g.evaluate(_post(auth_kind="apikey"), MemoryStore()) is None


def test_csrf_off_by_default():
    # with no `methods`, a state-changing session request with no proof is NOT flagged (unchanged behavior)
    assert SecFetch().evaluate(_post(), MemoryStore()) is None
