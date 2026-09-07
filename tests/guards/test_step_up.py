from limen.adapters import MemoryStore
from limen.core.types import Action, RequestContext
from limen.guards.step_up import StepUp


def _req(path, ts, account="u1"):
    return RequestContext(method="POST", path=path, account_id=account, auth_kind="session", ts=ts)


def test_sensitive_path_without_marker_challenges():
    g = StepUp(sensitive_paths=("/account/delete",), max_age_s=300)
    assert g.evaluate(_req("/account/delete", 1000.0), MemoryStore()).action is Action.CHALLENGE


def test_fresh_marker_allows():
    g = StepUp(sensitive_paths=("/account/delete",), max_age_s=300)
    s = MemoryStore()
    s.set_str("limen:reauth:u1", str(1000.0), 300)  # app records a fresh re-auth
    assert g.evaluate(_req("/account/delete", 1100.0), s) is None  # 100s < 300


def test_stale_marker_challenges():
    g = StepUp(sensitive_paths=("/account/delete",), max_age_s=300)
    s = MemoryStore()
    s.set_str("limen:reauth:u1", str(1000.0), 3600)
    assert g.evaluate(_req("/account/delete", 2000.0), s).action is Action.CHALLENGE  # 1000s > 300


def test_non_sensitive_path_is_untouched():
    g = StepUp(sensitive_paths=("/account/delete",))
    assert g.evaluate(_req("/home", 1000.0), MemoryStore()) is None


def test_default_instance_is_a_noop():
    assert StepUp().evaluate(_req("/anything", 1000.0), MemoryStore()) is None
