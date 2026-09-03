from limen.adapters import MemoryStore
from limen.core.types import Action, RequestContext
from limen.guards.account_budget import AccountBudget


def _req(account="u1"):
    return RequestContext(method="GET", path="/api/data", account_id=account, auth_kind="session")


def test_within_budget_is_silent_then_fires_over():
    g = AccountBudget(window_s=60, limit=3)
    store = MemoryStore()
    out = [g.evaluate(_req(), store) for _ in range(5)]  # counts 1,2,3,4,5
    assert out[0] is None and out[1] is None and out[2] is None  # 1..3 within budget
    assert out[3] is not None and out[3].action is Action.TARPIT  # count 4 > 3


def test_unauthenticated_is_ignored():
    g = AccountBudget()
    assert g.evaluate(RequestContext(method="GET", path="/x", account_id=None), MemoryStore()) is None


def test_budget_is_per_account():
    g = AccountBudget(window_s=60, limit=1)
    store = MemoryStore()
    assert g.evaluate(_req("a"), store) is None      # a: count 1
    assert g.evaluate(_req("b"), store) is None      # b: count 1 (separate bucket)
    assert g.evaluate(_req("a"), store) is not None  # a: count 2 > 1
