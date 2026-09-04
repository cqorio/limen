from limen.adapters import MemoryStore
from limen.core.config import EngineConfig
from limen.core.engine import Engine
from limen.core.guard import Guard, Registry
from limen.core.types import Action, Mode, RequestContext, Signal


class Fixed(Guard):
    """A guard that always emits a fixed action — for testing aggregation/modes."""

    def __init__(self, name, action, mode=Mode.ENFORCE):
        self.name = name
        self.default_mode = mode
        self._action = action

    def evaluate(self, ctx, store):
        return Signal(self._action, self.name, "fixed")


class Boom(Guard):
    name = "boom"
    default_mode = Mode.ENFORCE

    def evaluate(self, ctx, store):
        raise RuntimeError("kaboom")


def _ctx():
    return RequestContext(method="GET", path="/x")


def test_max_action_wins_and_reasons_collected():
    reg = Registry()
    reg.register(Fixed("a", Action.ALERT))
    reg.register(Fixed("b", Action.BLOCK))
    d = Engine(reg).evaluate(_ctx(), MemoryStore())
    assert d.action is Action.BLOCK
    assert len(d.reasons) == 2 and not d.shadow_reasons


def test_shadow_never_affects_the_action():
    reg = Registry()
    reg.register(Fixed("a", Action.BLOCK, Mode.SHADOW))
    d = Engine(reg).evaluate(_ctx(), MemoryStore())
    assert d.action is Action.ALLOW
    assert d.shadow_reasons and not d.reasons
    assert d.flagged and not d.blocked


def test_off_guard_is_skipped():
    reg = Registry()
    reg.register(Fixed("a", Action.BLOCK))
    d = Engine(reg, EngineConfig(modes={"a": Mode.OFF})).evaluate(_ctx(), MemoryStore())
    assert d.action is Action.ALLOW


def test_config_override_beats_default_mode():
    reg = Registry()
    reg.register(Fixed("a", Action.BLOCK, Mode.SHADOW))  # default shadow
    d = Engine(reg, EngineConfig(modes={"a": Mode.ENFORCE})).evaluate(_ctx(), MemoryStore())
    assert d.action is Action.BLOCK  # override wins


def test_a_raising_guard_fails_open():
    reg = Registry()
    reg.register(Boom())
    reg.register(Fixed("ok", Action.ALERT))
    d = Engine(reg).evaluate(_ctx(), MemoryStore())
    assert d.action is Action.ALERT  # boom swallowed, ok still applied


def test_exempt_short_circuits_to_allow():
    reg = Registry()
    reg.register(Fixed("a", Action.BLOCK))  # would block
    eng = Engine(reg, exempt=lambda ctx: ctx.ip == "9.9.9.9")
    blocked = eng.evaluate(RequestContext(method="GET", path="/x", ip="1.1.1.1"), MemoryStore())
    allowed = eng.evaluate(RequestContext(method="GET", path="/x", ip="9.9.9.9"), MemoryStore())
    assert blocked.action is Action.BLOCK
    assert allowed.action is Action.ALLOW and allowed.reasons == ("exempt",)


def test_exempt_also_skips_observe_counting():
    """An exempt request must not touch the store, so trusted traffic never inflates a guard's counters."""
    from limen.guards.account_budget import AccountBudget

    store = MemoryStore()
    reg = Registry()
    reg.register(AccountBudget(window_s=60, limit=1))
    eng = Engine(reg, exempt=lambda ctx: ctx.ip_trusted)
    for _ in range(5):
        eng.evaluate(RequestContext(method="GET", path="/x", account_id="u1", ip="9.9.9.9", ip_trusted=True), store)
    # exempt short-circuited before the budget guard incremented → the account's counter is untouched
    assert store.get("limen:budget:u1") == 0


class _BadStore:
    def incr(self, *a):
        raise RuntimeError("store down")

    def get(self, *a):
        raise RuntimeError("store down")

    def set_str(self, *a):
        raise RuntimeError("store down")

    def get_str(self, *a):
        raise RuntimeError("store down")


def test_store_outage_fails_open():
    from limen.guards.account_budget import AccountBudget

    reg = Registry()
    reg.register(AccountBudget(limit=0))  # would fire on every request if the store worked
    d = Engine(reg).evaluate(RequestContext(method="GET", path="/x", account_id="u1"), _BadStore())
    assert d.action is Action.ALLOW  # store raised → failed open, not a lockout


class _Rogue(Guard):
    name = "rogue"
    default_mode = Mode.ENFORCE

    def evaluate(self, ctx, store):
        return "not a Signal"  # violates the Signal | None contract


def test_contract_violating_guard_fails_open():
    reg = Registry()
    reg.register(_Rogue())
    reg.register(Fixed("ok", Action.ALERT))
    d = Engine(reg).evaluate(_ctx(), MemoryStore())
    assert d.action is Action.ALERT  # rogue's bad return raised inside the guarded body → skipped
