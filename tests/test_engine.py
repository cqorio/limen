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
