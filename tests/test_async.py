"""Native async path (v1.1.0): evaluate_async over an AsyncStore, and the base-raises safety pin."""
import asyncio

import pytest

from limen import Action, Guard, Limen, Registry, RequestContext
from limen.adapters import AsyncMemoryStore
from limen.guards.enumeration import Enumeration
from limen.guards.honeytoken import Honeytoken
from limen.guards.rate_limit import RateLimit, by_ip


class ForgotAsync(Guard):
    """A store-backed guard that forgot to override evaluate_async — the dangerous case the base raise guards."""

    name = "forgot_async"

    def evaluate(self, ctx, store):
        return None


def test_missing_async_override_raises_not_silent():
    """Plan (a): base ``evaluate_async`` RAISES rather than delegating to sync — a store-backed guard that
    forgot its async body must be LOUD, never a silent fail-open (an unawaited coroutine would be truthy)."""
    g = ForgotAsync()
    with pytest.raises(NotImplementedError):
        asyncio.run(g.evaluate_async(RequestContext(method="GET", path="/x"), AsyncMemoryStore()))


def test_rate_limit_counts_on_async_path():
    g = RateLimit(name="t", key=by_ip, limit=2, window_s=60)
    store = AsyncMemoryStore()
    ctx = RequestContext(method="POST", path="/x", ip="1.2.3.4")

    async def run():
        return [await g.evaluate_async(ctx, store) for _ in range(3)]

    r1, r2, r3 = asyncio.run(run())
    assert r1 is None and r2 is None      # first 2 under the limit → counted, not blocked
    assert r3.action is Action.BLOCK      # 3rd trips (proves the async store actually counted)


def test_pure_compute_guard_delegates_on_async_path():
    g = Honeytoken(paths=("/canary",))
    hit = asyncio.run(g.evaluate_async(RequestContext(method="GET", path="/canary"), AsyncMemoryStore()))
    miss = asyncio.run(g.evaluate_async(RequestContext(method="GET", path="/real"), AsyncMemoryStore()))
    assert hit.action is Action.BLOCK and miss is None


def test_facade_evaluate_async_and_record_async():
    reg = Registry()
    reg.register(Enumeration(limit=2))    # counts every 404
    limen = Limen(AsyncMemoryStore(), registry=reg)
    ip = "9.9.9.9"

    async def run():
        for _ in range(3):                # 3 not-found responses recorded (post-response phase)
            await limen.record_async(RequestContext(method="GET", path="/api/x", status=404, ip=ip))
        return await limen.evaluate_async(RequestContext(method="GET", path="/api/y", ip=ip))

    decision = asyncio.run(run())
    assert decision.action is Action.BLOCK   # count 3 > limit 2 → blocked on the next request


def test_engine_fails_open_when_async_guard_raises():
    """Through the engine, a raising async guard (e.g. a forgotten override) is caught and fails OPEN by
    default — same contract as the sync engine, so it degrades to fail-open + a log, never a crash."""
    reg = Registry()
    reg.register(ForgotAsync())
    limen = Limen(AsyncMemoryStore(), registry=reg)
    decision = asyncio.run(limen.evaluate_async(RequestContext(method="GET", path="/x")))
    assert decision.action is Action.ALLOW
