"""ReputationObserver + the async-observer path (v1.3.0)."""
import asyncio

from limen import Action, Limen, Registry, RequestContext
from limen.adapters import AsyncMemoryStore, MemoryStore, ReputationObserver
from limen.core.observer import Observer
from limen.core.types import Decision
from limen.guards.honeytoken import Honeytoken


def _hit(*guards, shadow=()):
    return Decision(action=Action.BLOCK,
                    reasons=tuple(f"{g}: x" for g in guards),
                    shadow_reasons=tuple(f"{g}: x" for g in shadow))


def test_score_accumulates_and_bans_at_threshold():
    store = MemoryStore()
    rep = ReputationObserver(store, weights={"honeytoken": 10, "enumeration": 5}, threshold=25)
    ctx = RequestContext(method="GET", path="/x", ip="6.6.6.6")
    rep.observe(ctx, _hit("honeytoken"))    # 10
    rep.observe(ctx, _hit("honeytoken"))    # 20
    assert store.get_str("limen:deny:ip:6.6.6.6") is None    # 20 < 25: not yet banned
    rep.observe(ctx, _hit("enumeration"))   # 25 -> ban
    assert store.get_str("limen:deny:ip:6.6.6.6") == "1"


def test_single_hit_does_not_ban_a_crawler():
    store = MemoryStore()
    rep = ReputationObserver(store, weights={"honeytoken": 10}, threshold=25)
    rep.observe(RequestContext(method="GET", path="/api/.env", ip="1.2.3.4"), _hit("honeytoken"))
    assert store.get_str("limen:deny:ip:1.2.3.4") is None    # 10 < 25: flagged, never banned on one hit


def test_clean_request_does_no_store_io():
    class Counting(MemoryStore):
        n = 0

        def get_str(self, k):
            type(self).n += 1
            return super().get_str(k)

        def set_str(self, k, v, t):
            type(self).n += 1
            return super().set_str(k, v, t)

    store = Counting()
    rep = ReputationObserver(store, weights={"honeytoken": 10}, threshold=25)
    rep.observe(RequestContext(method="GET", path="/ok", ip="1.1.1.1"), Decision(action=Action.ALLOW))
    assert Counting.n == 0   # no guard fired -> zero store access (cheap on clean traffic)


def test_unknown_guard_contributes_zero():
    store = MemoryStore()
    rep = ReputationObserver(store, weights={"honeytoken": 10}, threshold=5)
    rep.observe(RequestContext(method="GET", path="/x", ip="9.9.9.9"), _hit("timing"))  # not in weights
    assert store.get_str("limen:rep:ip:9.9.9.9") is None


def test_account_key_preferred_over_ip():
    store = MemoryStore()
    rep = ReputationObserver(store, weights={"honeytoken": 10}, threshold=10)
    ctx = RequestContext(method="GET", path="/x", account_id="u1", ip="6.6.6.6")
    rep.observe(ctx, _hit("honeytoken"))
    assert store.get_str("limen:deny:account:u1") == "1"
    assert store.get_str("limen:deny:ip:6.6.6.6") is None


def test_shadow_reasons_count_as_signals():
    store = MemoryStore()
    rep = ReputationObserver(store, weights={"sequence_anomaly": 30}, threshold=25)
    rep.observe(RequestContext(method="GET", path="/x", ip="6.6.6.6"), _hit(shadow=("sequence_anomaly",)))
    assert store.get_str("limen:deny:ip:6.6.6.6") == "1"   # a shadow detection is still a signal


def test_async_observer_path_bans_via_async_store():
    # A store-backed ReputationObserver runs on evaluate_async (observe_async awaited) and bans via the async
    # store. Honeytoken (ENFORCE) flags on the canary -> decision fires the observer.
    store = AsyncMemoryStore()
    rep = ReputationObserver(store, weights={"honeytoken": 10}, threshold=10)
    reg = Registry()
    reg.register(Honeytoken(paths=("/api/.env",)))
    limen = Limen(store, registry=reg, observer=rep)

    async def run():
        await limen.evaluate_async(RequestContext(method="GET", path="/api/.env", ip="6.6.6.6"))
        return await store.get_str("limen:deny:ip:6.6.6.6")

    assert asyncio.run(run()) == "1"


def test_sync_observer_still_runs_on_async_path():
    # An observer that did NOT override observe_async runs its sync observe via the base default under
    # evaluate_async — so v1.1/v1.2 sinks are unaffected by the new async path.
    seen = []

    class SyncSink(Observer):
        def observe(self, ctx, decision):
            seen.append(decision.action.name)

    limen = Limen(AsyncMemoryStore(), observer=SyncSink(), log_relevance="all")
    asyncio.run(limen.evaluate_async(RequestContext(method="GET", path="/x")))
    assert seen == ["ALLOW"]
