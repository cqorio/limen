"""ReputationObserver — accumulate a per-caller risk score across requests and auto-ban when it crosses a line.

WHAT IT IS & WHY IT MATTERS
    The risk spine (``EngineConfig.score_thresholds``) combines guards WITHIN one request. This sink combines
    them ACROSS requests: it keeps a decaying score per caller in the store, adds a weight every time a guard
    fires, and when the total crosses a threshold it writes a denylist entry so the ``denylist`` guard bans the
    caller on subsequent requests. That is the natural home for "one stray hit just flags, but repeated and/or
    multiple abuse signals ban" — and it is crawler-safe by construction: a single canary/404 hit adds one
    weight, far below the threshold, and decays away; only sustained or multi-signal abuse climbs past the line.

HOW IT DECIDES
    On each RELEVANT decision (``respects_relevance = False`` so the global ``log_relevance`` switch never
    silences it; a plain ALLOW does nothing because no guard fired) it sums the weights of the DISTINCT guards
    named in ``decision.reasons`` + ``decision.shadow_reasons`` (a shadow detection is still a signal). It adds
    that to the caller's score at ``limen:rep:<kind>:<id>`` (``kind`` = account when known, else IP) and writes
    it back with a TTL of ``window_s`` — a SLIDING window, so continued abuse keeps the score alive and
    behaving lets it expire. When the new total reaches ``threshold`` it writes ``limen:deny:<kind>:<id>`` with
    a TTL of ``ban_ttl_s``; enforcement then belongs to the store-backed ``denylist`` GUARD that reads that key
    (clean separation: this observer records + escalates, the guard blocks).

EXAMPLE
    >>> from limen.adapters import MemoryStore
    >>> from limen.core.types import RequestContext, Decision, Action
    >>> store = MemoryStore()
    >>> rep = ReputationObserver(store, weights={"honeytoken": 10, "enumeration": 5}, threshold=25)
    >>> def hit(guard):                                     # a flagged decision naming one guard
    ...     return Decision(action=Action.BLOCK, reasons=(f"{guard}: tripped",))
    >>> ctx = RequestContext(method="GET", path="/api/.env", ip="6.6.6.6")
    >>> rep.observe(ctx, hit("honeytoken"))                 # score 10
    >>> rep.observe(ctx, hit("honeytoken"))                 # score 20
    >>> store.get_str("limen:deny:ip:6.6.6.6") is None      # not yet banned (20 < 25)
    True
    >>> rep.observe(ctx, hit("enumeration"))                # score 25 -> ban written
    >>> store.get_str("limen:deny:ip:6.6.6.6")              # the denylist guard now blocks this caller
    '1'
    >>> rep.observe(RequestContext(method="GET", path="/ok", ip="1.1.1.1"),
    ...             Decision(action=Action.ALLOW))          # a clean request: no guard fired -> no store I/O
    >>> store.get_str("limen:rep:ip:1.1.1.1") is None
    True

TUNING
    ``weights``: how much each guard contributes (a honeytoken hit should weigh far more than one 404). A guard
    not in the map contributes 0. ``threshold``: the ban line — set it above any single weight so one stray hit
    never bans (crawler safety). ``window_s``: how fast the score decays (the sliding TTL). ``ban_ttl_s``: how
    long the auto-ban lasts (prefer a bounded temp-ban for IP-keyed bans, since IPs are reassigned).

ASYNC
    Use ``ReputationObserver(async_store, ...)`` in an async app: ``observe_async`` (awaited by the facade on
    ``evaluate_async``) awaits the store, so it never blocks the event loop; ``observe`` serves a sync store.

FALSE POSITIVES / CRAWLER SAFETY
    A well-behaved crawler that trips one canary once gets a single weight, well under ``threshold``, and it
    decays — it is never banned. Only a caller that repeats or trips several guards accumulates enough. Pair
    with a ``robots.txt`` Disallow on canary paths so good crawlers never score at all.

WHAT IT DOES NOT CATCH
    Distributed abuse across many IPs/accounts (each stays under its own score). IP-keyed bans age badly; keep
    ``ban_ttl_s`` bounded and prefer account keys for authenticated abuse. The read-modify-write of the score
    is not atomic, so under heavy concurrency from ONE caller a few increments can be lost — an approximation
    that only ever UNDER-counts (fails toward not-banning), which is the safe direction for a heuristic.

STORE KEYS & COST
    One score key per active caller (``limen:rep:<kind>:<id>``) + the ban key on escalation. One get + one set
    per FLAGGED request; zero store access on clean traffic (no guard fired -> early return).
"""
from __future__ import annotations

from typing import Mapping

from ..core.observer import Observer
from ..core.types import Decision, RequestContext


class ReputationObserver(Observer):
    # Always-on (like a metrics sink): the log-verbosity switch must not silence risk accumulation. It stays
    # cheap on clean traffic because a decision with no firing guard yields a zero delta and returns early.
    respects_relevance = False

    def __init__(
        self,
        store,
        weights: Mapping[str, float],
        threshold: float,
        window_s: int = 3600,
        ban_ttl_s: int = 3600,
    ) -> None:
        self.store = store
        self.weights = dict(weights)
        self.threshold = threshold
        self.window_s = window_s
        self.ban_ttl_s = ban_ttl_s

    @staticmethod
    def _caller(ctx: RequestContext) -> "tuple[str, str] | None":
        """(kind, id): account when known (survives IP change), else the trusted IP, else None (skip)."""
        if ctx.account_id:
            return "account", ctx.account_id
        if ctx.ip:
            return "ip", ctx.ip
        return None

    def _delta(self, decision: Decision) -> float:
        """Summed weight of the DISTINCT guards that fired (enforced or shadow) on this decision."""
        guards = {r.split(":", 1)[0] for r in (decision.reasons + decision.shadow_reasons)}
        return sum(self.weights.get(g, 0.0) for g in guards)

    def observe(self, ctx: RequestContext, decision: Decision) -> None:
        caller = self._caller(ctx)
        delta = self._delta(decision)
        if caller is None or delta <= 0:
            return
        kind, ident = caller
        raw = self.store.get_str(f"limen:rep:{kind}:{ident}")
        total = (float(raw) if raw else 0.0) + delta
        self.store.set_str(f"limen:rep:{kind}:{ident}", str(total), self.window_s)
        if total >= self.threshold:
            self.store.set_str(f"limen:deny:{kind}:{ident}", "1", self.ban_ttl_s)

    async def observe_async(self, ctx: RequestContext, decision: Decision) -> None:
        caller = self._caller(ctx)
        delta = self._delta(decision)
        if caller is None or delta <= 0:
            return
        kind, ident = caller
        raw = await self.store.get_str(f"limen:rep:{kind}:{ident}")
        total = (float(raw) if raw else 0.0) + delta
        await self.store.set_str(f"limen:rep:{kind}:{ident}", str(total), self.window_s)
        if total >= self.threshold:
            await self.store.set_str(f"limen:deny:{kind}:{ident}", "1", self.ban_ttl_s)
