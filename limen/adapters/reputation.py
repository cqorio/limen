"""ReputationObserver — accumulate a per-caller risk score across requests and auto-ban when it crosses a line.

WHAT IT IS & WHY IT MATTERS
    The risk spine (``EngineConfig.score_thresholds``) combines guards WITHIN one request. This sink combines
    them ACROSS requests: it keeps a per-caller score in the store, adds a weight every time a guard fires,
    and when the total crosses a threshold it writes a denylist entry so the ``denylist`` guard bans the
    caller on subsequent requests. That is the natural home for "one stray hit just flags, but repeated and/or
    multiple abuse signals ban."

HOW IT DECIDES
    Time is cut into fixed windows of ``window_s`` (``bucket = floor(now / window_s)``) and the score is kept
    PER WINDOW (``limen:rep:<kind>:<id>:<bucket>``, TTL ``window_s``), so it cannot grow without bound across
    windows: each window starts fresh and a caller who goes quiet simply stops writing and the key ages out.
    On each RELEVANT decision (``respects_relevance = False``; a plain ALLOW fires nothing) it sums the weights
    of the DISTINCT guards named in ``decision.reasons`` + ``decision.shadow_reasons`` (a shadow detection is
    still a signal), with one rule that makes it safe for noisy behavioral guards:

    - a guard listed in ``once_per_window_guards`` contributes its weight **at most once per window per
      caller** (tracked by a ``…:seen:<guard>:<bucket>`` marker). So ``timing`` / ``sequence_anomaly`` —
      which fire on EVERY request of a steady client — add their weight ONCE and cannot pile up. A lone
      metronomic poller therefore tops out at that guard's weight, which you keep below ``threshold``, and is
      never banned. Only when it COMBINES with another signal in the same window does the total cross.
    - a guard NOT in the set (e.g. ``honeytoken``) contributes on every hit, because a hit on an unlinked
      canary is unambiguous and repeated hits SHOULD accumulate.

    When the window's new total reaches ``threshold`` it writes ``limen:deny:<kind>:<id>`` (TTL ``ban_ttl_s``,
    NOT bucketed); enforcement then belongs to the store-backed ``denylist`` GUARD that reads that key (clean
    separation: this observer records + escalates, the guard blocks).

EXAMPLE
    >>> from limen.adapters import MemoryStore
    >>> from limen.core.types import RequestContext, Decision, Action
    >>> store = MemoryStore()
    >>> rep = ReputationObserver(store, weights={"honeytoken": 10, "timing": 5}, threshold=25,
    ...                          once_per_window_guards={"timing"})
    >>> def hit(*guards):                                   # a flagged decision naming guards
    ...     return Decision(action=Action.BLOCK, reasons=tuple(f"{g}: x" for g in guards))
    >>> ctx = RequestContext(method="GET", path="/api/x", ip="6.6.6.6")
    >>> for _ in range(20): rep.observe(ctx, hit("timing"))  # metronomic: timing counts ONCE this window
    >>> store.get_str("limen:deny:ip:6.6.6.6") is None       # score 5, never banned by rhythm alone
    True
    >>> rep.observe(ctx, hit("honeytoken"))                 # +10 -> 15
    >>> rep.observe(ctx, hit("honeytoken"))                 # +10 -> 25 -> ban (canary is per-hit)
    >>> store.get_str("limen:deny:ip:6.6.6.6")
    '1'

TUNING
    ``weights``: how much each guard contributes. ``threshold``: the ban line. Keep the sum of the
    ``once_per_window_guards`` weights that a LEGITIMATE client could trip (typically ``timing`` +
    ``sequence_anomaly``) BELOW ``threshold`` — then no well-behaved automated client is ever banned, and a
    ban always requires a genuinely hostile signal (a canary hit, id-enumeration). ``once_per_window_guards``:
    the noisy per-request behavioral guards. ``window_s``: the score window (also the "once per" period).
    ``ban_ttl_s``: how long the auto-ban lasts (prefer a bounded temp-ban for IP-keyed bans).

ASYNC
    Use ``ReputationObserver(async_store, ...)`` in an async app: ``observe_async`` (awaited by the facade on
    ``evaluate_async``) awaits the store, so it never blocks the event loop; ``observe`` serves a sync store.

FALSE POSITIVES / CRAWLER SAFETY
    A steady poller or health-check loop trips ``timing``/``sequence_anomaly`` on every request, but with them
    in ``once_per_window_guards`` that is one weight per window, capped below ``threshold`` — never a ban. A
    crawler that trips one canary once gets a single weight, well under ``threshold``, and the window ages
    out. Only a caller that repeats a hostile signal or trips several in one window accumulates enough. Pair
    with a ``robots.txt`` Disallow on canary paths so good crawlers never score at all.

WHAT IT DOES NOT CATCH
    Distributed abuse across many IPs/accounts (each stays under its own score). Abuse spread thinly across
    window boundaries (each window starts fresh — set ``window_s`` to the horizon you care about). IP-keyed
    bans age badly; keep ``ban_ttl_s`` bounded and prefer account keys for authenticated abuse. The
    read-modify-write of the score is not atomic, so under heavy concurrency from ONE caller a few increments
    can be lost — an approximation that only ever UNDER-counts (fails toward not-banning), the safe direction.

STORE KEYS & COST
    Per active caller per window: one score key ``limen:rep:<kind>:<id>:<bucket>`` and one
    ``…:seen:<guard>:<bucket>`` marker per firing once-per-window guard, plus the ban key on escalation. One
    incr per once-per-window guard + one get + one set per FLAGGED request; zero store access on clean traffic
    (no weighted guard fired -> early return).
"""
from __future__ import annotations

import time
from typing import Iterable, Mapping

from ..core.observer import Observer
from ..core.types import Decision, RequestContext


class ReputationObserver(Observer):
    # Always-on (like a metrics sink): the log-verbosity switch must not silence risk accumulation. It stays
    # cheap on clean traffic because a decision with no weighted firing guard returns before any store access.
    respects_relevance = False

    def __init__(
        self,
        store,
        weights: Mapping[str, float],
        threshold: float,
        window_s: int = 3600,
        ban_ttl_s: int = 3600,
        once_per_window_guards: Iterable[str] = (),
    ) -> None:
        self.store = store
        self.weights = dict(weights)
        self.threshold = threshold
        self.window_s = window_s
        self.ban_ttl_s = ban_ttl_s
        self.once_per_window_guards = frozenset(once_per_window_guards)

    @staticmethod
    def _caller(ctx: RequestContext) -> "tuple[str, str] | None":
        """(kind, id): account when known (survives IP change), else the trusted IP, else None (skip)."""
        if ctx.account_id:
            return "account", ctx.account_id
        if ctx.ip:
            return "ip", ctx.ip
        return None

    def _fired(self, decision: Decision) -> set[str]:
        """DISTINCT guards that fired (enforced or shadow) AND carry a positive weight."""
        guards = {r.split(":", 1)[0] for r in (decision.reasons + decision.shadow_reasons)}
        return {g for g in guards if self.weights.get(g, 0.0) > 0}

    def observe(self, ctx: RequestContext, decision: Decision) -> None:
        caller = self._caller(ctx)
        if caller is None:
            return
        guards = self._fired(decision)
        if not guards:
            return
        kind, ident = caller
        bucket = int(time.time() // self.window_s)
        delta = 0.0
        for g in guards:
            if g in self.once_per_window_guards:
                if self.store.incr(f"limen:rep:seen:{kind}:{ident}:{g}:{bucket}", self.window_s) != 1:
                    continue   # already counted this window: cannot pile up
            delta += self.weights[g]
        if delta <= 0:
            return   # nothing new this window -> do NOT rewrite the score (let the window age out)
        key = f"limen:rep:{kind}:{ident}:{bucket}"
        raw = self.store.get_str(key)
        total = (float(raw) if raw else 0.0) + delta
        self.store.set_str(key, str(total), self.window_s)
        if total >= self.threshold:
            self.store.set_str(f"limen:deny:{kind}:{ident}", "1", self.ban_ttl_s)

    async def observe_async(self, ctx: RequestContext, decision: Decision) -> None:
        caller = self._caller(ctx)
        if caller is None:
            return
        guards = self._fired(decision)
        if not guards:
            return
        kind, ident = caller
        bucket = int(time.time() // self.window_s)
        delta = 0.0
        for g in guards:
            if g in self.once_per_window_guards:
                if await self.store.incr(f"limen:rep:seen:{kind}:{ident}:{g}:{bucket}", self.window_s) != 1:
                    continue   # already counted this window: cannot pile up
            delta += self.weights[g]
        if delta <= 0:
            return   # nothing new this window -> do NOT rewrite the score (let the window age out)
        key = f"limen:rep:{kind}:{ident}:{bucket}"
        raw = await self.store.get_str(key)
        total = (float(raw) if raw else 0.0) + delta
        await self.store.set_str(key, str(total), self.window_s)
        if total >= self.threshold:
            await self.store.set_str(f"limen:deny:{kind}:{ident}", "1", self.ban_ttl_s)
