"""Sequence anomaly — a browser session hammering ONE endpoint with no page fan-out looks like a script.

WHAT IT DETECTS & WHY IT MATTERS
    A real page load touches a SPREAD of endpoints (the page, its data calls, assets). A cookie session that
    instead pounds a single data route in a tight loop is the tell of automation wearing a browser's cookies:
    a scraper, a scripted export, a credential-stuffer reusing a logged-in session.

HOW IT DECIDES
    Per account per window it counts total requests and per-endpoint requests (endpoints grouped by
    ``path_template`` so ``/api/items/1`` and ``/api/items/2`` collapse to one). Once there are at least
    ``min_requests`` in the window, if a single endpoint's share of the total is >= ``dominance`` (default
    0.9), it emits ``action``. Only browser cookie sessions are judged (``auth_kind == "session"``); machine
    callers legitimately hit one endpoint repeatedly and are ignored, plus you can exempt path prefixes.

EXAMPLE
    >>> from limen.adapters import MemoryStore
    >>> from limen.guards.sequence_anomaly import SequenceAnomaly
    >>> from limen.core.types import RequestContext, Action
    >>> g = SequenceAnomaly(window_s=300, min_requests=20, dominance=0.9, action=Action.ALERT)
    >>> store = MemoryStore()
    >>> req = RequestContext(method="GET", path="/api/items/1", account_id="u1", auth_kind="session")
    >>> out = [g.evaluate(req, store) for _ in range(25)]   # 25 hits to ONE endpoint, no fan-out
    >>> out[-1].action is Action.ALERT
    True

TUNING
    ``dominance``: lower to catch subtler scripts (more false positives). ``min_requests``: raise so brief
    bursts do not trip it. ``window_s``: the observation window. ``exempt_prefixes``: paths that legitimately
    get hammered (health checks, a versioned API, webhooks) — EMPTY by default; set them for YOUR app.

FALSE POSITIVES / WHY SHADOW-FIRST
    An infinite-scroll or polling UI can legitimately dominate one endpoint, so a false positive would lock out
    a real user — the default mode is SHADOW. Watch ``decision.shadow_reasons`` for a while, then ENFORCE.

WHAT IT DOES NOT CATCH
    A scraper that spreads across endpoints to mimic a page, or one that rotates accounts. It only judges
    authenticated browser sessions; API-key and anonymous traffic are out of scope (use ``rate_limit`` there).

STORE KEYS & COST
    Two counters per account per window: ``limen:seq:<account>:__total__`` and ``…:<endpoint-template>``.
    O(1) per request (two ``incr``s).
"""
from __future__ import annotations

from ..core.guard import Guard, register
from ..core.ports import AsyncStore, Store
from ..core.types import Action, Mode, RequestContext, Signal


@register
class SequenceAnomaly(Guard):
    name = "sequence_anomaly"
    default_mode = Mode.SHADOW

    def __init__(
        self,
        window_s: int = 300,
        min_requests: int = 20,
        dominance: float = 0.9,
        exempt_prefixes: tuple[str, ...] = (),
        action: Action = Action.ALERT,
    ) -> None:
        self.window_s = window_s
        self.min_requests = min_requests
        self.dominance = dominance
        self.exempt_prefixes = exempt_prefixes
        self.action = action

    def _skip(self, ctx: RequestContext) -> bool:
        return (
            not ctx.is_pre_request
            or ctx.auth_kind != "session"
            or ctx.account_id is None
            or (bool(self.exempt_prefixes) and self.under_any(ctx.path, self.exempt_prefixes))
        )

    def _decide(self, ctx: RequestContext, tmpl: str, total: int, hits: int) -> Signal | None:
        if total >= self.min_requests and hits / total >= self.dominance:
            return Signal(
                self.action,
                self.name,
                f"account {ctx.account_id}: {hits}/{total} requests to {tmpl} (no page fan-out)",
            )
        return None

    def evaluate(self, ctx: RequestContext, store: Store) -> Signal | None:
        if self._skip(ctx):
            return None
        tmpl = self.path_template(ctx.path)
        total = store.incr(f"limen:seq:{ctx.account_id}:__total__", self.window_s)
        hits = store.incr(f"limen:seq:{ctx.account_id}:{tmpl}", self.window_s)
        return self._decide(ctx, tmpl, total, hits)

    async def evaluate_async(self, ctx: RequestContext, store: AsyncStore) -> Signal | None:
        if self._skip(ctx):
            return None
        tmpl = self.path_template(ctx.path)
        total = await store.incr(f"limen:seq:{ctx.account_id}:__total__", self.window_s)
        hits = await store.incr(f"limen:seq:{ctx.account_id}:{tmpl}", self.window_s)
        return self._decide(ctx, tmpl, total, hits)
