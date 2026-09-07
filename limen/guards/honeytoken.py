"""Honeytoken — a hit on a secret canary path nobody should know about is a near-certain alarm.

WHAT IT DETECTS & WHY IT MATTERS
    Plant a route or id that NO legitimate UI ever links or surfaces. A real user can never reach it; only
    someone poking at your API by hand or from a leaked internal reference does. So unlike a heuristic, a hit
    is high-confidence malice — one of the few signals worth a hard BLOCK on the first occurrence.

HOW IT DECIDES
    Exact-match the request path against your configured ``paths`` (random, unlinked canaries). Any match
    emits ``action`` (default BLOCK); the reason carries the caller (ip/account) for attribution. It is a
    no-op until you configure canaries, so ENFORCE-by-default is safe out of the box.

EXAMPLE
    >>> from limen.adapters import MemoryStore
    >>> from limen.guards.honeytoken import Honeytoken
    >>> from limen.core.types import RequestContext, Action
    >>> g = Honeytoken(paths=("/api/__canary_9f3a__",))
    >>> g.evaluate(RequestContext(method="GET", path="/api/__canary_9f3a__", ip="6.6.6.6"), MemoryStore()).action
    <Action.BLOCK: 4>
    >>> g.evaluate(RequestContext(method="GET", path="/api/real", ip="6.6.6.6"), MemoryStore()) is None
    True

TUNING
    ``paths``: the canaries. Make them RANDOM and unlinked (``/api/reports/__canary_9f3a7c__``), never
    guessable dictionary words a scanner would try anyway, or you get false alarms. ``action``: BLOCK, or
    ALERT if you would rather silently watch who found it.

FALSE POSITIVES
    Essentially none IF the canary is truly unlinked and random. A poorly chosen (guessable) path a generic
    scanner probes will fire on non-targeted bots — choose obscure values.

WHAT IT DOES NOT CATCH
    Anything that never touches a canary. It is a tripwire, not coverage; pair it with the detection guards.

STORE KEYS & COST
    None — a set membership check. O(1), no store access.
"""
from __future__ import annotations

from ..core.guard import Guard, register
from ..core.ports import AsyncStore, Store
from ..core.types import Action, Mode, RequestContext, Signal


@register
class Honeytoken(Guard):
    name = "honeytoken"
    default_mode = Mode.ENFORCE

    def __init__(self, paths: tuple[str, ...] = (), action: Action = Action.BLOCK) -> None:
        self.paths = frozenset(paths)
        self.action = action

    def evaluate(self, ctx: RequestContext, store: Store) -> Signal | None:
        if not ctx.is_pre_request or ctx.path not in self.paths:
            return None
        return Signal(
            self.action,
            self.name,
            f"honeytoken accessed: {ctx.path} (ip={ctx.ip} account={ctx.account_id})",
        )

    async def evaluate_async(self, ctx: RequestContext, store: AsyncStore) -> Signal | None:
        return self.evaluate(ctx, store)  # pure set-membership check — no store access
