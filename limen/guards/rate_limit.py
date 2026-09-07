"""Generic fixed-window rate limit — cap how often ONE caller (by any dimension you pick) may hit you.

WHAT IT DETECTS & WHY IT MATTERS
    Almost every abuse starts as "too many requests from one source": credential stuffing on a login, a
    scraper on an account, a script pounding one endpoint, a flood from one IP. A rate limit is the single
    most useful primitive a chokepoint has. This one guard, instantiated once per "bucket", subsumes the lot:
    you choose the KEY (the dimension to count by), the LIMIT, and the WINDOW.

HOW IT DECIDES
    A fixed-window counter in the ``Store``: the first request in a window sets the counter with a TTL of
    ``window_s``; each request increments it; when the count exceeds ``limit`` the guard emits ``action``.
    The window resets when the TTL lapses (simple and cheap; not a sliding window — a burst straddling a
    window boundary can briefly allow up to ~2x, which is the standard fixed-window tradeoff).

    ``key(ctx)`` picks the dimension and returns a string, or ``None`` to SKIP this request (e.g. ``by_ip``
    returns ``None`` when there is no trusted IP, so the bucket self-disables rather than lumping everyone
    together). Ship several instances in one registry for per-IP + per-account + per-endpoint + global caps.

EXAMPLE
    >>> from limen.adapters import MemoryStore
    >>> from limen.guards.rate_limit import RateLimit, by_ip
    >>> from limen.core.types import RequestContext, Action
    >>> g = RateLimit(name="login_ip", key=by_ip, limit=3, window_s=60)   # 3 per minute per IP
    >>> store = MemoryStore()
    >>> r = RequestContext(method="POST", path="/login", ip="1.2.3.4")
    >>> [g.evaluate(r, store) is None for _ in range(3)]                  # first 3 pass
    [True, True, True]
    >>> g.evaluate(r, store).action is Action.BLOCK                       # the 4th trips
    True
    >>> g.evaluate(RequestContext(method="POST", path="/login"), store) is None  # no IP -> skipped
    True

TUNING
    ``limit`` / ``window_s``: the cap. Too low → false positives on power users; too high → useless. Start
    generous, watch, tighten. ``action``: ``BLOCK`` to refuse, ``TARPIT`` to serve slowly (good for authed
    budgets), ``CHALLENGE`` to captcha. ``fail_closed``: default False (fail OPEN if the store dies); set True
    on a security-critical bucket (login, signup) so a store outage denies instead of waving everyone through.

FALSE POSITIVES
    Shared egress (corporate NAT, mobile carriers) makes many humans share one IP — a per-IP limit counts
    them together, so keep per-IP limits generous and prefer per-ACCOUNT limits for authed traffic. A
    legitimate polling integration can look like a flood; give it its own key or a higher bucket.

WHAT IT DOES NOT CATCH
    Distributed abuse across many IPs/accounts (each stays under its own bucket) — combine with ``enumeration``
    (404-rate) and the score spine. Fixed windows allow a short 2x burst at a boundary. It counts requests, not
    cost: one expensive request weighs the same as a cheap one.

STORE KEYS & COST
    One counter per active key: ``limen:rl:<name>:<key>``. O(1) per request (one ``incr``).
"""
from __future__ import annotations

from typing import Callable

from ..core.guard import Guard
from ..core.ports import AsyncStore, Store
from ..core.types import Action, Mode, RequestContext, Signal

KeyFn = Callable[[RequestContext], "str | None"]


# --- key builders: pick the dimension to count by. Each returns a string, or None to skip the request. ---
def by_ip(ctx: RequestContext) -> str | None:
    return ctx.ip


def by_account(ctx: RequestContext) -> str | None:
    return ctx.account_id


def by_path(ctx: RequestContext) -> str | None:
    return ctx.path


def global_(ctx: RequestContext) -> str | None:
    """A single shared bucket (a global cap across all callers)."""
    return "*"


def per(*keyfns: KeyFn) -> KeyFn:
    """Compose a COMPOSITE key from several builders, e.g. ``per(by_ip, by_path)`` = per-IP-per-endpoint.
    Skips (returns None) if ANY component is None, so a missing dimension disables the bucket cleanly."""

    def key(ctx: RequestContext) -> str | None:
        parts = []
        for fn in keyfns:
            value = fn(ctx)
            if value is None:
                return None
            parts.append(value)
        return "|".join(parts)

    return key


class RateLimit(Guard):
    """One rate-limit bucket. Construct one per dimension you want to cap and register it. Keyed on whatever
    ``key`` picks; self-disables when ``key`` returns None.

    NOT auto-registered: a rate limit has no meaningful zero-config default (a limit is a number and a key is a
    choice), so unlike the other bundled guards it is not in the default ``REGISTRY``. You add the buckets you
    want to your own ``Registry`` (see docs/recipes.md) and pass ``registry=`` to ``Limen``."""

    default_mode = Mode.ENFORCE

    def __init__(
        self,
        name: str,
        key: KeyFn,
        limit: int,
        window_s: int,
        action: Action = Action.BLOCK,
        fail_closed: bool = False,
    ) -> None:
        self.name = name
        self.key = key
        self.limit = limit
        self.window_s = window_s
        self.action = action
        self.fail_closed = fail_closed

    def evaluate(self, ctx: RequestContext, store: Store) -> Signal | None:
        if not ctx.is_pre_request:
            return None
        k = self.key(ctx)
        if k is None:  # dimension absent (e.g. no trusted IP) → this bucket does not apply
            return None
        return self._decide(k, store.incr(f"limen:rl:{self.name}:{k}", self.window_s))

    async def evaluate_async(self, ctx: RequestContext, store: AsyncStore) -> Signal | None:
        if not ctx.is_pre_request:
            return None
        k = self.key(ctx)
        if k is None:
            return None
        return self._decide(k, await store.incr(f"limen:rl:{self.name}:{k}", self.window_s))

    def _decide(self, k: str, count: int) -> Signal | None:
        if count > self.limit:
            return Signal(
                self.action,
                self.name,
                f"rate limit: {count}/{self.limit} per {self.window_s}s for {k}",
            )
        return None
