"""Enumeration — a caller racking up "not found" responses is guessing ids/endpoints it should not know.

WHAT IT DETECTS & WHY IT MATTERS
    Scanning for valid object ids (``/api/items/1``, ``/2``, …) or hidden endpoints produces a burst of 404s
    from one source. Legitimate users almost never generate many not-founds; an attacker enumerating your
    id-space does. Catching it early denies the map before they find a real target.

HOW IT DECIDES
    Two phases (see ``RequestContext``'s PHASE CONVENTION). POST-response: a 404 (optionally only under
    ``path_prefixes``) increments a per-CALLER counter with TTL ``window_s``. PRE-request: if that caller's
    recent not-found count exceeds ``limit``, the NEXT request from it is BLOCKed. Keyed on **account when
    known, else the trusted IP** (like ``timing``/``sequence_anomaly``) — so an authenticated caller is judged
    on ITS OWN 404s, and users who merely share a NAT IP are not lumped together. Self-disables when neither an
    account nor a trusted IP is known.

EXAMPLE
    >>> from limen.adapters import MemoryStore
    >>> from limen.guards.enumeration import Enumeration
    >>> from limen.core.types import RequestContext, Action
    >>> g = Enumeration(limit=3, path_prefixes=("/api/items/",))
    >>> store = MemoryStore()
    >>> for i in range(4):   # 4 not-found responses recorded in the POST-response phase
    ...     _ = g.evaluate(RequestContext(method="GET", path=f"/api/items/{i}", status=404, ip="6.6.6.6"), store)
    >>> g.evaluate(RequestContext(method="GET", path="/api/items/x", ip="6.6.6.6"), store).action
    <Action.BLOCK: 5>

TUNING
    ``limit`` / ``window_s``: how many 404s in how long is "guessing" (lower = stricter). ``path_prefixes``:
    scope it to your id routes so a crawler's incidental 404s on other paths do not count — empty means count
    every 404.

FALSE POSITIVES
    A broken client or a dead link farm can 404 a lot; keep ``limit`` above normal noise, and prefer scoping
    to id routes. Anonymous callers still share one counter per IP (no account to key on), so keep ``limit``
    generous — but an authenticated caller is keyed on its account, so a shared NAT no longer lumps signed-in
    users together.

WHAT IT DOES NOT CATCH
    Enumeration that gets 200s (valid-id scraping — that is ``rate_limit``/``sequence_anomaly``), or attackers
    spreading 404s across many accounts/IPs. Needs an account or a trusted IP; without one it does nothing.

STORE KEYS & COST
    One counter per active caller: ``limen:enum:<kind>:<id>`` (kind = account or ip). O(1): one ``get``
    pre-request, one ``incr`` per 404.
"""
from __future__ import annotations

from ..core.guard import Guard, register
from ..core.ports import AsyncStore, Store
from ..core.types import Action, Mode, RequestContext, Signal


@register
class Enumeration(Guard):
    """Two phases (see RequestContext's PHASE CONVENTION):

    - PRE-request (``status is None``): read the recent not-found count for this caller; over ``limit`` → BLOCK.
    - POST-response (``status`` set): a 404 (optionally only under ``path_prefixes``) increments the count.

    Keep it PATH-SCOPED to your id routes (``path_prefixes=("/api/reports/", "/r/")``) so a legitimate
    crawler's incidental 404s don't trip it. Keyed on account when known, else the trusted IP → self-disables
    when neither is known.
    """

    name = "enumeration"
    default_mode = Mode.ENFORCE

    def __init__(self, window_s: int = 60, limit: int = 20, path_prefixes: tuple[str, ...] = ()) -> None:
        self.window_s = window_s
        self.limit = limit
        self.path_prefixes = path_prefixes

    @staticmethod
    def _caller(ctx: RequestContext) -> "tuple[str, str] | None":
        """(kind, id): account when known (an authenticated caller is judged on its own 404s, and survives an
        IP change), else the trusted IP, else None (skip — no one to attribute the 404s to)."""
        if ctx.account_id:
            return "account", ctx.account_id
        if ctx.ip:
            return "ip", ctx.ip
        return None

    def _key(self, kind: str, ident: str) -> str:
        return f"limen:enum:{kind}:{ident}"

    def evaluate(self, ctx: RequestContext, store: Store) -> Signal | None:
        caller = self._caller(ctx)
        if caller is None:
            return None
        kind, ident = caller
        if ctx.is_pre_request:
            count = store.get(self._key(kind, ident))
            if count > self.limit:
                return Signal(Action.BLOCK, self.name, f"{count} recent not-found responses from {kind} {ident}")
            return None
        if ctx.status == 404 and (not self.path_prefixes or self.under_any(ctx.path, self.path_prefixes)):
            store.incr(self._key(kind, ident), self.window_s)
        return None

    async def evaluate_async(self, ctx: RequestContext, store: AsyncStore) -> Signal | None:
        caller = self._caller(ctx)
        if caller is None:
            return None
        kind, ident = caller
        if ctx.is_pre_request:
            count = await store.get(self._key(kind, ident))
            if count > self.limit:
                return Signal(Action.BLOCK, self.name, f"{count} recent not-found responses from {kind} {ident}")
            return None
        if ctx.status == 404 and (not self.path_prefixes or self.under_any(ctx.path, self.path_prefixes)):
            await store.incr(self._key(kind, ident), self.window_s)
        return None
