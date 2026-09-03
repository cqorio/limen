"""Enumeration guard: flag an IP racking up 'not found' responses (the signature of id/endpoint guessing)."""
from __future__ import annotations

from ..core.guard import Guard, register
from ..core.ports import Store
from ..core.types import Action, Mode, RequestContext, Signal


@register
class Enumeration(Guard):
    """Two phases (see RequestContext's PHASE CONVENTION):

    - PRE-request (``status is None``): read the recent not-found count for this IP; over ``limit`` → BLOCK.
    - POST-response (``status`` set): a 404 (optionally only under ``path_prefixes``) increments the count.

    Keep it PATH-SCOPED to your id routes (``path_prefixes=("/api/reports/", "/r/")``) so a legitimate
    crawler's incidental 404s don't trip it. Keyed on IP → self-disables when there is no trusted IP.
    """

    name = "enumeration"
    default_mode = Mode.ENFORCE

    def __init__(self, window_s: int = 60, limit: int = 20, path_prefixes: tuple[str, ...] = ()) -> None:
        self.window_s = window_s
        self.limit = limit
        self.path_prefixes = path_prefixes

    def _key(self, ip: str) -> str:
        return f"limen:enum:{ip}"

    def evaluate(self, ctx: RequestContext, store: Store) -> Signal | None:
        if ctx.ip is None:
            return None
        if ctx.is_pre_request:
            count = store.get(self._key(ctx.ip))
            if count > self.limit:
                return Signal(Action.BLOCK, self.name, f"{count} recent not-found responses from {ctx.ip}")
            return None
        if ctx.status == 404 and (not self.path_prefixes or self.under_any(ctx.path, self.path_prefixes)):
            store.incr(self._key(ctx.ip), self.window_s)
        return None
