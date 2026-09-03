"""Sequence-anomaly guard: a browser session pounding ONE endpoint with no page fan-out looks like a script."""
from __future__ import annotations

from ..core.guard import Guard, register
from ..core.ports import Store
from ..core.types import Action, Mode, RequestContext, Signal


@register
class SequenceAnomaly(Guard):
    """A real page load hits a SPREAD of endpoints; a cookie-session hammering a single data route in a
    loop is the tell of automation. SHADOW by default (watch before you enforce — a false positive here
    would lock out a real user).

    Only judges browser cookie sessions (``auth_kind == "session"``), and exempts machine callers by path
    (health, versioned API, webhooks, scanner) — those legitimately hit one endpoint repeatedly.
    """

    name = "sequence_anomaly"
    default_mode = Mode.SHADOW

    def __init__(
        self,
        window_s: int = 300,
        min_requests: int = 20,
        dominance: float = 0.9,
        exempt_prefixes: tuple[str, ...] = ("/api/health", "/api/v1", "/api/webhooks", "/api/scanner-ips"),
        action: Action = Action.ALERT,
    ) -> None:
        self.window_s = window_s
        self.min_requests = min_requests
        self.dominance = dominance
        self.exempt_prefixes = exempt_prefixes
        self.action = action

    def evaluate(self, ctx: RequestContext, store: Store) -> Signal | None:
        if not ctx.is_pre_request or ctx.auth_kind != "session" or ctx.account_id is None:
            return None
        if self.under_any(ctx.path, self.exempt_prefixes):
            return None
        tmpl = self.path_template(ctx.path)
        total = store.incr(f"limen:seq:{ctx.account_id}:__total__", self.window_s)
        hits = store.incr(f"limen:seq:{ctx.account_id}:{tmpl}", self.window_s)
        if total >= self.min_requests and hits / total >= self.dominance:
            return Signal(
                self.action,
                self.name,
                f"account {ctx.account_id}: {hits}/{total} requests to {tmpl} (no page fan-out)",
            )
        return None
