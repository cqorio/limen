"""Per-account request budget: catch one authenticated account pulling far more than a human would."""
from __future__ import annotations

from ..core.guard import Guard, register
from ..core.ports import Store
from ..core.types import Action, Mode, RequestContext, Signal


@register
class AccountBudget(Guard):
    """A human reloads a dashboard a handful of times an hour; a scraper on one account pulls thousands.
    Counts authenticated requests per account per window; over ``limit`` → ``action`` (default TARPIT).

    Keyed on ``account_id`` → does nothing for unauthenticated traffic (that is the anon rate-limiter's job).
    Fails OPEN: the engine catches any store error, so a backend hiccup never locks out a paying user.
    """

    name = "account_budget"
    default_mode = Mode.ENFORCE

    def __init__(self, window_s: int = 3600, limit: int = 600, action: Action = Action.TARPIT) -> None:
        self.window_s = window_s
        self.limit = limit
        self.action = action

    def evaluate(self, ctx: RequestContext, store: Store) -> Signal | None:
        if ctx.account_id is None or not ctx.is_pre_request:
            return None
        count = store.incr(f"limen:budget:{ctx.account_id}", self.window_s)
        if count > self.limit:
            return Signal(
                self.action,
                self.name,
                f"account {ctx.account_id} over budget ({count}/{self.limit} per {self.window_s}s)",
            )
        return None
