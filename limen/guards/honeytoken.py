"""Honeytoken guard: access to a canary path is a high-confidence alarm.

Configure ``paths`` with canary routes/ids that NO legitimate UI ever surfaces — random and unlinked, so only a
targeted enumerator (never a link-follower or your own scanner probing dictionary paths) reaches them. Any hit
returns ``action`` (default BLOCK), and the reason carries the caller for attribution. No-op until you configure
canaries, so ENFORCE-by-default is safe.
"""
from __future__ import annotations

from ..core.guard import Guard, register
from ..core.ports import Store
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
