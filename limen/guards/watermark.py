"""Watermark guard: emit a per-account tag so leaked data/exports trace back to the account that pulled them.

Passive — it NEVER blocks. It returns an ALERT signal whose reason carries ``wm=<tag>`` (an HMAC of the account
id under ``secret``), which an adapter can read (e.g. from ``decision.shadow_reasons`` in SHADOW mode) and stamp
onto a response or export. Attribution, not prevention. No-op without a ``secret`` or an account.
"""
from __future__ import annotations

import hashlib
import hmac

from ..core.guard import Guard, register
from ..core.ports import Store
from ..core.types import Action, Mode, RequestContext, Signal


@register
class Watermark(Guard):
    name = "watermark"
    default_mode = Mode.SHADOW  # informational only — must never change the action

    def __init__(self, secret: str = "", digits: int = 16) -> None:
        self.secret = secret
        self.digits = digits

    def tag(self, account_id: str) -> str:
        return hmac.new(self.secret.encode(), account_id.encode(), hashlib.sha256).hexdigest()[: self.digits]

    def evaluate(self, ctx: RequestContext, store: Store) -> Signal | None:
        if not ctx.is_pre_request or not self.secret or ctx.account_id is None:
            return None
        return Signal(Action.ALERT, self.name, f"wm={self.tag(ctx.account_id)}")
