"""Watermark — emit a per-account tag so leaked data/exports trace back to whoever pulled them.

WHAT IT DETECTS & WHY IT MATTERS
    It detects nothing and blocks nothing — it is PASSIVE, for ATTRIBUTION. When a customer's data later
    shows up somewhere it should not, a per-account watermark stamped into responses/exports tells you which
    account leaked it. Deterrence and forensics, not prevention.

HOW IT DECIDES
    For an authenticated request it returns an ALERT signal whose reason carries ``wm=<tag>``, where ``tag``
    is an HMAC-SHA256 of the account id under your ``secret`` (truncated to ``digits``). An adapter reads that
    tag (from ``decision.shadow_reasons`` in SHADOW mode) and stamps it into a response header or an export.
    No-op without a ``secret`` or an account, so it is safe to leave registered.

EXAMPLE
    >>> from limen.adapters import MemoryStore
    >>> from limen.guards.watermark import Watermark
    >>> from limen.core.types import RequestContext
    >>> g = Watermark(secret="s3cr3t")
    >>> sig = g.evaluate(RequestContext(method="GET", path="/export", account_id="u1"), MemoryStore())
    >>> sig.reason.startswith("wm=") and len(sig.reason) > 3
    True
    >>> g.evaluate(RequestContext(method="GET", path="/export", account_id="u1"), MemoryStore()).reason == sig.reason
    True

TUNING
    ``secret``: the HMAC key — keep it out of the repo (inject from your secret store). ``digits``: tag length
    (longer = fewer collisions, more to embed). Keep it SHADOW (never let it change the action).

FALSE POSITIVES
    None — it never blocks. The only failure mode is a leaked/blank ``secret`` (tags become forgeable/absent).

WHAT IT DOES NOT CATCH
    It does not stop exfiltration, only attributes it after the fact, and only if you actually stamp the tag
    onto what you serve. A determined leaker who strips the tag defeats it.

STORE KEYS & COST
    None — a pure HMAC. O(1), no store access.
"""
from __future__ import annotations

import hashlib
import hmac

from ..core.guard import Guard, register
from ..core.ports import AsyncStore, Store
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

    async def evaluate_async(self, ctx: RequestContext, store: AsyncStore) -> Signal | None:
        return self.evaluate(ctx, store)  # pure HMAC — no store access
