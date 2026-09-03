"""Metronomic-timing guard: a caller whose requests arrive at near-constant intervals is almost certainly a bot.

Keeps a short per-caller history of request timestamps in the store and flags when the interval standard
deviation collapses below ``max_stdev_s`` over ``samples`` requests. Default SHADOW — a legitimate poller is
also metronomic, so watch before enforcing. Keyed on account (else IP); skips when neither is known.
"""
from __future__ import annotations

import json
import statistics

from ..core.guard import Guard, register
from ..core.ports import Store
from ..core.types import Action, Mode, RequestContext, Signal


@register
class Timing(Guard):
    name = "timing"
    default_mode = Mode.SHADOW

    def __init__(
        self,
        samples: int = 8,
        max_stdev_s: float = 0.5,
        window_s: int = 300,
        action: Action = Action.ALERT,
    ) -> None:
        self.samples = samples
        self.max_stdev_s = max_stdev_s
        self.window_s = window_s
        self.action = action

    def evaluate(self, ctx: RequestContext, store: Store) -> Signal | None:
        if not ctx.is_pre_request:
            return None
        caller = ctx.account_id or ctx.ip
        if caller is None:
            return None
        key = f"limen:timing:{caller}"
        raw = store.get_str(key)
        history = json.loads(raw) if raw else []
        history.append(ctx.ts)
        history = history[-self.samples:]
        store.set_str(key, json.dumps(history), self.window_s)
        if len(history) < self.samples:
            return None
        intervals = [b - a for a, b in zip(history, history[1:])]
        stdev = statistics.pstdev(intervals)
        if stdev <= self.max_stdev_s:
            return Signal(
                self.action,
                self.name,
                f"metronomic timing (interval stdev {stdev:.3f}s over {len(history)} requests)",
            )
        return None
