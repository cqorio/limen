"""Metronomic timing — near-constant intervals between requests are a machine's signature, not a human's.

WHAT IT DETECTS & WHY IT MATTERS
    Humans are irregular: they read, pause, click at uneven moments. A script fires on a timer, so its
    inter-arrival gaps are almost identical. When the spacing between a caller's requests stops scattering and
    collapses toward a constant, that regularity itself betrays automation, even automation wearing a session.

HOW IT DECIDES
    Keeps the last ``samples`` request timestamps per caller in the store, computes the POPULATION standard
    deviation of the gaps between them, and emits ``action`` when it falls to ``max_stdev_s`` or below (a
    human's gaps scatter; a cron's collapse toward zero). Keyed on account, else IP; skips when neither is
    known and until it has ``samples`` timestamps.

EXAMPLE
    >>> from limen.adapters import MemoryStore
    >>> from limen.guards.timing import Timing
    >>> from limen.core.types import RequestContext, Action
    >>> g = Timing(samples=4, max_stdev_s=0.5)
    >>> store = MemoryStore()
    >>> sig = None
    >>> for t in (100.0, 101.0, 102.0, 103.0):    # exactly 1.0s apart -> stdev 0
    ...     sig = g.evaluate(RequestContext(method="GET", path="/x", account_id="bot", ts=t), store)
    >>> sig.action is Action.ALERT
    True

TUNING
    ``max_stdev_s``: raise to catch jittery bots (more false positives), lower to only flag the metronomic.
    ``samples``: more samples = higher confidence, slower to trip. ``window_s``: how long the history lives.

FALSE POSITIVES / WHY SHADOW-FIRST
    A legitimate poller or a health-check loop is also metronomic, so default mode is SHADOW: watch, confirm
    it is really abuse, then ENFORCE. Combining it with other weak signals via the score spine is safer than
    enforcing it alone.

WHAT IT DOES NOT CATCH
    A bot that deliberately adds random jitter to its timing, or one that makes too few requests to fill
    ``samples``. It is a soft signal — best as one input to a risk score, not a lone hard block.

STORE KEYS & COST
    One short list per caller: ``limen:timing:<caller>`` (the last ``samples`` timestamps). O(samples) to
    compute the stdev; one read + one write per request.
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
