"""The orchestrator: run the enabled guards over one request and reduce their signals to a Decision."""
from __future__ import annotations

import logging
from typing import Callable

from .config import EngineConfig
from .guard import REGISTRY, Registry
from .ports import Store
from .types import Action, Decision, Mode, RequestContext

log = logging.getLogger("limen")


class Engine:
    """Iterates the registry, respects each guard's effective mode, and aggregates. Pure: it takes a
    ``RequestContext`` and a ``Store`` and returns a ``Decision`` — no framework, no globals beyond the
    registry you pass. Fast: O(enabled guards), each guard doing O(1) store work.

    ``exempt`` short-circuits to ALLOW before any guard runs (a TOTAL bypass — skips every guard). Use it for
    trusted source traffic (your own scanner). DANGER: an IP-based exempt is only as safe as your IP source —
    gate it on ``ctx.ip_trusted`` (``exempt=lambda ctx: ctx.ip_trusted and ctx.ip in TRUSTED``) or a spoofed
    header turns Limen off entirely. See docs/integration.md."""

    def __init__(
        self,
        registry: Registry = REGISTRY,
        config: EngineConfig | None = None,
        exempt: Callable[[RequestContext], bool] | None = None,
    ) -> None:
        self.registry = registry
        self.config = config or EngineConfig()
        self.exempt = exempt

    def evaluate(self, ctx: RequestContext, store: Store) -> Decision:
        if self.exempt is not None and self.exempt(ctx):
            return Decision(action=Action.ALLOW, reasons=("exempt",))
        action = Action.ALLOW
        score = 0.0
        reasons: list[str] = []
        shadow: list[str] = []

        for guard in self.registry.all():
            mode = self.config.mode_for(guard)
            if mode is Mode.OFF:
                continue
            # FAIL OPEN — a broken guard, a store outage, OR a guard that violates the Signal|None contract
            # must never lock out a user. The whole body is guarded, not just evaluate().
            try:
                signal = guard.evaluate(ctx, store)
                if signal is None:
                    continue
                if mode is Mode.ENFORCE:
                    action = max(action, signal.action)
                    score += signal.score
                    reasons.append(f"{signal.guard}: {signal.reason}")
                else:  # SHADOW — observed only, never changes the action
                    shadow.append(f"{signal.guard}: {signal.reason}")
            except Exception:
                log.exception("limen guard %r failed; failing open", guard.name)
                continue

        return Decision(action=action, score=score, reasons=tuple(reasons), shadow_reasons=tuple(shadow))
