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
            # The WHOLE body is guarded (not just evaluate()) so a guard that violates the Signal|None
            # contract also lands here rather than crashing the request.
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
                # DEFAULT is FAIL OPEN — a broken guard or store outage must never lock out a user. A guard
                # that OPTED IN to `fail_closed` denies instead, but only under ENFORCE (a SHADOW fail-closed
                # is recorded, never enforced). `action` has a safe base default on Guard, so this cannot raise.
                fail_closed = getattr(guard, "fail_closed", False)
                log.exception("limen guard %r failed; %s", guard.name, "fail-closed" if fail_closed else "failing open")
                if fail_closed:
                    reason = f"{guard.name}: fail-closed (guard error)"
                    if mode is Mode.ENFORCE:
                        action = max(action, getattr(guard, "action", Action.BLOCK))
                        reasons.append(reason)
                    else:  # SHADOW — record, do not enforce
                        shadow.append(reason)
                continue

        # Risk spine: many weak ENFORCE-mode scores can combine into an action none raised alone.
        if self.config.score_thresholds:
            action = max(action, self.config.action_for_score(score))

        return Decision(action=action, score=score, reasons=tuple(reasons), shadow_reasons=tuple(shadow))
