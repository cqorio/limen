"""The ``Observer`` abstract base class — the decision sink you subclass to send Limen's verdicts somewhere.

An Observer is an authored extension (like a ``Guard``, like the standard library's ``logging.Handler``): you
subclass it and implement one method, ``observe``. It is an ABC rather than a ``Protocol`` precisely because it
hands you shared behavior — the ``event`` field helper, a sensible ``respects_relevance`` default, and a no-op
``observe_latency`` you override only for metrics. (Contrast the injected ports in ``ports.py``, which are
Protocols because you WRAP something you already own; an Observer you author for Limen.)

    >>> from limen.core.observer import Observer
    >>> from limen.core.types import RequestContext, Decision, Action
    >>> class Collect(Observer):                     # a custom sink: subclass + implement observe
    ...     def __init__(self): self.seen = []
    ...     def observe(self, ctx, decision): self.seen.append(decision.action.name)
    >>> sink = Collect()
    >>> sink.observe(RequestContext(method="GET", path="/x"), Decision(action=Action.BLOCK))
    >>> sink.seen
    ['BLOCK']
    >>> Observer.event(RequestContext(method="GET", path="/x"), Decision(action=Action.ALLOW))["action"]
    'ALLOW'
"""
from __future__ import annotations

from abc import ABC, abstractmethod
from typing import Any

from .types import Decision, RequestContext


class Observer(ABC):
    """Subclass this, implement ``observe(ctx, decision)``. Optionally set ``respects_relevance`` (False only in
    a metrics sink) and override ``observe_latency``. The facade calls ``observe`` once per enforcing evaluate."""

    # A LOG sink leaves this True so the facade's global ``log_relevance`` can drop plain ALLOWs; a METRICS sink
    # sets it False so it counts EVERY decision (the allow count is the denominator for "% blocked").
    respects_relevance: bool = True

    @abstractmethod
    def observe(self, ctx: RequestContext, decision: Decision) -> None:
        """Handle one decision. Must be cheap (it is on the request path) and should not raise (the facade
        guards the call, but a raising sink is a bug). Never log secret values."""

    def observe_latency(self, seconds: float) -> None:
        """The facade calls this with the per-request evaluate time. No-op by default; override it in a metrics
        sink to record a latency histogram."""

    @staticmethod
    def event(ctx: RequestContext, decision: Decision) -> dict[str, Any]:
        """The field union a sink serializes — identity + request + verdict, no bodies/headers/secrets. Reuse
        it in your own observer so every sink emits the same record shape."""
        return {
            "ts": ctx.ts,
            "action": decision.action.name,
            "score": decision.score,
            "reasons": list(decision.reasons),
            "shadow_reasons": list(decision.shadow_reasons),
            "ip": ctx.ip,
            "account": ctx.account_id,
            "auth_kind": ctx.auth_kind,
            "method": ctx.method,
            "path": ctx.path,
            "status": ctx.status,
        }
