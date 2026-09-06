"""Prometheus metrics sink (Layer B, aggregate). Extra: ``pip install 'limen[prometheus]'``.

Unlike the log sinks, this is a scoreboard: it keeps running COUNTS, cheaply, for every decision — including
``allow``, so a dashboard can compute "% blocked" = ``block / sum(all)``. It therefore sets
``respects_relevance = False`` so the global ``log_relevance`` switch never silences the allow count.

It only PRODUCES the numbers. YOU expose and PROTECT the ``/metrics`` endpoint (mount it on your app, keep it
internal-only or admin-gated); Limen never opens a port.

    from prometheus_client import make_asgi_app
    limen = Limen(store, observer=PrometheusObserver())
    app.mount("/metrics", make_asgi_app())   # protect this route — do NOT expose it publicly
"""
from __future__ import annotations

from typing import Any


class PrometheusObserver:
    respects_relevance = False  # count EVERY action, incl. allow (the denominator for "% blocked")

    def __init__(self, registry: Any = None) -> None:
        try:
            from prometheus_client import Counter, Histogram
        except ImportError as exc:  # pragma: no cover - exercised only without the extra
            raise ImportError(
                "PrometheusObserver needs prometheus_client: pip install 'limen[prometheus]'"
            ) from exc
        kw = {"registry": registry} if registry is not None else {}
        self._decisions = Counter(
            "limen_decisions_total",
            "Limen decisions, labeled by the action taken and the guard that drove it.",
            ["action", "guard"],
            **kw,
        )
        self._latency = Histogram(
            "limen_decision_latency_seconds",
            "Time spent evaluating Limen guards for one request.",
            **kw,
        )

    def observe(self, ctx: Any, decision: Any) -> None:
        guard = decision.reasons[0].split(":", 1)[0] if decision.reasons else "none"
        self._decisions.labels(action=decision.action.name, guard=guard).inc()

    def observe_latency(self, seconds: float) -> None:
        """Optional hook the facade calls with the per-request evaluate time."""
        self._latency.observe(seconds)
