"""Sentry decision sink. Extra: ``pip install 'limen[sentry]'``.

Reports serious Limen decisions to Sentry as messages (tagged with the action/guard/ip/account/path), so you get
alerting on blocks/challenges alongside your app's error stream. Sentry is just one bundled ``Observer`` — the
same port lets you write a Datadog/Slack/webhook sink in a few lines (see docs/integration.md, "Write your own
observer").

Sentry has quotas, so this is deliberately quiet: it is a LOG sink (``respects_relevance = True``, so the global
``log_relevance`` still applies) AND it only reports decisions whose action reaches ``min_action`` (default
BLOCK), keeping alerts to the events that matter.

The Sentry call is behind an injectable ``capture(message, level, tags)`` — the default wraps ``sentry_sdk``,
but you can pass your own (which is also how it is unit-tested without the dependency):

    >>> from limen.adapters.sentry import SentryObserver
    >>> from limen.core.types import RequestContext, Decision, Action
    >>> events = []
    >>> obs = SentryObserver(capture=lambda msg, level, tags: events.append((level, tags["limen_action"])))
    >>> obs.observe(RequestContext(method="POST", path="/pay"),
    ...             Decision(action=Action.BLOCK, reasons=("rate_limit: over",)))
    >>> obs.observe(RequestContext(method="GET", path="/x"), Decision(action=Action.ALERT))  # below min_action
    >>> events
    [('warning', 'BLOCK')]
"""
from __future__ import annotations

from typing import Any, Callable

from ..core.observer import Observer
from ..core.types import Action

Capture = Callable[[str, str, "dict[str, str]"], None]


class SentryObserver(Observer):
    respects_relevance = True

    def __init__(
        self,
        min_action: Action = Action.BLOCK,
        level: str = "warning",
        capture: Capture | None = None,
    ) -> None:
        self._min_action = min_action
        self._level = level
        self._capture = capture or self._default_capture()

    @staticmethod
    def _default_capture() -> Capture:
        try:
            import sentry_sdk
        except ImportError as exc:  # pragma: no cover - exercised only without the extra
            raise ImportError("SentryObserver needs sentry-sdk: pip install 'limen[sentry]'") from exc

        def cap(message: str, level: str, tags: dict[str, str]) -> None:
            with sentry_sdk.new_scope() as scope:  # new_scope() is the 2.x+ API (push_scope was removed in 3.0)
                for k, v in tags.items():
                    scope.set_tag(k, v)
                sentry_sdk.capture_message(message, level=level)

        return cap

    def observe(self, ctx: Any, decision: Any) -> None:
        if decision.action < self._min_action:  # only serious decisions become Sentry events
            return
        ev = self.event(ctx, decision)
        reasons = decision.reasons or decision.shadow_reasons
        message = f"limen {ev['action']} {ev['method']} {ev['path']}: " + "; ".join(reasons)
        tags = {
            "limen_action": ev["action"],
            "limen_ip": ev["ip"] or "",
            "limen_account": ev["account"] or "",
            "limen_path": ev["path"],
        }
        self._capture(message, self._level, tags)
