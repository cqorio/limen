"""Decision sinks (Layer B — the audit/event log), both zero-dependency. The facade calls ``observe(ctx,
decision)`` once per enforcing evaluate. ``PrometheusObserver`` (metrics) lives in ``prometheus.py`` behind the
``limen[prometheus]`` extra; ``SentryObserver`` in ``sentry.py`` behind ``limen[sentry]``.

Both here subclass ``Observer`` and are LOG sinks (``respects_relevance = True``), so the facade's global
``log_relevance`` switch can drop plain ALLOWs from them. Never log secret values — ``RequestContext`` carries no
bodies/tokens, and guard ``reason`` strings should not either.

    >>> import io, json
    >>> from limen.adapters.observers import JsonlObserver
    >>> from limen.core.types import RequestContext, Decision, Action
    >>> buf = io.StringIO()
    >>> JsonlObserver(buf).observe(RequestContext(method="GET", path="/pay", ip="1.1.1.1"),
    ...                            Decision(action=Action.BLOCK, reasons=("rl: over",)))
    >>> json.loads(buf.getvalue())["action"], json.loads(buf.getvalue())["path"]
    ('BLOCK', '/pay')
"""
from __future__ import annotations

import json
import logging
import sys
import threading
from typing import Any

from ..core.observer import Observer


class LoggingObserver(Observer):
    """Zero-config default: one structured line per decision through the stdlib ``logging`` system (so the app
    routes/filters/formats it). Fields go in ``extra`` namespaced ``limen_*`` to avoid ``LogRecord`` clashes.
    Emits at INFO — a routine BLOCK is the library WORKING, not a warning; filter on ``limen_action``."""

    def __init__(self, logger: logging.Logger | None = None, level: int = logging.INFO) -> None:
        self._log = logger or logging.getLogger("limen.decisions")
        self._level = level

    def observe(self, ctx: Any, decision: Any) -> None:
        self._log.log(
            self._level,
            "limen %s %s %s",
            decision.action.name,
            ctx.method,
            ctx.path,
            extra={
                "limen_action": decision.action.name,
                "limen_reasons": list(decision.reasons),
                "limen_shadow": list(decision.shadow_reasons),
                "limen_ip": ctx.ip,
                "limen_account": ctx.account_id,
                "limen_score": decision.score,
                "limen_path": ctx.path,
            },
        )


class JsonlObserver(Observer):
    """One JSON object per line — the most inspectable audit format (grep / tail / ship to Loki/ELK). ``dest``
    is a file PATH (appended, line-buffered) or an open text stream; default ``sys.stdout`` (the screen)."""

    def __init__(self, dest: Any = None) -> None:
        self._lock = threading.Lock()
        if dest is None:
            self._fh = sys.stdout
        elif isinstance(dest, str):
            self._fh = open(dest, "a", buffering=1)  # line-buffered append
        else:
            self._fh = dest

    def observe(self, ctx: Any, decision: Any) -> None:
        line = json.dumps(self.event(ctx, decision))
        with self._lock:
            self._fh.write(line + "\n")
            self._fh.flush()
