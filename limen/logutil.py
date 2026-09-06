"""Opt-in logging convenience. A library must stay SILENT by default and let the app own logging config
(handlers, levels, formatting) — so ``limen/__init__.py`` attaches only a ``NullHandler`` and nothing here
runs unless you call it.

``enable_logging()`` is a one-liner for dev/demo/CLI use: it attaches a stream handler to the ``limen`` logger
ONLY (never the root logger, never ``basicConfig``), so it cannot hijack your app's logging. Production apps
should NOT call it — configure the ``limen`` logger yourself.
"""
from __future__ import annotations

import logging
import sys
from typing import IO


def enable_logging(level: int = logging.INFO, stream: IO[str] | None = None) -> logging.Logger:
    """Attach a handler to the ``limen`` logger and set its level. Idempotent (calling twice does not stack
    handlers). ``stream`` defaults to stderr; pass a file object to send Limen's operational logs there.

        import limen
        limen.enable_logging()                      # -> stderr, INFO
        limen.enable_logging(stream=open("limen.log", "a"))
    """
    logger = logging.getLogger("limen")
    for h in logger.handlers:  # idempotent: reuse the handler we added before
        if getattr(h, "_limen_dev_handler", False):
            h.setLevel(level)
            logger.setLevel(level)
            return logger
    handler = logging.StreamHandler(stream or sys.stderr)
    handler.setFormatter(logging.Formatter("%(asctime)s %(levelname)s %(name)s %(message)s"))
    handler._limen_dev_handler = True  # type: ignore[attr-defined]
    logger.addHandler(handler)
    logger.setLevel(level)
    logger.propagate = False  # our handler already prints; don't double-log through the app's root handler
    return logger
