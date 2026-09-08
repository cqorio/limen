"""Ready-made adapters. ``MemoryStore`` / ``AsyncMemoryStore`` (sync + async in-process stores), the two
zero-dependency observers, ``TurnstileVerifier`` (stdlib ``urllib``), ``PrometheusObserver`` and
``SentryObserver`` are always importable — but constructing ``PrometheusObserver`` / ``SentryObserver`` needs
its extra (``limen[prometheus]`` / ``limen[sentry]``) and raises a clear error otherwise. ``RedisStore`` /
``AsyncRedisStore`` (``limen[redis]``) and ``LimenMiddleware`` (``limen[fastapi]``) need their extra to
CONSTRUCT (the default client), and the middleware to import."""
from .memory_store import AsyncMemoryStore, MemoryStore
from .observers import JsonlObserver, LoggingObserver
from .prometheus import PrometheusObserver  # importable; raises on construction without the prometheus extra
from .reputation import ReputationObserver  # zero-dep: accumulates a per-caller score in your store -> auto-ban
from .sentry import SentryObserver  # importable; raises on construction without the sentry extra
from .turnstile import TurnstileVerifier  # stdlib-only (urllib), always available

__all__ = [
    "MemoryStore",
    "AsyncMemoryStore",
    "LoggingObserver",
    "JsonlObserver",
    "ReputationObserver",
    "TurnstileVerifier",
    "PrometheusObserver",
    "SentryObserver",
]

try:
    from .redis_store import AsyncRedisStore, RedisStore

    __all__ += ["RedisStore", "AsyncRedisStore"]
except ImportError:  # redis extra not installed
    pass

try:
    from .fastapi import LimenMiddleware

    __all__.append("LimenMiddleware")
except ImportError:  # fastapi extra not installed
    pass
