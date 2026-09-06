"""Ready-made adapters. ``MemoryStore``, the two zero-dependency observers, ``TurnstileVerifier`` (stdlib
``urllib``) and ``PrometheusObserver`` are always importable — but constructing ``PrometheusObserver`` needs
``limen[prometheus]`` and raises a clear error otherwise. ``RedisStore`` (``limen[redis]``) and
``LimenMiddleware`` (``limen[fastapi]``) import only when their extra is installed."""
from .memory_store import MemoryStore
from .observers import JsonlObserver, LoggingObserver
from .prometheus import PrometheusObserver  # importable; raises on construction without the prometheus extra
from .turnstile import TurnstileVerifier  # stdlib-only (urllib), always available

__all__ = ["MemoryStore", "LoggingObserver", "JsonlObserver", "TurnstileVerifier", "PrometheusObserver"]

try:
    from .redis_store import RedisStore

    __all__.append("RedisStore")
except ImportError:  # redis extra not installed
    pass

try:
    from .fastapi import LimenMiddleware

    __all__.append("LimenMiddleware")
except ImportError:  # fastapi extra not installed
    pass
