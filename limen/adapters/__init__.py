"""Ready-made adapters. ``MemoryStore`` is always available; ``RedisStore`` and ``LimenMiddleware`` load
only when their extra is installed (``limen[redis]`` / ``limen[fastapi]``)."""
from .memory_store import MemoryStore

__all__ = ["MemoryStore"]

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
