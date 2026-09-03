"""Limen — a lightweight, modular abuse-defense engine.

Threshold guarding for your API: a registry of small, independently toggleable "guards" (rate/enumeration/
anomaly/…) run by one fast engine, with an off / shadow / enforce mode per guard so you can roll each out
safely. Zero required dependencies; bring your own store (memory ships built in, Redis is an extra).

    from limen import Limen, RequestContext
    from limen.adapters import MemoryStore
    limen = Limen(MemoryStore())
    decision = limen.evaluate(RequestContext(method="GET", path="/api/me", account_id="u1", auth_kind="session"))
"""
from __future__ import annotations

from .core.config import EngineConfig
from .core.guard import REGISTRY, Guard, Registry, register
from .core.ports import ClientIP, Identity, Store
from .core.types import Action, Decision, Mode, RequestContext, Signal
from .facade import Limen

# Importing the bundled guards triggers their @register into REGISTRY.
from . import guards as _guards  # noqa: E402,F401

__version__ = "0.1.0"

__all__ = [
    "Limen",
    "Guard",
    "Registry",
    "register",
    "REGISTRY",
    "EngineConfig",
    "Action",
    "Decision",
    "Mode",
    "RequestContext",
    "Signal",
    "Store",
    "ClientIP",
    "Identity",
]
