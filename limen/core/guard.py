"""The extension point: a ``Guard`` is one defense, and the ``Registry`` is the set of them.

Add a defense = subclass ``Guard``, set ``name``, implement ``evaluate``, decorate with ``@register``.
Nothing else in the codebase needs to change (the engine iterates the registry). This mirrors a plugin
registry: one small, explicit, framework-free surface.
"""
from __future__ import annotations

import re
from abc import ABC, abstractmethod

from .ports import Store
from .types import Mode, RequestContext, Signal

# path segments that look like ids (uuid, long hex, or all-digits) → collapsed so "/reports/{id}" groups.
_ID_SEG = re.compile(r"^([0-9a-f]{8,}|[0-9a-f-]{16,}|\d+)$", re.IGNORECASE)


class Guard(ABC):
    """One defense. Stateless: all state lives in the injected ``Store``, so guards are cheap singletons
    and safe under concurrency. Subclasses set ``name`` (unique) and ``default_mode``, and implement
    ``evaluate``; tune thresholds via ``__init__`` args (kept out of the engine, per "thresholds are config")."""

    name: str = ""
    default_mode: Mode = Mode.ENFORCE

    @abstractmethod
    def evaluate(self, ctx: RequestContext, store: Store) -> Signal | None:
        """Return a ``Signal`` to act, or ``None`` for "nothing to say / not my phase". Must not raise on
        the normal path; the engine catches exceptions and fails OPEN, but a guard that raises every time
        is silently disabled — keep it total."""

    # --- shared helpers (available to every guard) ---
    @staticmethod
    def path_template(path: str) -> str:
        """`/api/reports/6f3a.../x` → `/api/reports/:id/x`. Groups id-bearing routes for counting."""
        parts = [":id" if _ID_SEG.match(seg) else seg for seg in path.split("/")]
        return "/".join(parts)

    @staticmethod
    def under_any(path: str, prefixes: tuple[str, ...]) -> bool:
        return any(path.startswith(p) for p in prefixes)


class Registry:
    """An ordered, name-unique set of guards. Not a bare dict so it can enforce invariants (unique name)
    and offer a stable iteration order for the engine."""

    def __init__(self) -> None:
        self._guards: dict[str, Guard] = {}

    def register(self, guard: Guard) -> Guard:
        if not guard.name:
            raise ValueError(f"{type(guard).__name__} must set a non-empty `name`")
        if guard.name in self._guards:
            raise ValueError(f"duplicate guard name: {guard.name!r}")
        self._guards[guard.name] = guard
        return guard

    def get(self, name: str) -> Guard | None:
        return self._guards.get(name)

    def all(self) -> tuple[Guard, ...]:
        return tuple(self._guards.values())

    def names(self) -> tuple[str, ...]:
        return tuple(self._guards)


# The default registry the bundled guards register into. Consumers can build their own Registry and
# register hand-configured guard instances for full control.
REGISTRY = Registry()


def register(cls: type[Guard]) -> type[Guard]:
    """Class decorator: instantiate the guard (default thresholds) and add it to the default REGISTRY."""
    REGISTRY.register(cls())
    return cls
