"""The extension point: a ``Guard`` is one defense, and the ``Registry`` is the set of them.

Add a defense = subclass ``Guard``, set ``name``, implement ``evaluate``, decorate with ``@register``.
Nothing else in the codebase needs to change (the engine iterates the registry). This mirrors a plugin
registry: one small, explicit, framework-free surface.

    >>> from limen.core.guard import Guard
    >>> Guard.path_template("/api/reports/6f3a9c2b1d4e/pdf")   # id segments collapse so routes group
    '/api/reports/:id/pdf'
    >>> Guard.under_any("/api/items/1", ("/api/items/", "/orders/"))
    True
"""
from __future__ import annotations

import re
from abc import ABC, abstractmethod

from .ports import AsyncStore, Store
from .types import Action, Mode, RequestContext, Signal

# path segments that look like ids (uuid, long hex, or all-digits) → collapsed so "/reports/{id}" groups.
_ID_SEG = re.compile(r"^([0-9a-f]{8,}|[0-9a-f-]{16,}|\d+)$", re.IGNORECASE)


class Guard(ABC):
    """One defense. Stateless: all state lives in the injected ``Store``, so guards are cheap singletons
    and safe under concurrency. Subclasses set ``name`` (unique) and ``default_mode``, and implement
    ``evaluate``; tune thresholds via ``__init__`` args (kept out of the engine, per "thresholds are config")."""

    name: str = ""
    default_mode: Mode = Mode.ENFORCE
    # The action this guard deals in. Read by the engine ONLY on the fail-closed path (below), where there is
    # no Signal to read it from. Guards that emit a single action set it (rate_limit, denylist, …); guards with
    # no single action leave the BLOCK default (it is used only when `fail_closed` is True, so it never bites
    # a fail-open guard). Base default here means `guard.action` is ALWAYS safe to read — see engine.evaluate.
    action: Action = Action.BLOCK
    # When True and this guard's `evaluate` RAISES (store outage, a bug), the engine denies with `action`
    # instead of failing open — but only under ENFORCE (a SHADOW fail-closed records to shadow_reasons). Opt-in
    # per guard; the DEFAULT is fail-OPEN, so a broken guard never locks users out unless you asked it to.
    fail_closed: bool = False

    @abstractmethod
    def evaluate(self, ctx: RequestContext, store: Store) -> Signal | None:
        """Return a ``Signal`` to act, or ``None`` for "nothing to say / not my phase". Must not raise on
        the normal path; the engine catches exceptions and fails OPEN (unless ``fail_closed``), but a guard
        that raises every time is silently disabled — keep it total."""

    async def evaluate_async(self, ctx: RequestContext, store: AsyncStore) -> Signal | None:
        """The async twin of ``evaluate`` (used by ``Engine.evaluate_async`` with an ``AsyncStore``).

        The base **raises** — it deliberately does NOT fall back to ``self.evaluate`` — because a sync guard
        run against an async store would call ``store.incr(...)`` without awaiting it, and in Python an
        UNAWAITED COROUTINE IS TRUTHY: the guard would count nothing and silently FAIL OPEN. So a store-backed
        guard MUST override this with an awaiting body; a pure-compute guard (no store access) may simply
        ``return self.evaluate(ctx, store)`` since it never touches the store. A guard that forgets is loud
        (this raise), not silently disabled."""
        raise NotImplementedError(
            f"{type(self).__name__} has no evaluate_async; a store-backed guard must implement it (awaiting the "
            f"async store), and a pure-compute guard may `return self.evaluate(ctx, store)`."
        )

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
