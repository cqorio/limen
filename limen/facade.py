"""``Limen`` — the one object most users need. Holds your Store + config + observers; call it per request."""
from __future__ import annotations

import logging
import time
from typing import Callable, Iterable

from .core.config import EngineConfig
from .core.engine import Engine
from .core.guard import REGISTRY, Registry
from .core.ports import Observer, Store
from .core.types import Action, Decision, Mode, RequestContext

log = logging.getLogger("limen.facade")


class Limen:
    """Quickstart::

        from limen import Limen, RequestContext, Mode
        from limen.adapters import MemoryStore, LoggingObserver

        limen = Limen(MemoryStore(), config={"sequence_anomaly": Mode.ENFORCE},
                      observer=LoggingObserver())
        ctx = RequestContext(method="GET", path="/api/reports/abc", ip="1.2.3.4",
                             account_id="u1", auth_kind="session")
        decision = limen.evaluate(ctx)
        if decision.blocked:
            ...  # refuse / tarpit / challenge, per decision.action

    ``observer`` is one ``Observer`` sink or a list of them (log, JSONL, metrics). ``log_relevance`` is the
    single global switch for the LOG sinks: ``"relevant_only"`` (default — skip plain ALLOWs), ``"all"``, or
    ``"off"``. A metrics sink (``respects_relevance = False``) ignores it and counts every decision.
    """

    def __init__(
        self,
        store: Store,
        config: EngineConfig | dict[str, Mode | str] | None = None,
        registry: Registry = REGISTRY,
        exempt: Callable[[RequestContext], bool] | None = None,
        observer: Observer | Iterable[Observer] | None = None,
        log_relevance: str = "relevant_only",
    ) -> None:
        cfg = config if isinstance(config, EngineConfig) else EngineConfig.from_dict(config)
        self._store = store
        self._engine = Engine(registry, cfg, exempt=exempt)
        self._observers: tuple[Observer, ...] = self._as_tuple(observer)
        if log_relevance not in ("relevant_only", "all", "off"):
            raise ValueError('log_relevance must be "relevant_only", "all", or "off"')
        self._log_relevance = log_relevance

    @staticmethod
    def _as_tuple(observer: Observer | Iterable[Observer] | None) -> tuple[Observer, ...]:
        if observer is None:
            return ()
        if isinstance(observer, (list, tuple)):
            return tuple(observer)
        return (observer,)

    @property
    def store(self) -> Store:
        """The underlying store — exposed so an adapter (e.g. the challenge flow in the middleware) can read
        and write markers without reaching into a private attribute."""
        return self._store

    def evaluate(self, ctx: RequestContext) -> Decision:
        """Run the enabled guards over `ctx` and return the aggregate Decision. Call PRE-request
        (``ctx.status`` None) to enforce. Fires the observers exactly once, here, on the enforcing decision."""
        start = time.perf_counter()
        decision = self._engine.evaluate(ctx, self._store)
        self._emit(ctx, decision, time.perf_counter() - start)
        return decision

    def record(self, ctx: RequestContext) -> None:
        """Feed a POST-response context (``ctx.status`` set) so response-based guards (e.g. 404-rate) update
        their counters. The decision is intentionally discarded — you cannot un-send a response; the
        enforcement lands on the NEXT request's ``evaluate``. Does NOT fire observers (they fire once, on
        ``evaluate``), so a decision is never double-emitted."""
        self._engine.evaluate(ctx, self._store)

    def _emit(self, ctx: RequestContext, decision: Decision, elapsed: float) -> None:
        if not self._observers:
            return
        relevant = decision.action != Action.ALLOW or bool(decision.shadow_reasons)
        for obs in self._observers:
            if getattr(obs, "respects_relevance", True):
                if self._log_relevance == "off":
                    continue
                if self._log_relevance == "relevant_only" and not relevant:
                    continue
            try:
                obs.observe(ctx, decision)
                latency_hook = getattr(obs, "observe_latency", None)
                if latency_hook is not None:
                    latency_hook(elapsed)
            except Exception:  # an observer must never break request handling (fail-open)
                log.warning("limen observer %r failed; ignoring", type(obs).__name__, exc_info=True)
