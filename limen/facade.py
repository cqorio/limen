"""``Limen`` — the one object most users need. Holds your Store + config; call it per request."""
from __future__ import annotations

from typing import Callable

from .core.config import EngineConfig
from .core.engine import Engine
from .core.guard import REGISTRY, Registry
from .core.ports import Store
from .core.types import Decision, Mode, RequestContext


class Limen:
    """Quickstart::

        from limen import Limen, RequestContext, Mode
        from limen.adapters import MemoryStore

        limen = Limen(MemoryStore(), config={"sequence_anomaly": Mode.ENFORCE})
        ctx = RequestContext(method="GET", path="/api/reports/abc", ip="1.2.3.4",
                             account_id="u1", auth_kind="session")
        decision = limen.evaluate(ctx)
        if decision.blocked:
            ...  # refuse / tarpit / challenge, per decision.action
    """

    def __init__(
        self,
        store: Store,
        config: EngineConfig | dict[str, Mode | str] | None = None,
        registry: Registry = REGISTRY,
        exempt: Callable[[RequestContext], bool] | None = None,
    ) -> None:
        cfg = config if isinstance(config, EngineConfig) else EngineConfig.from_dict(config)
        self._store = store
        self._engine = Engine(registry, cfg, exempt=exempt)

    def evaluate(self, ctx: RequestContext) -> Decision:
        """Run the enabled guards over `ctx` and return the aggregate Decision. Call PRE-request
        (``ctx.status`` None) to enforce."""
        return self._engine.evaluate(ctx, self._store)

    def observe(self, ctx: RequestContext) -> None:
        """Feed a POST-response context (``ctx.status`` set) so response-based guards (e.g. 404-rate)
        update their counters. The decision is intentionally discarded — you cannot un-send a response;
        the enforcement lands on the NEXT request's ``evaluate``."""
        self._engine.evaluate(ctx, self._store)
