import pytest

pytest.importorskip("prometheus_client")  # skips cleanly unless `limen[prometheus]` is installed

from prometheus_client import CollectorRegistry  # noqa: E402

from limen import Action, Guard, Limen, Mode, Registry, RequestContext, Signal  # noqa: E402
from limen.adapters import MemoryStore, PrometheusObserver  # noqa: E402


class Block(Guard):
    name = "block"
    default_mode = Mode.ENFORCE

    def evaluate(self, ctx, store):
        if ctx.path == "/blocked":
            return Signal(Action.BLOCK, self.name, "blocked")
        return None


def _value(registry, action, guard):
    return registry.get_sample_value("limen_decisions_total", {"action": action, "guard": guard}) or 0.0


def test_counts_every_action_including_allow():
    prom_registry = CollectorRegistry()
    obs = PrometheusObserver(registry=prom_registry)
    reg = Registry()
    reg.register(Block())
    limen = Limen(MemoryStore(), registry=reg, observer=obs, log_relevance="off")  # off must NOT gag metrics

    limen.evaluate(RequestContext(method="GET", path="/ok"))        # ALLOW
    limen.evaluate(RequestContext(method="GET", path="/ok"))        # ALLOW
    limen.evaluate(RequestContext(method="GET", path="/blocked"))   # BLOCK

    assert _value(prom_registry, "ALLOW", "none") == 2.0   # allow IS counted → denominator for "% blocked"
    assert _value(prom_registry, "BLOCK", "block") == 1.0
