import io
import json

from limen import Action, Guard, Limen, Mode, Observer, Registry, RequestContext, Signal
from limen.adapters import JsonlObserver, MemoryStore


class Block(Guard):
    name = "block"
    default_mode = Mode.ENFORCE

    def evaluate(self, ctx, store):
        return Signal(Action.BLOCK, self.name, "blocked")


def _block_registry():
    reg = Registry()
    reg.register(Block())
    return reg


class Capture(Observer):
    def __init__(self):
        self.events = []

    def observe(self, ctx, decision):
        self.events.append((ctx, decision))


class Metrics(Observer):
    respects_relevance = False

    def __init__(self):
        self.count = 0

    def observe(self, ctx, decision):
        self.count += 1


def _req(**kw):
    kw.setdefault("method", "GET")
    kw.setdefault("path", "/x")
    return RequestContext(**kw)


def test_fires_once_on_evaluate_and_not_on_record():
    cap = Capture()
    limen = Limen(MemoryStore(), config={"enumeration": Mode.ENFORCE}, observer=cap, log_relevance="all")
    limen.record(_req(path="/api/reports/1", status=404, ip="9.9.9.9"))  # post-response: must NOT emit
    assert cap.events == []
    limen.evaluate(_req(path="/api/me", ip="9.9.9.9"))                    # pre-request: emits once
    assert len(cap.events) == 1


def test_relevant_only_skips_allow_for_logs_but_metrics_still_count():
    cap, met = Capture(), Metrics()
    limen = Limen(MemoryStore(), observer=[cap, met])  # default log_relevance="relevant_only"
    limen.evaluate(_req(account_id="u1", auth_kind="session"))  # a plain ALLOW
    assert cap.events == []  # log sink skipped the allow
    assert met.count == 1    # metrics counted it (needs the allow for "% blocked")


def test_all_relevance_includes_allow():
    cap = Capture()
    limen = Limen(MemoryStore(), observer=cap, log_relevance="all")
    limen.evaluate(_req(account_id="u1"))
    assert len(cap.events) == 1


def test_off_silences_logs_even_on_a_block_but_metrics_still_count():
    cap, met = Capture(), Metrics()
    limen = Limen(MemoryStore(), registry=_block_registry(), observer=[cap, met], log_relevance="off")
    d = limen.evaluate(_req())
    assert d.action is Action.BLOCK
    assert cap.events == []  # "off" silences the log sink
    assert met.count == 1    # metrics ignore log_relevance entirely


def test_a_raising_observer_never_breaks_the_request():
    class Boom(Observer):
        def observe(self, ctx, decision):
            raise RuntimeError("sink down")

    limen = Limen(MemoryStore(), registry=_block_registry(), observer=Boom(), log_relevance="all")
    d = limen.evaluate(_req())  # must not raise
    assert d.action is Action.BLOCK


def test_a_raising_latency_hook_never_breaks_the_request():
    class BadLatency(Observer):
        def observe(self, ctx, decision):
            pass

        def observe_latency(self, seconds):
            raise RuntimeError("metric backend down")

    limen = Limen(MemoryStore(), registry=_block_registry(), observer=BadLatency(), log_relevance="all")
    d = limen.evaluate(_req())  # must not raise
    assert d.action is Action.BLOCK


def test_jsonl_observer_writes_one_json_line_per_decision():
    buf = io.StringIO()
    limen = Limen(MemoryStore(), registry=_block_registry(), observer=JsonlObserver(buf), log_relevance="all")
    limen.evaluate(_req(path="/pay", ip="1.1.1.1"))
    rec = json.loads(buf.getvalue().strip())
    assert rec["action"] == "BLOCK" and rec["path"] == "/pay" and rec["ip"] == "1.1.1.1"


def test_invalid_log_relevance_is_rejected():
    import pytest

    with pytest.raises(ValueError):
        Limen(MemoryStore(), log_relevance="sometimes")
