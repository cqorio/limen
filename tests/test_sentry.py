import importlib.util

import pytest

from limen import Action, Decision, Guard, Limen, Mode, Registry, RequestContext, Signal
from limen.adapters import MemoryStore, SentryObserver


def _observer_with_capture():
    events = []
    obs = SentryObserver(capture=lambda msg, level, tags: events.append((level, msg, tags)))
    return obs, events


def test_reports_a_block_with_tags():
    obs, events = _observer_with_capture()
    obs.observe(
        RequestContext(method="POST", path="/pay", ip="1.1.1.1", account_id="u1"),
        Decision(action=Action.BLOCK, reasons=("rate_limit: over",)),
    )
    assert len(events) == 1
    level, msg, tags = events[0]
    assert level == "warning"
    assert tags["limen_action"] == "BLOCK" and tags["limen_ip"] == "1.1.1.1" and tags["limen_account"] == "u1"
    assert "rate_limit: over" in msg


def test_below_min_action_is_not_reported():
    obs, events = _observer_with_capture()
    obs.observe(RequestContext(method="GET", path="/x"), Decision(action=Action.ALERT))
    obs.observe(RequestContext(method="GET", path="/x"), Decision(action=Action.TARPIT))
    assert events == []  # default min_action = BLOCK


def test_shadow_only_block_is_not_reported():
    # a SHADOW guard's would-be BLOCK leaves decision.action at ALLOW → below the min_action floor
    obs, events = _observer_with_capture()
    obs.observe(RequestContext(method="GET", path="/x"),
                Decision(action=Action.ALLOW, shadow_reasons=("sequence_anomaly: would block",)))
    assert events == []


def test_min_action_is_configurable():
    events = []
    obs = SentryObserver(min_action=Action.CHALLENGE, capture=lambda m, l, t: events.append(t["limen_action"]))
    obs.observe(RequestContext(method="GET", path="/x"), Decision(action=Action.CHALLENGE))
    obs.observe(RequestContext(method="GET", path="/x"), Decision(action=Action.TARPIT))  # below
    assert events == ["CHALLENGE"]


def test_through_the_facade_relevance_and_min_action_compose():
    events = []
    obs = SentryObserver(capture=lambda m, l, t: events.append(t["limen_action"]))

    class Block(Guard):
        name = "b"
        default_mode = Mode.ENFORCE

        def evaluate(self, ctx, store):
            return Signal(Action.BLOCK, self.name, "x") if ctx.path == "/bad" else None

    reg = Registry()
    reg.register(Block())
    limen = Limen(MemoryStore(), registry=reg, observer=obs)  # default log_relevance="relevant_only"
    limen.evaluate(RequestContext(method="GET", path="/ok"))   # ALLOW → dropped by relevant_only
    limen.evaluate(RequestContext(method="GET", path="/bad"))  # BLOCK → reported
    assert events == ["BLOCK"]


def test_default_capture_needs_the_extra():
    if importlib.util.find_spec("sentry_sdk") is not None:
        pytest.skip("sentry-sdk is installed")
    with pytest.raises(ImportError):
        SentryObserver()  # no capture → tries to import sentry_sdk and fails clearly


def test_default_capture_uses_a_supported_scope_api():
    """Runs only when sentry-sdk is installed: exercises the real new_scope()/set_tag()/capture_message()
    path so a future SDK API break (like push_scope's removal in 3.0) is caught, not silently swallowed."""
    sentry_sdk = pytest.importorskip("sentry_sdk")
    captured = []
    sentry_sdk.init(
        dsn="https://public@example.com/1",
        before_send=lambda event, hint: captured.append(event) or None,  # capture, then drop (no network)
        default_integrations=False,
    )
    SentryObserver().observe(
        RequestContext(method="POST", path="/pay", ip="1.1.1.1"),
        Decision(action=Action.BLOCK, reasons=("rate_limit: over",)),
    )
    assert captured and captured[0].get("tags", {}).get("limen_action") == "BLOCK"
