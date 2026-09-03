import hashlib
import hmac

from limen.adapters import MemoryStore
from limen.core.types import Action, RequestContext
from limen.guards.watermark import Watermark


def test_emits_deterministic_tag_for_account():
    g = Watermark(secret="s3cret")
    sig = g.evaluate(RequestContext(method="GET", path="/x", account_id="u1"), MemoryStore())
    expected = hmac.new(b"s3cret", b"u1", hashlib.sha256).hexdigest()[:16]
    assert sig is not None
    assert sig.action is Action.ALERT  # never blocks
    assert sig.reason == f"wm={expected}"


def test_no_secret_is_noop():
    assert Watermark().evaluate(RequestContext(method="GET", path="/x", account_id="u1"), MemoryStore()) is None


def test_no_account_is_noop():
    g = Watermark(secret="s")
    assert g.evaluate(RequestContext(method="GET", path="/x", account_id=None), MemoryStore()) is None
