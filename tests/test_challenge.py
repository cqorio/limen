import pytest

pytest.importorskip("starlette")

from starlette.applications import Starlette  # noqa: E402
from starlette.responses import PlainTextResponse  # noqa: E402
from starlette.routing import Route  # noqa: E402
from starlette.testclient import TestClient  # noqa: E402

from limen import Action, Guard, Limen, Mode, Registry, Signal  # noqa: E402
from limen.adapters import AsyncMemoryStore, LimenMiddleware, MemoryStore  # noqa: E402
from limen.guards.rate_limit import RateLimit, by_ip  # noqa: E402
from limen.guards.step_up import StepUp  # noqa: E402


class AsyncIdentity:
    async def resolve(self, request):   # an async port (e.g. a coroutine DB/JWT lookup)
        return "u1", "session"


class AccountChallenge(Guard):
    """Challenges only when the account resolved to the string "u1" — so a 401 proves the async identity
    yielded a real string, not an unawaited coroutine."""

    name = "acct_challenge"
    default_mode = Mode.ENFORCE

    def evaluate(self, ctx, store):
        return Signal(Action.CHALLENGE, self.name, "u1 must verify") if ctx.account_id == "u1" else None

    async def evaluate_async(self, ctx, store):
        return self.evaluate(ctx, store)  # pure compute — no store access


class ChallengeProtected(Guard):
    name = "challenge_protected"
    default_mode = Mode.ENFORCE

    def evaluate(self, ctx, store):
        if ctx.path == "/protected":
            return Signal(Action.CHALLENGE, self.name, "verify to enter")
        return None

    async def evaluate_async(self, ctx, store):
        return self.evaluate(ctx, store)  # pure compute — no store access


class TokenVerifier:
    def verify(self, token):
        return token == "good"


class FixedIdentity:
    def resolve(self, request):
        return "u1", "session"


def _client(verifier=None, guard=None, identity=None, async_store=False, **mw):
    reg = Registry()
    reg.register(guard or ChallengeProtected())
    limen = Limen(AsyncMemoryStore() if async_store else MemoryStore(), registry=reg)

    async def protected(request):
        return PlainTextResponse("secret")

    app = Starlette(routes=[Route("/protected", protected)])
    app.add_middleware(LimenMiddleware, limen=limen, verifier=verifier, identity=identity, **mw)
    return TestClient(app)


def test_challenge_served_as_401_without_a_passed_marker():
    client = _client(verifier=TokenVerifier())
    assert client.get("/protected").status_code == 401


def test_verify_then_allowed_within_ttl():
    client = _client(verifier=TokenVerifier())
    assert client.get("/protected").status_code == 401
    assert client.post("/_limen/verify?token=good").status_code == 200  # solves the challenge
    assert client.get("/protected").status_code == 200                  # marker now exempts it


def test_bad_token_is_rejected_and_still_challenged():
    client = _client(verifier=TokenVerifier())
    assert client.post("/_limen/verify?token=bad").status_code == 403
    assert client.get("/protected").status_code == 401


def test_no_verifier_still_challenges():
    client = _client(verifier=None)
    assert client.get("/protected").status_code == 401           # CHALLENGE still surfaces
    assert client.post("/_limen/verify?token=good").status_code == 501  # nothing to verify with


def test_verify_route_is_rate_limited():
    client = _client(verifier=TokenVerifier(), verify_limit=3, verify_window_s=60)
    for _ in range(3):  # 3 attempts allowed (bad token → 403)
        assert client.post("/_limen/verify?token=bad").status_code == 403
    assert client.post("/_limen/verify?token=bad").status_code == 429  # 4th is throttled


def test_step_up_challenge_is_not_cleared_by_a_generic_captcha_marker():
    # A captcha proves "human", not "recently re-authenticated" — it must NOT satisfy step_up.
    step_up = StepUp(sensitive_paths=("/protected",))
    client = _client(verifier=TokenVerifier(), guard=step_up, identity=FixedIdentity())
    assert client.get("/protected").status_code == 401           # step_up challenges (no re-auth marker)
    assert client.post("/_limen/verify?token=good").status_code == 200  # captcha solved
    assert client.get("/protected").status_code == 401           # STILL challenged (captcha != re-auth)


# --- async store: the middleware must AWAIT the engine + the challenge/verify markers (v1.1.0) ---

def test_async_store_challenge_not_satisfied_by_missing_marker():
    """Plan (b): under an AsyncStore a CHALLENGE stays 401 — the marker read must be AWAITED, not left as a
    truthy unawaited coroutine that would silently exempt every request."""
    client = _client(verifier=TokenVerifier(), async_store=True)
    assert client.get("/protected").status_code == 401


def test_async_store_verify_writes_and_reads_marker_no_500():
    """Plan (c): verify route increments + verifies + writes the marker (all awaited) with no 500, and the
    marker then exempts the challenge."""
    client = _client(verifier=TokenVerifier(), async_store=True)
    assert client.get("/protected").status_code == 401
    assert client.post("/_limen/verify?token=good").status_code == 200   # awaited incr + set_str, no 500
    assert client.get("/protected").status_code == 200                   # awaited marker read exempts it


def test_async_identity_resolves_account_to_a_string():
    """Plan (d): an async Identity port is awaited, so account_id is a real string (the guard fires on "u1")."""
    client = _client(guard=AccountChallenge(), identity=AsyncIdentity(), async_store=True)
    assert client.get("/protected").status_code == 401   # would be 200 if account_id were an unawaited coroutine


# --- v1.2.0: a tripped RateLimit is a THROTTLE, served as 429 + Retry-After (NOT 403) ---

def test_rate_limit_trips_429_with_retry_after():
    """A RateLimit bucket that trips emits Action.THROTTLE, which the middleware serves as 429 + Retry-After
    (a retryable "slow down"), not a 403. TestClient's socket peer is the trusted IP the bucket keys on."""
    client = _client(guard=RateLimit(name="t", key=by_ip, limit=2, window_s=60), retry_after=42)
    assert client.get("/protected").status_code == 200   # 1st under the limit (record phase never re-counts)
    assert client.get("/protected").status_code == 200   # 2nd under the limit
    resp = client.get("/protected")                       # 3rd trips
    assert resp.status_code == 429
    assert resp.headers["Retry-After"] == "42"


def test_rate_limit_trips_429_on_async_store():
    """Same throttle mapping over an AsyncStore (evaluate_async path)."""
    client = _client(guard=RateLimit(name="t", key=by_ip, limit=1, window_s=60), async_store=True)
    assert client.get("/protected").status_code == 200
    assert client.get("/protected").status_code == 429
