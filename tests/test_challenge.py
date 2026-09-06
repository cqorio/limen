import pytest

pytest.importorskip("starlette")

from starlette.applications import Starlette  # noqa: E402
from starlette.responses import PlainTextResponse  # noqa: E402
from starlette.routing import Route  # noqa: E402
from starlette.testclient import TestClient  # noqa: E402

from limen import Action, Guard, Limen, Mode, Registry, Signal  # noqa: E402
from limen.adapters import LimenMiddleware, MemoryStore  # noqa: E402
from limen.guards.step_up import StepUp  # noqa: E402


class ChallengeProtected(Guard):
    name = "challenge_protected"
    default_mode = Mode.ENFORCE

    def evaluate(self, ctx, store):
        if ctx.path == "/protected":
            return Signal(Action.CHALLENGE, self.name, "verify to enter")
        return None


class TokenVerifier:
    def verify(self, token):
        return token == "good"


class FixedIdentity:
    def resolve(self, request):
        return "u1", "session"


def _client(verifier=None, guard=None, identity=None, **mw):
    reg = Registry()
    reg.register(guard or ChallengeProtected())
    limen = Limen(MemoryStore(), registry=reg)

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
