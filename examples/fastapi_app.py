"""A COMPLETE FastAPI integration. Needs the extra: pip install 'limen[fastapi]'.
Run: uvicorn examples.fastapi_app:app  → then hit http://127.0.0.1:8000/api/me

Shows the three things a real app must supply: an Identity port (who is this?), a ClientIP port (what is
the trusted IP?), and — optionally — an exempt predicate (skip trusted source IPs, e.g. your own scanner).
See docs/integration.md for the full walkthrough.
"""
from fastapi import FastAPI

from limen import Limen, Mode
from limen.adapters import LimenMiddleware, MemoryStore  # use RedisStore in production (multi-worker)


# 1) Identity: return (account_id, auth_kind). Replace the bodies with your real session/JWT + API-key logic.
class Identity:
    def resolve(self, request):
        token = request.cookies.get("session")          # your cookie/JWT session
        if token:
            return f"acct-for-{token}", "session"        # -> decode to your real account id
        key = request.headers.get("x-api-key")           # programmatic clients
        if key:
            return f"acct-for-key-{key}", "apikey"
        return None, None


# 2) ClientIP: the trusted client IP (or None). Trust cf-connecting-ip ONLY behind a locked edge that sets it
#    and a proxy that strips spoofable copies; otherwise return None and per-IP guards self-disable.
class ClientIP:
    def resolve(self, request):
        return request.headers.get("cf-connecting-ip") or (request.client.host if request.client else None)


TRUSTED_SCANNER_IPS = {"203.0.113.7"}  # your own crawler's egress IPs — never throttle yourself

app = FastAPI()
limen = Limen(
    MemoryStore(),
    # Rate limiting is opt-in — add RateLimit buckets to a custom registry (see examples/observability.py).
    config={"enumeration": Mode.ENFORCE, "sequence_anomaly": Mode.SHADOW},
    # `ctx.ip_trusted` gates the bypass: with client_ip_trusted=False below, this is inert, so copying this
    # example is NEVER a bypass. An attacker spoofing cf-connecting-ip cannot satisfy it.
    exempt=lambda ctx: ctx.ip_trusted and ctx.ip in TRUSTED_SCANNER_IPS,
)
app.add_middleware(
    LimenMiddleware, limen=limen, client_ip=ClientIP(), identity=Identity(), tarpit_seconds=1.0,
    # Flip to True ONLY when you are behind a locked edge that sets cf-connecting-ip and strips spoofable
    # copies (x-forwarded-for, …). Until then, ctx.ip_trusted stays False and the IP exempt above never fires.
    client_ip_trusted=False,
)


@app.get("/api/me")
def me():
    return {"ok": True}
