"""FastAPI / Starlette middleware. Extra: ``pip install 'limen[fastapi]'``.

Enforces PRE-request and records POST-response::

    from fastapi import FastAPI
    from limen import Limen
    from limen.adapters import MemoryStore, LimenMiddleware

    app = FastAPI()
    limen = Limen(MemoryStore())
    app.add_middleware(LimenMiddleware, limen=limen, client_ip=my_ip, identity=my_identity)

Challenge flow (optional): pass a ``verifier`` (any ``Verifier`` — e.g. ``TurnstileVerifier``). On a CHALLENGE
decision the middleware serves 401 unless the caller has a recent passed-marker; the caller solves the
challenge and POSTs the token to ``verify_path`` (default ``/_limen/verify``), which verifies it and writes the
marker for ``challenge_ttl`` seconds. With no ``verifier`` a CHALLENGE is simply served as 401.

Two safeguards on that flow:
- The passed-marker is keyed on the ACCOUNT when known, else the IP. An IP key is shared behind NAT/CGNAT, so
  one solved challenge exempts every caller on that egress IP until ``challenge_ttl`` — keep the TTL modest and
  prefer authenticated (per-account) challenges.
- A captcha proves "human", NOT "recently re-authenticated". So a passed marker does NOT satisfy a CHALLENGE
  raised by a ``reauth_guards`` guard (default ``step_up``/``impossible_travel``): those must be cleared by
  their own mechanism (e.g. the app writing ``limen:reauth:<account>``), never by a generic captcha.
"""
from __future__ import annotations

import asyncio
from typing import Any

try:
    from starlette.concurrency import run_in_threadpool
    from starlette.middleware.base import BaseHTTPMiddleware
    from starlette.requests import Request
    from starlette.responses import PlainTextResponse, Response
except ImportError as exc:  # pragma: no cover
    raise ImportError("the FastAPI adapter needs starlette/fastapi: pip install 'limen[fastapi]'") from exc

from ..core.types import Action, RequestContext
from ..facade import Limen


class LimenMiddleware(BaseHTTPMiddleware):
    """`client_ip` / `identity` are optional ports (see limen.core.ports). Without `client_ip` it falls
    back to the socket peer; without `identity` the request is treated as unauthenticated."""

    def __init__(
        self,
        app: Any,
        limen: Limen,
        client_ip: Any = None,
        identity: Any = None,
        tarpit_seconds: float = 1.0,
        client_ip_trusted: bool = False,
        verifier: Any = None,
        verify_path: str = "/_limen/verify",
        challenge_ttl: int = 1800,
        verify_limit: int = 30,
        verify_window_s: int = 60,
        reauth_guards: tuple[str, ...] = ("step_up", "impossible_travel"),
    ) -> None:
        super().__init__(app)
        self.limen = limen
        self.client_ip = client_ip
        self.identity = identity
        self.tarpit_seconds = tarpit_seconds
        # Assert True ONLY behind a locked edge that sets the client-IP header AND a proxy that strips
        # spoofable copies. It stamps ctx.ip_trusted, which an IP-based `exempt` must gate on. Default False,
        # so an IP-based exempt is inert until you deliberately vouch for your IP source.
        self.client_ip_trusted = client_ip_trusted
        self.verifier = verifier
        self.verify_path = verify_path
        self.challenge_ttl = challenge_ttl
        self.verify_limit = verify_limit          # cap POSTs to the verify route (anti-flood, per caller)
        self.verify_window_s = verify_window_s
        self.reauth_guards = reauth_guards        # challenges a captcha marker must NOT satisfy

    def _ctx(self, request: Request, status: int | None = None) -> RequestContext:
        ip = self.client_ip.resolve(request) if self.client_ip else (request.client.host if request.client else None)
        account_id, auth_kind = self.identity.resolve(request) if self.identity else (None, None)
        return RequestContext(
            method=request.method,
            path=request.url.path,
            status=status,
            sec_fetch_site=request.headers.get("sec-fetch-site"),
            sec_fetch_mode=request.headers.get("sec-fetch-mode"),
            ip=ip,
            ip_trusted=self.client_ip_trusted and ip is not None,
            account_id=account_id,
            auth_kind=auth_kind,
            referer=request.headers.get("referer"),
            origin=request.headers.get("origin"),
        )

    def _challenge_key(self, ctx: RequestContext) -> str | None:
        return ctx.account_id or ctx.ip

    def _challenge_passed(self, ctx: RequestContext) -> bool:
        key = self._challenge_key(ctx)
        return key is not None and self.limen.store.get_str(f"challenge_ok:{key}") is not None

    def _is_reauth_challenge(self, decision: Any) -> bool:
        """True when a guard that manages its own proof (step_up / impossible_travel) drove the CHALLENGE —
        a generic captcha marker must not clear those."""
        return any(r.split(":", 1)[0] in self.reauth_guards for r in decision.reasons)

    async def _handle_verify(self, request: Request) -> Response:
        if self.verifier is None:
            return PlainTextResponse("No verifier configured", status_code=501)
        ctx = self._ctx(request)
        key = self._challenge_key(ctx)
        if key is None:
            return PlainTextResponse("Cannot identify client", status_code=400)
        # Rate-limit the verify route itself: it never reaches the engine, and each call makes a blocking
        # outbound verify — cap it per caller so it can't be used to flood the verifier or the event loop.
        if self.limen.store.incr(f"limen:verify_rl:{key}", self.verify_window_s) > self.verify_limit:
            return PlainTextResponse("Too many attempts", status_code=429)
        token = request.query_params.get("token") or request.headers.get("x-limen-token") or ""
        # verifier.verify may be a blocking network call — run it off the event loop.
        if await run_in_threadpool(self.verifier.verify, token):
            self.limen.store.set_str(f"challenge_ok:{key}", "1", self.challenge_ttl)
            return PlainTextResponse("OK", status_code=200)
        return PlainTextResponse("Verification failed", status_code=403)

    async def dispatch(self, request: Request, call_next: Any) -> Response:
        if request.url.path == self.verify_path and request.method == "POST":
            return await self._handle_verify(request)

        ctx = self._ctx(request)
        decision = self.limen.evaluate(ctx)
        action = decision.action
        if action == Action.CHALLENGE and self._challenge_passed(ctx) and not self._is_reauth_challenge(decision):
            action = Action.ALLOW  # a recent passed challenge exempts, except re-auth/travel challenges

        if action >= Action.BLOCK:
            return PlainTextResponse("Forbidden", status_code=403)
        if action == Action.CHALLENGE:
            return PlainTextResponse("Verification required", status_code=401)
        if action == Action.TARPIT and self.tarpit_seconds > 0:
            await asyncio.sleep(self.tarpit_seconds)  # serve it, slowly (raises the cost of abuse)

        response = await call_next(request)
        self.limen.record(self._ctx(request, status=response.status_code))
        return response
