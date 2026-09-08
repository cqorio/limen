"""FastAPI / Starlette middleware. Extra: ``pip install 'limen[fastapi]'``.

Enforces PRE-request and records POST-response::

    from fastapi import FastAPI
    from limen import Limen
    from limen.adapters import MemoryStore, LimenMiddleware

    app = FastAPI()
    limen = Limen(MemoryStore())
    app.add_middleware(LimenMiddleware, limen=limen, client_ip=my_ip, identity=my_identity)

Async: construct ``Limen`` with an ``AsyncRedisStore`` (or ``AsyncMemoryStore``) and the middleware awaits the
async engine and store automatically (no event-loop blocking). ``client_ip`` / ``identity`` ports may be sync
or async — an async ``resolve`` is awaited (so a coroutine DB lookup for the account works).

Decision → HTTP status: ``BLOCK`` → ``403``, ``THROTTLE`` (a tripped rate limit) → ``429`` with a
``Retry-After: <retry_after>`` header, ``CHALLENGE`` → ``401`` (see the challenge flow below), ``TARPIT`` →
served after ``tarpit_seconds``, ``ALLOW``/``ALERT`` → passed through.

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
import inspect
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
        retry_after: int = 60,
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
        # Retry-After (seconds) sent with a 429 on THROTTLE.
        # ponytail: one value for every bucket; per-bucket would need the window carried on the Decision.
        self.retry_after = retry_after
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
        # An AsyncStore's methods are coroutines: we must AWAIT the engine (evaluate_async) and every direct
        # store call in the challenge/verify flow. Calling a sync method on an async store returns an unawaited
        # coroutine — truthy — which would silently pass every CHALLENGE. Detect it once here.
        self._async_store = inspect.iscoroutinefunction(getattr(limen.store, "incr", None))

    @staticmethod
    async def _await_maybe(value: Any) -> Any:
        """Return `value`, awaiting it first if it is awaitable — so one code path serves both a sync ``Store``
        (returns a value) and an ``AsyncStore`` (returns a coroutine)."""
        return await value if inspect.isawaitable(value) else value

    async def _resolve(self, port: Any, request: Request) -> Any:
        """Call a ClientIP/Identity port's ``resolve``, awaiting it if the port is async."""
        return await self._await_maybe(port.resolve(request))

    async def _ctx(self, request: Request, status: int | None = None) -> RequestContext:
        ip = await self._resolve(self.client_ip, request) if self.client_ip else (request.client.host if request.client else None)
        account_id, auth_kind = await self._resolve(self.identity, request) if self.identity else (None, None)
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

    async def _challenge_passed(self, ctx: RequestContext) -> bool:
        key = self._challenge_key(ctx)
        if key is None:
            return False
        return await self._await_maybe(self.limen.store.get_str(f"challenge_ok:{key}")) is not None

    def _is_reauth_challenge(self, decision: Any) -> bool:
        """True when a guard that manages its own proof (step_up / impossible_travel) drove the CHALLENGE —
        a generic captcha marker must not clear those."""
        return any(r.split(":", 1)[0] in self.reauth_guards for r in decision.reasons)

    async def _handle_verify(self, request: Request) -> Response:
        if self.verifier is None:
            return PlainTextResponse("No verifier configured", status_code=501)
        ctx = await self._ctx(request)
        key = self._challenge_key(ctx)
        if key is None:
            return PlainTextResponse("Cannot identify client", status_code=400)
        # Rate-limit the verify route itself: it never reaches the engine, and each call makes a blocking
        # outbound verify — cap it per caller so it can't be used to flood the verifier or the event loop.
        count = await self._await_maybe(self.limen.store.incr(f"limen:verify_rl:{key}", self.verify_window_s))
        if count > self.verify_limit:
            return PlainTextResponse("Too many attempts", status_code=429)
        token = request.query_params.get("token") or request.headers.get("x-limen-token") or ""
        # verifier.verify may be a blocking network call — run it off the event loop.
        if await run_in_threadpool(self.verifier.verify, token):
            await self._await_maybe(self.limen.store.set_str(f"challenge_ok:{key}", "1", self.challenge_ttl))
            return PlainTextResponse("OK", status_code=200)
        return PlainTextResponse("Verification failed", status_code=403)

    async def dispatch(self, request: Request, call_next: Any) -> Response:
        if request.url.path == self.verify_path and request.method == "POST":
            return await self._handle_verify(request)

        ctx = await self._ctx(request)
        decision = await self.limen.evaluate_async(ctx) if self._async_store else self.limen.evaluate(ctx)
        action = decision.action
        if (action == Action.CHALLENGE and not self._is_reauth_challenge(decision)
                and await self._challenge_passed(ctx)):
            action = Action.ALLOW  # a recent passed challenge exempts, except re-auth/travel challenges

        if action >= Action.BLOCK:
            return PlainTextResponse("Forbidden", status_code=403)
        if action == Action.THROTTLE:
            return PlainTextResponse(
                "Too Many Requests", status_code=429, headers={"Retry-After": str(self.retry_after)}
            )
        if action == Action.CHALLENGE:
            return PlainTextResponse("Verification required", status_code=401)
        if action == Action.TARPIT and self.tarpit_seconds > 0:
            await asyncio.sleep(self.tarpit_seconds)  # serve it, slowly (raises the cost of abuse)

        response = await call_next(request)
        post = await self._ctx(request, status=response.status_code)
        if self._async_store:
            await self.limen.record_async(post)
        else:
            self.limen.record(post)
        return response
