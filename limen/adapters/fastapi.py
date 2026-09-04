"""FastAPI / Starlette middleware. Extra: ``pip install 'limen[fastapi]'``.

Enforces PRE-request and observes POST-response::

    from fastapi import FastAPI
    from limen import Limen
    from limen.adapters import MemoryStore, LimenMiddleware

    app = FastAPI()
    limen = Limen(MemoryStore())
    app.add_middleware(LimenMiddleware, limen=limen, client_ip=my_ip, identity=my_identity)
"""
from __future__ import annotations

import asyncio
from typing import Any

try:
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
        )

    async def dispatch(self, request: Request, call_next: Any) -> Response:
        decision = self.limen.evaluate(self._ctx(request))
        if decision.action >= Action.BLOCK:
            return PlainTextResponse("Forbidden", status_code=403)
        if decision.action == Action.CHALLENGE:
            return PlainTextResponse("Verification required", status_code=429)
        if decision.action == Action.TARPIT and self.tarpit_seconds > 0:
            await asyncio.sleep(self.tarpit_seconds)  # serve it, slowly (raises the cost of abuse)
        response = await call_next(request)
        self.limen.observe(self._ctx(request, status=response.status_code))
        return response
