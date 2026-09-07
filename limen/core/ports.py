"""The pluggable dependencies Limen needs, as structural ``typing.Protocol``s.

Structural (not ABCs) on purpose: you inject your OWN implementation — wrap your existing Redis client,
your reverse-proxy's client-IP logic, your session/JWT decoder, your captcha SDK — without inheriting anything
of ours. A type that has the right methods IS a valid port. ``limen.adapters`` ships ready-made ones.

ABC-vs-Protocol rule: things you WRAP (something you already own) are Protocols here (``Store`` /
``AsyncStore``, ``ClientIP``, ``Identity``, ``Verifier``, ``Geo``); things you AUTHOR for Limen, with shared
behavior to inherit, are ABCs
(``Guard`` in ``guard.py``, ``Observer`` in ``observer.py``).

You implement a port by writing a class with the right method — no inheritance (shown as a snippet because a
real one needs your framework's request object)::

    class ClientIP:
        def resolve(self, request):
            return request.headers.get("cf-connecting-ip")   # trusted ONLY behind a locked edge
"""
from __future__ import annotations

from typing import Any, Protocol, runtime_checkable


@runtime_checkable
class Store(Protocol):
    """A small shared-state backend: fixed-window counters + short-lived key/value.

    Must be safe for concurrent callers. `incr` is the hot path (rate/enumeration/budget guards);
    the string kv is for honeytoken/watermark bookkeeping. Return 0 / None for missing or expired keys.
    """

    def incr(self, key: str, window_s: int) -> int:
        """Increment `key`'s counter for the current fixed window (creating it with TTL `window_s`
        on the first hit) and return the new count."""
        ...

    def get(self, key: str) -> int:
        """Current counter value for `key` (0 if absent/expired)."""
        ...

    def set_str(self, key: str, value: str, ttl_s: int) -> None:
        """Store a string value under `key`, expiring after `ttl_s` seconds."""
        ...

    def get_str(self, key: str) -> str | None:
        """Read a string value (None if absent/expired)."""
        ...


@runtime_checkable
class AsyncStore(Protocol):
    """The async twin of ``Store`` — same contract, ``await``-able methods, for async apps (FastAPI on
    ``redis.asyncio``) that must not block the event loop.

    A guard reaches an async store only through its ``evaluate_async`` (the sync ``evaluate`` uses ``Store``).
    ``limen.adapters`` ships ``AsyncMemoryStore`` (in-process, zero-infra — used by the async doctests) and
    ``AsyncRedisStore`` (shared across workers). Implement one by wrapping your own async client::

        class AsyncStore:
            async def incr(self, key, window_s): ...   # await your async Redis
    """

    async def incr(self, key: str, window_s: int) -> int:
        """Increment `key`'s counter for the current fixed window (creating it with TTL `window_s` on the
        first hit) and return the new count."""
        ...

    async def get(self, key: str) -> int:
        """Current counter value for `key` (0 if absent/expired)."""
        ...

    async def set_str(self, key: str, value: str, ttl_s: int) -> None:
        """Store a string value under `key`, expiring after `ttl_s` seconds."""
        ...

    async def get_str(self, key: str) -> str | None:
        """Read a string value (None if absent/expired)."""
        ...


@runtime_checkable
class ClientIP(Protocol):
    """Resolve the TRUSTED client IP from a framework request, or None when there is no trustworthy
    source (e.g. no reverse proxy / origin lock). Guards that key on IP self-disable when this is None,
    so per-account rules keep working without a WAF in front."""

    def resolve(self, request: Any) -> str | None: ...


@runtime_checkable
class Identity(Protocol):
    """Resolve ``(account_id, auth_kind)`` from a framework request. `account_id` is None when
    unauthenticated; `auth_kind` is a short tag like "session" or "apikey" so guards can treat
    browser traffic differently from programmatic API-key traffic."""

    def resolve(self, request: Any) -> tuple[str | None, str | None]: ...


@runtime_checkable
class Verifier(Protocol):
    """Turn a human-verification token (from a captcha widget, an emailed code, an internal risk service) into
    a bool. Injected into the middleware so a ``CHALLENGE`` can be satisfied. No vendor is baked in: implement
    this in ~5 lines for your provider, use the bundled ``TurnstileVerifier``, or wire none at all."""

    def verify(self, token: str) -> bool: ...


@runtime_checkable
class Geo(Protocol):
    """Map an IP to a coarse region label (a country/continent code is plenty), or ``None`` when unknown.
    Injected into the ``impossible_travel`` guard so Limen carries no geo-database dependency — wrap MaxMind,
    an IP-info API, or a CDN's country header. The guard self-disables when this returns ``None``."""

    def locate(self, ip: str) -> str | None: ...
