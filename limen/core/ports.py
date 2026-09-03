"""The pluggable dependencies Limen needs, as structural ``typing.Protocol``s.

Structural (not ABCs) on purpose: you inject your OWN implementation — wrap your existing Redis client,
your reverse-proxy's client-IP logic, your session/JWT decoder — without inheriting anything of ours.
A type that has the right methods IS a valid port. `limen.adapters` ships ready-made ones.
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
