"""Value objects for Limen: the immutable data a guard reasons over and the decision it produces.

All frozen dataclasses (cheap, hashable, no accidental mutation on the hot path) and two small enums.
`Action` is an ``IntEnum`` ordered by severity so aggregating many guards' signals is just ``max()``.

    >>> from limen.core.types import Action, Decision, RequestContext
    >>> Action.BLOCK > Action.ALLOW                 # ordered by severity → aggregate with max()
    True
    >>> Decision(action=Action.TARPIT).blocked      # tarpit/challenge/block all count as "blocked"
    True
    >>> RequestContext(method="GET", path="/x").is_pre_request   # no status yet = the enforce phase
    True
"""
from __future__ import annotations

import time
from dataclasses import dataclass, field
from enum import Enum, IntEnum


class Mode(Enum):
    """How a guard's signal is treated. Roll a new guard out in SHADOW, watch it, then ENFORCE."""

    OFF = "off"          # not run at all
    SHADOW = "shadow"    # evaluated and logged, but NEVER affects the returned action
    ENFORCE = "enforce"  # its signal can raise the decision's action


class Action(IntEnum):
    """What to do about a request, least to most severe. Aggregation across guards is ``max``."""

    ALLOW = 0      # nothing
    ALERT = 1      # let it through, but flag it (non-blocking)
    TARPIT = 2     # let it through slowly (add latency)
    CHALLENGE = 3  # require a human/interactive check (e.g. a captcha)
    BLOCK = 4      # refuse the request


@dataclass(frozen=True, slots=True)
class RequestContext:
    """One request, normalized. Build it in an adapter (see limen.adapters) or by hand.

    PHASE CONVENTION: ``status is None`` means the PRE-request (enforce) phase — guards that decide
    from request metadata act here. ``status is not None`` means the POST-response (observe) phase —
    guards that key on the response (e.g. counting 404s) update their state here. Most guards handle
    exactly one phase and return None in the other.
    """

    method: str
    path: str
    status: int | None = None            # response status; None = pre-request phase
    sec_fetch_site: str | None = None     # e.g. "same-origin" | "cross-site"
    sec_fetch_mode: str | None = None     # e.g. "navigate" | "cors"
    ip: str | None = None                 # trusted client IP, or None when there is no trustworthy source
    account_id: str | None = None         # resolved tenant/account, or None when unauthenticated
    auth_kind: str | None = None          # "session" | "apikey" | None
    referer: str | None = None
    origin: str | None = None             # the Origin header, for CSRF/same-origin proof on writes
    # True ONLY when `ip` came from a source that cannot be spoofed (a locked edge that sets it + a proxy that
    # strips client-supplied copies). Default False. Gate an IP-based `exempt` on this so a spoofed header can
    # never satisfy the bypass: `exempt=lambda ctx: ctx.ip_trusted and ctx.ip in TRUSTED`.
    ip_trusted: bool = False
    ts: float = field(default_factory=time.time)

    @property
    def is_pre_request(self) -> bool:
        return self.status is None


@dataclass(frozen=True, slots=True)
class Signal:
    """A single guard's finding: the action it suggests, why, and an optional additive score."""

    action: Action
    guard: str
    reason: str
    score: float = 0.0


@dataclass(frozen=True, slots=True)
class Decision:
    """The engine's aggregate answer for one request."""

    action: Action
    score: float = 0.0
    reasons: tuple[str, ...] = ()          # from ENFORCE guards (drove the action)
    shadow_reasons: tuple[str, ...] = ()   # from SHADOW guards (what WOULD have happened)

    @property
    def blocked(self) -> bool:
        """True when the caller should not serve the request normally (tarpit/challenge/block)."""
        return self.action >= Action.TARPIT

    @property
    def flagged(self) -> bool:
        """True when anything fired at all (alert or worse), enforced OR shadow."""
        return self.action >= Action.ALERT or bool(self.shadow_reasons)
