"""Impossible travel — one account seen from two different regions in too short a time = a likely stolen session.

WHAT IT DETECTS & WHY IT MATTERS
    A hijacked session or shared/leaked credentials often show up as the same account making requests from
    geographically distant places within minutes. A human cannot be in two countries at once, so a region
    change inside a short window is a strong "verify this is really you" signal.

HOW IT DECIDES
    An injected ``Geo`` port maps ``ctx.ip`` to a coarse region label (a country code is plenty). The guard
    remembers the last ``(region, ts)`` per account in the ``Store``; if the current region differs from the
    remembered one AND the gap is within ``window_s``, it emits ``action``. It self-disables when there is no
    ``Geo``, no trusted IP, no account, or an unknown region — so it is a safe no-op until you wire geo.

    Ceiling: with only coarse region LABELS (no coordinates) this is "region changed within the window", not a
    true speed/distance calculation. Adjacent-border legitimate movement can trip it; that is why the default
    mode is SHADOW and the default action is CHALLENGE, not BLOCK.

EXAMPLE
    >>> from limen.adapters import MemoryStore
    >>> from limen.guards.impossible_travel import ImpossibleTravel
    >>> from limen.core.types import RequestContext, Action
    >>> class StubGeo:                       # your real Geo wraps MaxMind / an IP-info API
    ...     def __init__(self, m): self.m = m
    ...     def locate(self, ip): return self.m.get(ip)
    >>> geo = StubGeo({"1.1.1.1": "US", "2.2.2.2": "JP"})
    >>> g = ImpossibleTravel(geo=geo, window_s=3600)
    >>> store = MemoryStore()
    >>> g.evaluate(RequestContext(method="GET", path="/x", account_id="u1", ip="1.1.1.1", ts=1000.0), store) is None
    True
    >>> g.evaluate(RequestContext(method="GET", path="/x", account_id="u1", ip="2.2.2.2", ts=1100.0), store).action
    <Action.CHALLENGE: 3>

TUNING
    ``window_s``: how close in time two regions must be to look impossible (larger = stricter/more alerts).
    ``action``: CHALLENGE (verify) is usual; ALERT to only observe, BLOCK only once you trust the geo source.

FALSE POSITIVES
    VPNs, mobile carriers routing through another country, travelers, and border regions all look like a jump.
    Keep it SHADOW until you have watched the rate; consider allow-listing known VPN egress.

WHAT IT DOES NOT CATCH
    A thief in the SAME region as the victim. Coarse labels miss intra-region impossibility. It needs a
    ``Geo`` source and a trusted IP; without either it does nothing.

STORE KEYS & COST
    One key per active account: ``limen:geo:<account>`` (last region + ts). O(1): one read + one write.
"""
from __future__ import annotations

import json

from ..core.guard import Guard, register
from ..core.ports import AsyncStore, Geo, Store
from ..core.types import Action, Mode, RequestContext, Signal


@register
class ImpossibleTravel(Guard):
    name = "impossible_travel"
    default_mode = Mode.SHADOW  # region heuristics are noisy — watch before enforcing

    def __init__(self, geo: Geo | None = None, window_s: int = 3600, action: Action = Action.CHALLENGE) -> None:
        self.geo = geo
        self.window_s = window_s
        self.action = action

    def evaluate(self, ctx: RequestContext, store: Store) -> Signal | None:
        if not ctx.is_pre_request or self.geo is None or ctx.account_id is None or ctx.ip is None:
            return None
        region = self.geo.locate(ctx.ip)
        if region is None:
            return None
        key = f"limen:geo:{ctx.account_id}"
        stored = store.get_str(key)
        raw = json.loads(stored) if stored else None
        # Only advance the stored sighting with a NEWER observation (ignore reordered/late arrivals).
        if raw is None or ctx.ts >= raw[1]:
            store.set_str(key, json.dumps([region, ctx.ts]), self.window_s)
        if raw:
            last_region, last_ts = raw
            delta = ctx.ts - last_ts
            if last_region != region and 0 <= delta <= self.window_s:
                return Signal(
                    self.action,
                    self.name,
                    f"account {ctx.account_id}: region {last_region}->{region} in {delta:.0f}s",
                )
        return None

    async def evaluate_async(self, ctx: RequestContext, store: AsyncStore) -> Signal | None:
        if not ctx.is_pre_request or self.geo is None or ctx.account_id is None or ctx.ip is None:
            return None
        region = self.geo.locate(ctx.ip)  # Geo port is sync (no I/O we own)
        if region is None:
            return None
        key = f"limen:geo:{ctx.account_id}"
        stored = await store.get_str(key)
        raw = json.loads(stored) if stored else None
        if raw is None or ctx.ts >= raw[1]:
            await store.set_str(key, json.dumps([region, ctx.ts]), self.window_s)
        if raw:
            last_region, last_ts = raw
            delta = ctx.ts - last_ts
            if last_region != region and 0 <= delta <= self.window_s:
                return Signal(
                    self.action,
                    self.name,
                    f"account {ctx.account_id}: region {last_region}->{region} in {delta:.0f}s",
                )
        return None
