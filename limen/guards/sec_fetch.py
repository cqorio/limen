"""Sec-Fetch coherence guard: a cookie-session API call from a cross-site context did not come from your page.

``Sec-Fetch-Site`` is browser-set and cannot be forged by page JavaScript, so it cleanly separates "your app's
own fetch" (``same-origin`` / ``same-site``) from a cross-site caller. Default SHADOW: some legitimate flows
(embeds, certain OAuth hops) are cross-site, so watch before enforcing. Only judges browser cookie sessions,
and only when the header is actually present (its absence is not proof of anything).
"""
from __future__ import annotations

from ..core.guard import Guard, register
from ..core.ports import Store
from ..core.types import Action, Mode, RequestContext, Signal


@register
class SecFetch(Guard):
    name = "sec_fetch"
    default_mode = Mode.SHADOW

    def __init__(
        self,
        action: Action = Action.CHALLENGE,
        allowed_sites: tuple[str, ...] = ("same-origin", "same-site", "none"),
    ) -> None:
        self.action = action
        self.allowed_sites = allowed_sites

    def evaluate(self, ctx: RequestContext, store: Store) -> Signal | None:
        if not ctx.is_pre_request or ctx.auth_kind != "session":
            return None
        site = ctx.sec_fetch_site
        if site is not None and site not in self.allowed_sites:
            return Signal(self.action, self.name, f"cross-site fetch (Sec-Fetch-Site: {site}) to {ctx.path}")
        return None
