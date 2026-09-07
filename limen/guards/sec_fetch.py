"""Sec-Fetch / origin coherence — a cookie-session call that did not come from your own page.

WHAT IT DETECTS & WHY IT MATTERS
    Browsers stamp ``Sec-Fetch-Site`` on every request and page JavaScript cannot forge it, so it cleanly
    separates "your app's own fetch" (``same-origin`` / ``same-site``) from a cross-site caller. On a cookie
    session that is a strong signal: your API is being called from somewhere that is not your app (an embed, a
    malicious page, a CSRF attempt). With ``methods=`` set it also becomes a CSRF guard for state-changing
    requests (see below).

HOW IT DECIDES
    Only judges browser cookie sessions (``auth_kind == "session"``); API-key traffic is ignored.
    - READ coherence: if ``Sec-Fetch-Site`` is present and NOT in ``allowed_sites`` (default same-origin /
      same-site / none), emit ``action``. An ABSENT header is not proof here (old clients omit it), so it is
      left alone.
    - CSRF (only when ``methods`` is set, e.g. POST/PUT/PATCH/DELETE): for those methods the stance INVERTS —
      the request must POSITIVELY prove same-origin. ``Sec-Fetch-Site: same-origin``/``same-site`` proves it;
      otherwise (absent, or ``none``) the ``Origin``/``Referer`` must match one of ``allowed_origins``. If
      nothing proves same-origin, emit ``action``. This is what closes the header-absent CSRF hole.

EXAMPLE
    >>> from limen.adapters import MemoryStore
    >>> from limen.guards.sec_fetch import SecFetch
    >>> from limen.core.types import RequestContext, Action
    >>> store = MemoryStore()
    >>> g = SecFetch()                                   # default: read-coherence only
    >>> g.evaluate(RequestContext(method="GET", path="/api/me", sec_fetch_site="cross-site",
    ...                           auth_kind="session"), store).action
    <Action.CHALLENGE: 3>
    >>> csrf = SecFetch(methods=("POST",), allowed_origins=("https://example.com",))
    >>> post = RequestContext(method="POST", path="/api/pay", auth_kind="session")   # no proof at all
    >>> csrf.evaluate(post, store).action
    <Action.CHALLENGE: 3>
    >>> ok = RequestContext(method="POST", path="/api/pay", auth_kind="session", origin="https://example.com")
    >>> csrf.evaluate(ok, store) is None                 # Origin matches -> allowed
    True

TUNING
    ``methods``: leave empty for read-coherence only; set the state-changing verbs to turn on CSRF. Note that
    CSRF needs either browser Sec-Fetch or a configured ``allowed_origins`` to have anything to prove against.
    ``allowed_sites`` / ``allowed_origins``: your own origins. ``action``: CHALLENGE or BLOCK.

FALSE POSITIVES
    Legitimate cross-site flows (embeds, some OAuth hops) look cross-site — the read check defaults to SHADOW
    for that reason. For CSRF, forgetting to list a real front-end origin re-prompts real users; list them all.

WHAT IT DOES NOT CATCH
    Non-browser CSRF-style abuse over API keys (out of scope — those are not cookie sessions). A same-origin
    XSS acting as the user (that is the sanitizer's job, not this guard's).

STORE KEYS & COST
    None — a pure header check. O(1), no store access.
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
        methods: tuple[str, ...] = (),
        allowed_origins: tuple[str, ...] = (),
    ) -> None:
        self.action = action
        self.allowed_sites = allowed_sites
        self.methods = tuple(m.upper() for m in methods)
        self.allowed_origins = allowed_origins

    def _origin_ok(self, ctx: RequestContext) -> bool:
        """Positive same-origin proof from Origin/Referer against the configured origins."""
        if not self.allowed_origins:
            return False  # nothing to validate against → cannot prove same-origin
        origin = ctx.origin
        if origin and any(origin.rstrip("/") == o.rstrip("/") for o in self.allowed_origins):
            return True
        ref = ctx.referer
        if ref and any(ref.startswith(o) for o in self.allowed_origins):
            return True
        return False

    def evaluate(self, ctx: RequestContext, store: Store) -> Signal | None:
        if not ctx.is_pre_request or ctx.auth_kind != "session":
            return None
        site = ctx.sec_fetch_site
        # (1) read coherence: an explicit cross-site header on a cookie session
        if site is not None and site not in self.allowed_sites:
            return Signal(self.action, self.name, f"cross-site fetch (Sec-Fetch-Site: {site}) to {ctx.path}")
        # (2) CSRF for state-changing methods: require POSITIVE same-origin proof (acts on an absent header)
        if self.methods and ctx.method.upper() in self.methods:
            if site in ("same-origin", "same-site") or self._origin_ok(ctx):
                return None
            return Signal(self.action, self.name, f"{ctx.method} {ctx.path}: no same-origin proof (possible CSRF)")
        return None
