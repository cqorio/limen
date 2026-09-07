"""Step-up re-auth — require a fresh authentication before a sensitive action.

WHAT IT DETECTS & WHY IT MATTERS
    Some actions (change email/password, delete account, move money, rotate API keys) deserve more than a
    valid session: they should require the user to have proven who they are RECENTLY. This guard enforces
    that "re-authenticate before this" rule generically, so a stolen but idle session cannot walk straight
    into your most dangerous endpoints.

HOW IT DECIDES
    You mark some paths sensitive (``sensitive_paths``, prefix match, empty by default → no-op). When an
    authenticated request hits one, the guard looks for a recent re-auth marker your app writes on a fresh
    login/2FA (``limen:reauth:<account>`` holding the wall-clock time of that auth). Missing, unparseable, or
    older than ``max_age_s`` → it emits ``action`` (default CHALLENGE, i.e. "re-authenticate"). Set the marker
    with ``store.set_str(f"limen:reauth:{account}", str(time.time()), ttl)`` after a successful step-up.

EXAMPLE
    >>> import time
    >>> from limen.adapters import MemoryStore
    >>> from limen.guards.step_up import StepUp
    >>> from limen.core.types import RequestContext, Action
    >>> g = StepUp(sensitive_paths=("/account/delete",), max_age_s=300)
    >>> store = MemoryStore()
    >>> now = time.time()
    >>> req = RequestContext(method="POST", path="/account/delete", account_id="u1", auth_kind="session", ts=now)
    >>> g.evaluate(req, store).action                                  # no recent re-auth -> challenge
    <Action.CHALLENGE: 3>
    >>> store.set_str("limen:reauth:u1", str(now), 300)                # app records a fresh re-auth
    >>> g.evaluate(req, store) is None                                 # now allowed
    True
    >>> g.evaluate(RequestContext(method="GET", path="/home", account_id="u1", ts=now), store) is None
    True

TUNING
    ``sensitive_paths``: the prefixes that demand a fresh auth. ``max_age_s``: how long a re-auth stays valid
    (shorter = safer, more prompts). ``action``: CHALLENGE to force re-auth; BLOCK to refuse outright.

FALSE POSITIVES
    By design it prompts whenever the marker is stale — that is the point, not a false positive. Set the
    marker (and a matching TTL) on every path that counts as a fresh auth, or users get re-prompted.

WHAT IT DOES NOT CATCH
    It trusts the marker: if your app writes it without actually re-authenticating, the gate is empty. It does
    nothing for unauthenticated requests or non-sensitive paths.

STORE KEYS & COST
    Reads one key on a sensitive path: ``limen:reauth:<account>``. O(1); no store access off the sensitive set.
"""
from __future__ import annotations

from ..core.guard import Guard, register
from ..core.ports import Store
from ..core.types import Action, Mode, RequestContext, Signal


@register
class StepUp(Guard):
    name = "step_up"
    default_mode = Mode.ENFORCE

    def __init__(
        self,
        sensitive_paths: tuple[str, ...] = (),
        max_age_s: int = 300,
        action: Action = Action.CHALLENGE,
    ) -> None:
        self.sensitive_paths = tuple(sensitive_paths)
        self.max_age_s = max_age_s
        self.action = action

    def evaluate(self, ctx: RequestContext, store: Store) -> Signal | None:
        if not ctx.is_pre_request or ctx.account_id is None:
            return None
        if not self.sensitive_paths or not self.under_any(ctx.path, self.sensitive_paths):
            return None
        raw = store.get_str(f"limen:reauth:{ctx.account_id}")
        if raw is None:
            return Signal(self.action, self.name, f"step-up required for {ctx.path} (no recent re-auth)")
        try:
            reauthed_at = float(raw)
        except ValueError:
            return Signal(self.action, self.name, f"step-up required for {ctx.path} (bad re-auth marker)")
        if (ctx.ts - reauthed_at) > self.max_age_s:
            return Signal(self.action, self.name, f"step-up required for {ctx.path} (re-auth stale)")
        return None
