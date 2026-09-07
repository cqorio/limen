"""Denylist — hard-block specific accounts or IPs you have already judged to be bad.

WHAT IT DETECTS & WHY IT MATTERS
    The mirror image of ``exempt`` (an allowlist): a banned/abusive account or a known-bad IP should lose
    access outright, not merely be rate-limited. This is the "we know this one is bad" control.

HOW IT DECIDES
    Two sources, checked cheaply: a STATIC set of accounts/IPs passed at construction (config), and — when
    ``store_backed`` is on — a DYNAMIC entry in the ``Store`` (``limen:deny:account:<id>`` /
    ``limen:deny:ip:<ip>``) so an app can ban at runtime by writing a key (with an optional TTL for a
    temp-ban). A match emits ``action`` (default BLOCK). Empty static sets + ``store_backed=False`` is a true
    no-op, so ENFORCE-by-default is safe out of the box.

EXAMPLE
    >>> from limen.adapters import MemoryStore
    >>> from limen.guards.denylist import Denylist
    >>> from limen.core.types import RequestContext, Action
    >>> g = Denylist(accounts=("banned-1",), ips=("6.6.6.6",))
    >>> g.evaluate(RequestContext(method="GET", path="/x", account_id="banned-1"), MemoryStore()).action
    <Action.BLOCK: 4>
    >>> g.evaluate(RequestContext(method="GET", path="/x", ip="6.6.6.6"), MemoryStore()).action
    <Action.BLOCK: 4>
    >>> g.evaluate(RequestContext(method="GET", path="/x", account_id="ok"), MemoryStore()) is None
    True

TUNING
    ``accounts`` / ``ips``: the static ban lists. ``store_backed``: enable to also honor runtime bans written
    to the store (default False so the bundled instance stays a zero-cost no-op). ``action``: BLOCK to refuse,
    TARPIT/CHALLENGE if you prefer to slow rather than shut out.

FALSE POSITIVES
    Only what you put on the list. IP bans age badly (addresses are reassigned; NAT shares them) — prefer
    account bans, and give store-backed IP bans a TTL.

WHAT IT DOES NOT CATCH
    Anything you have not listed. It is not detection — it enforces a decision you (or another guard, or an
    ops tool) already made.

STORE KEYS & COST
    Static-only: O(1), no store access. ``store_backed``: up to two ``get_str`` reads per request.
"""
from __future__ import annotations

from ..core.guard import Guard, register
from ..core.ports import AsyncStore, Store
from ..core.types import Action, Mode, RequestContext, Signal


@register
class Denylist(Guard):
    name = "denylist"
    default_mode = Mode.ENFORCE

    def __init__(
        self,
        accounts: tuple[str, ...] = (),
        ips: tuple[str, ...] = (),
        action: Action = Action.BLOCK,
        store_backed: bool = False,
    ) -> None:
        self.accounts = frozenset(accounts)
        self.ips = frozenset(ips)
        self.action = action
        self.store_backed = store_backed

    def evaluate(self, ctx: RequestContext, store: Store) -> Signal | None:
        if not ctx.is_pre_request:
            return None
        acct, ip = ctx.account_id, ctx.ip
        if acct is not None and acct in self.accounts:
            return Signal(self.action, self.name, f"account {acct} is denylisted")
        if ip is not None and ip in self.ips:
            return Signal(self.action, self.name, f"ip {ip} is denylisted")
        if self.store_backed:
            if acct is not None and store.get_str(f"limen:deny:account:{acct}") is not None:
                return Signal(self.action, self.name, f"account {acct} is denylisted (runtime)")
            if ip is not None and store.get_str(f"limen:deny:ip:{ip}") is not None:
                return Signal(self.action, self.name, f"ip {ip} is denylisted (runtime)")
        return None

    async def evaluate_async(self, ctx: RequestContext, store: AsyncStore) -> Signal | None:
        if not ctx.is_pre_request:
            return None
        acct, ip = ctx.account_id, ctx.ip
        if acct is not None and acct in self.accounts:
            return Signal(self.action, self.name, f"account {acct} is denylisted")
        if ip is not None and ip in self.ips:
            return Signal(self.action, self.name, f"ip {ip} is denylisted")
        if self.store_backed:
            if acct is not None and await store.get_str(f"limen:deny:account:{acct}") is not None:
                return Signal(self.action, self.name, f"account {acct} is denylisted (runtime)")
            if ip is not None and await store.get_str(f"limen:deny:ip:{ip}") is not None:
                return Signal(self.action, self.name, f"ip {ip} is denylisted (runtime)")
        return None
