"""Minimal Limen usage — no framework, no Redis. Run: python examples/minimal.py"""
from limen import Limen, Mode, RequestContext
from limen.adapters import MemoryStore

limen = Limen(MemoryStore(), config={"enumeration": Mode.ENFORCE, "account_budget": Mode.ENFORCE})

# A normal authenticated request → allowed.
d = limen.evaluate(RequestContext(method="GET", path="/api/me", account_id="u1", auth_kind="session", ip="1.2.3.4"))
print("normal request ->", d.action.name, d.reasons)

# An attacker guessing report ids: many 404s from one IP (observe phase) → then they are blocked.
for i in range(25):
    limen.observe(RequestContext(method="GET", path=f"/api/reports/{i}", status=404, ip="6.6.6.6"))
d = limen.evaluate(RequestContext(method="GET", path="/api/reports/0", ip="6.6.6.6"))
print("enumerator     ->", d.action.name, d.reasons)

assert d.blocked, "the enumerator should be blocked"
