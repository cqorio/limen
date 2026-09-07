"""Observability + rate-limit recipes. Run: python examples/observability.py

Shows three things v1.0 adds: the generic RateLimit (one class per bucket, replacing the old account_budget),
decision sinks (an Observer you can SEE), and Limen's own operational logs.
"""
import sys

import limen
from limen import Action, Limen, Registry, RequestContext
from limen.adapters import JsonlObserver, LoggingObserver, MemoryStore
from limen.guards.rate_limit import RateLimit, by_account, by_ip

# Layer A — Limen's own operational logs (is the engine healthy?) on stderr. Off by default; opt in:
limen.enable_logging()

# Build a registry of rate-limit buckets: the generic RateLimit, one instance per dimension you want to cap.
reg = Registry()
reg.register(RateLimit(name="per_ip", key=by_ip, limit=5, window_s=60))  # anti-flood, per IP
reg.register(  # the ex-`account_budget`: a per-account request budget, served slowly (TARPIT)
    RateLimit(name="account_budget", key=by_account, limit=100, window_s=3600, action=Action.TARPIT)
)

# Layer B — two decision sinks: human-readable logs + a JSONL audit stream to the screen. The global
# log_relevance="relevant_only" keeps the ALLOW noise out of the logs.
engine = Limen(
    MemoryStore(),
    registry=reg,
    observer=[LoggingObserver(), JsonlObserver(sys.stdout)],
    log_relevance="relevant_only",
)

# Six requests from one IP against a 5/min cap → the 6th trips BLOCK and appears in both sinks.
d = None
for _ in range(6):
    d = engine.evaluate(RequestContext(method="GET", path="/api/items", ip="9.9.9.9"))

print("final action ->", d.action.name, d.reasons)
assert d.action is Action.BLOCK, "the 6th request should be blocked by the per-IP bucket"
