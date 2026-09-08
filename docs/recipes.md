# Recipes

Short, copy-paste answers to "how do I express *X* with Limen's primitives". Every guard is general; the
examples below use plain paths (`/api/items`, `/orders`) — swap in your own. Two worked apps appear throughout:
a **plain JSON API** and an **e-commerce checkout**. (framescan, the scanner SaaS Limen was validated against,
is just one more consumer — it wires the same primitives.)

All recipes assume:

```python
from limen import Limen, Registry, Action, Mode, RequestContext
from limen.adapters import MemoryStore   # or RedisStore across workers
```

## Rate-limit an endpoint per IP

```python
from limen.guards.rate_limit import RateLimit, by_ip
reg = Registry()
reg.register(RateLimit(name="login_ip", key=by_ip, limit=10, window_s=60, fail_closed=True))  # default action THROTTLE → 429
limen = Limen(MemoryStore(), registry=reg)
```

`fail_closed=True` on a security-critical bucket (login) denies if the store is down, instead of waving
everyone through. Leave it False (the default) elsewhere to fail open.

## A per-tenant read budget (the old `account_budget`)

```python
from limen.guards.rate_limit import RateLimit, by_account
reg.register(RateLimit(name="account_budget", key=by_account, limit=600, window_s=3600, action=Action.TARPIT))
```

Per-account, served slowly (TARPIT) over budget. Self-disables for unauthenticated traffic.

## Several buckets at once (per-IP + per-account + per-endpoint + global)

```python
from limen.guards.rate_limit import RateLimit, by_ip, by_account, by_path, global_, per
reg = Registry()
reg.register(RateLimit(name="anon_ip",   key=by_ip,               limit=100, window_s=60))
reg.register(RateLimit(name="acct",      key=by_account,          limit=600, window_s=3600, action=Action.TARPIT))
reg.register(RateLimit(name="checkout",  key=per(by_account, by_path), limit=20, window_s=60))  # composite
reg.register(RateLimit(name="global",    key=global_,             limit=5000, window_s=1, fail_closed=True))
```

E-commerce checkout: the `checkout` bucket caps a single account hammering `/orders`; the `global` bucket is a
coarse site-wide backstop.

## Catch id-enumeration (404 scanning)

```python
from limen.guards.enumeration import Enumeration
reg.register(Enumeration(limit=20, window_s=60, path_prefixes=("/api/items/", "/orders/")))
```

Scope it to your id routes so a crawler's incidental 404s elsewhere do not count.

## Block a list of accounts or IPs

```python
from limen.guards.denylist import Denylist
reg.register(Denylist(accounts=("banned-42",), ips=("203.0.113.9",)))
# or store-backed for runtime bans: Denylist(store_backed=True), then
#   store.set_str("limen:deny:account:banned-42", "1", 86400)   # 24h temp-ban
```

## Captcha-gate a form (challenge), provider-agnostic

```python
from limen.adapters import LimenMiddleware, TurnstileVerifier
# any guard that returns Action.CHALLENGE triggers it; e.g. sec_fetch/impossible_travel, or your own guard
app.add_middleware(LimenMiddleware, limen=limen, verifier=TurnstileVerifier(secret="0x..."))
```

Your own provider is a 5-line `Verifier`:

```python
class EmailCodeVerifier:
    def verify(self, token: str) -> bool:
        return token == lookup_expected_code_for_this_session()
```

Wire no verifier at all and a `CHALLENGE` simply surfaces in the `Decision` for your app to handle.

## Protect a dangerous action with step-up re-auth

```python
from limen.guards.step_up import StepUp
reg.register(StepUp(sensitive_paths=("/account/delete", "/orders/refund"), max_age_s=300))
# after a fresh login / 2FA, your app records the marker:
#   store.set_str(f"limen:reauth:{account_id}", str(time.time()), 300)
```

## CSRF-protect state-changing requests

```python
from limen.guards.sec_fetch import SecFetch
reg.register(SecFetch(methods=("POST", "PUT", "PATCH", "DELETE"),
                      allowed_origins=("https://app.example.com",)))
```

## Combine weak signals into a challenge (the risk spine)

```python
from limen import EngineConfig
cfg = EngineConfig(
    modes={"sequence_anomaly": Mode.ENFORCE, "timing": Mode.ENFORCE, "sec_fetch": Mode.ENFORCE},
    score_thresholds=((30, Action.BLOCK), (15, Action.CHALLENGE), (5, Action.ALERT)),
)
limen = Limen(MemoryStore(), config=cfg, registry=reg)
```

Give your guards a `score=` on their `Signal`; three weak signals summing past 15 → CHALLENGE, though none
alone would.

## Build a registry from your own config (admin-editable limits)

Limen ships no `from_config` — your config schema is yours. The whole glue is ~10 lines you own, so limits can
live in a database/`app_config` and be edited without a redeploy:

```python
from limen import Registry, Action
from limen.guards.rate_limit import RateLimit, by_ip, by_account, by_path

KEYS = {"ip": by_ip, "account": by_account, "path": by_path}

def build_registry(buckets):
    """buckets: e.g. [{"name": "anon_ip", "key": "ip", "limit": 100, "window_s": 60, "action": "BLOCK"}]"""
    reg = Registry()
    for b in buckets:
        reg.register(RateLimit(
            name=b["name"], key=KEYS[b["key"]],
            limit=b["limit"], window_s=b["window_s"],
            action=Action[b.get("action", "BLOCK")],
            fail_closed=b.get("fail_closed", False),
        ))
    return reg
```

## See what it decided (logs) and graph it (metrics)

```python
from limen.adapters import LoggingObserver, JsonlObserver, PrometheusObserver, SentryObserver
limen = Limen(store, registry=reg,
              observer=[LoggingObserver(), JsonlObserver("limen-audit.jsonl"),
                        PrometheusObserver(), SentryObserver()],   # SentryObserver needs limen[sentry]
              log_relevance="relevant_only")   # logs skip ALLOWs; metrics still count them
```

`SentryObserver` reports only decisions at or above `min_action` (default BLOCK) as tagged Sentry messages. For
any other service (Datadog/Slack/webhook), subclass `Observer` — see docs/integration.md, "Write your own observer".

Expose the metrics (and **protect** the route — internal-only or admin-gated; never public):

```python
from prometheus_client import make_asgi_app
app.mount("/metrics", make_asgi_app())   # scraped by Prometheus inside your network only
```

`limen_decisions_total{action,guard}` counts every action including `allow`, so "% blocked" =
`block / sum(all)`.
