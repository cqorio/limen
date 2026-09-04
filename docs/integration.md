# Integrating Limen

Limen runs wherever you can see the request. For a typical **SPA + API** app (a Next.js frontend proxying to a
FastAPI backend — the shape this guide assumes), the enforcement point is **one middleware in the backend**,
optionally with a **thin early reject at the edge**. You supply two small objects that teach Limen how *your*
app authenticates and how it finds the client IP; everything else is defaults you tune.

There are exactly four decisions: **store**, **identity**, **client IP**, **which guards + modes**.

---

## 1. Store — where counters live

```python
from limen.adapters import MemoryStore, RedisStore
store = MemoryStore()                       # single process / dev / tests
store = RedisStore(url="redis://localhost") # multiple workers or replicas (pip install 'limen[redis]')
```
Rate/enumeration/budget guards count in the store, so with more than one process you need Redis or each worker
counts separately.

## 2. Identity — "who is this request?"

A duck-typed object with `resolve(request) -> (account_id, auth_kind)`. `account_id` is your tenant key (None
when unauthenticated); `auth_kind` is a short tag so guards can treat browser sessions differently from
programmatic API-key traffic (e.g. `sequence_anomaly` only judges `"session"`). Wrap your EXISTING auth — Limen
never decodes tokens itself.

```python
class Identity:
    def resolve(self, request):
        token = read_session_cookie(request)     # your existing session/JWT logic
        if token:
            return account_id_from(token), "session"
        key = request.headers.get("x-api-key")
        if key:
            return account_id_for_key(key), "apikey"
        return None, None
```

## 3. ClientIP — "what is the trusted client IP?"

`resolve(request) -> str | None`. Return the IP you *trust*, or `None` when you have no trustworthy source —
per-IP guards then self-disable and per-account guards carry on (Limen degrades gracefully without a WAF/edge).

```python
class ClientIP:
    def resolve(self, request):
        # trustworthy ONLY because your edge (Cloudflare, ALB, …) sets this AND your proxy strips spoofable
        # copies (x-forwarded-for, etc.). If that isn't true, return None.
        return request.headers.get("cf-connecting-ip")
```

## 4. Guards + modes — shadow-first

```python
from limen import Limen, Mode
limen = Limen(store, config={
    "enumeration": Mode.ENFORCE,
    "account_budget": Mode.ENFORCE,
    "sequence_anomaly": Mode.SHADOW,   # observe for a while, then flip to ENFORCE
    "sec_fetch": Mode.SHADOW,
}, exempt=lambda ctx: ctx.ip_trusted and ctx.ip in TRUSTED_SCANNER_IPS)   # see "Exempting trusted traffic"
```
Unlisted guards use their own default mode. `config` sets **modes**; to change **thresholds** or scope a guard
to specific paths, use a custom registry (below).

## 5. Enforce — the backend middleware

```python
from limen.adapters import LimenMiddleware
app.add_middleware(LimenMiddleware, limen=limen,
                   client_ip=ClientIP(), identity=Identity(), tarpit_seconds=1.0)
```
The middleware evaluates **pre-request** (BLOCK→403, CHALLENGE→429, TARPIT→`tarpit_seconds` delay then serve)
and **observes post-response** (feeds response statuses to guards like `enumeration` that count 404s). Every
route is covered — no per-endpoint code. (`examples/fastapi_app.py` is this, runnable.)

## 6. (Optional) early reject at the edge — Next.js proxy

If a same-origin proxy sits in front (a Next `route.ts`), you can reject before forwarding with `@limen/proxy`.
Keep **one** engine (the backend); the edge just applies the backend's `Decision`.

```ts
import { buildContext, applyDecision } from "@limen/proxy";
const ctx = buildContext(request, { ip, account_id, auth_kind });
const decision = await askBackendLimen(ctx);   // a small internal endpoint that calls limen.evaluate
const early = applyDecision(decision);          // 403 on BLOCK, 429 on CHALLENGE, else null
if (early) return early;
```
See `examples/nextjs_proxy.md`.

---

## Exempting trusted traffic (your own scanner, a partner)

High-volume traffic you *sent* (a security scanner pointed at your own site) will look hostile. `exempt`
short-circuits to ALLOW before any guard runs.

> **DANGER — an IP exempt is a total bypass, and only as trustworthy as your IP source.** `exempt` skips
> *every* guard (enumeration, account_budget, honeytoken, all of it). If `ctx.ip` comes from a spoofable
> header (no locked edge / unstripped `x-forwarded-for`), an attacker sets that header, matches your
> allowlist, and turns Limen off entirely — with no auth required. This is *more* dangerous than a per-IP
> guard: an untrusted IP makes per-IP guards self-disable, but a spoofed IP here bypasses per-account guards too.

So gate the exempt on **`ctx.ip_trusted`**, which `LimenMiddleware` stamps True only when you pass
`client_ip_trusted=True` (assert that ONLY behind a locked edge). Then a spoofed header can never satisfy it,
and the exempt is inert until you deliberately vouch for your IP source:

```python
TRUSTED_SCANNER_IPS = {"203.0.113.7", "203.0.113.8"}
limen = Limen(store, config={...}, exempt=lambda ctx: ctx.ip_trusted and ctx.ip in TRUSTED_SCANNER_IPS)
app.add_middleware(LimenMiddleware, limen=limen, client_ip=ClientIP(), identity=Identity(),
                   client_ip_trusted=True)  # ONLY if your edge sets the IP header and strips spoofable copies
```

## Custom registry — thresholds, path scoping, canaries

`Limen(store, config=...)` uses the default registry (each guard at its default thresholds). To set thresholds,
scope `enumeration` to your id routes, or configure `honeytoken` canaries, build your own registry of configured
instances and pass it in:

```python
from limen import Registry, Limen
from limen.guards.enumeration import Enumeration
from limen.guards.account_budget import AccountBudget
from limen.guards.honeytoken import Honeytoken

reg = Registry()
reg.register(Enumeration(window_s=60, limit=15, path_prefixes=("/api/reports/", "/r/")))
reg.register(AccountBudget(window_s=3600, limit=1000))
reg.register(Honeytoken(paths=("/api/reports/__canary_9f3a7c__",)))   # random + unlinked

limen = Limen(store, registry=reg, config={"enumeration": Mode.ENFORCE})
# Only the guards you register run — this is opt-in. (Per-guard runtime threshold config without a custom
# registry is a planned ergonomic; for now, construct the instances you want.)
```

## Testing your integration

- **Enumeration**: from one IP, request `/api/reports/<random>` (a 404) ~limit+1 times, then any request from
  that IP → 403.
- **Account budget**: loop a cheap authed endpoint past the limit → 429/TARPIT.
- **Shadow doesn't bite**: with `sequence_anomaly` in SHADOW, drive it hard and confirm real users are never
  blocked — the finding appears in `decision.shadow_reasons` only.
- **Exemption**: the same abusive pattern from a `TRUSTED_SCANNER_IPS` address → ALLOW.

## Where things run (summary)

| concern | where |
|---|---|
| enforcement | backend `LimenMiddleware` (has the account + trusted IP) |
| early reject | optional edge proxy (`@limen/proxy`), applies the backend Decision |
| shared counters | `RedisStore` when >1 process |
| "who / what IP" | your `Identity` / `ClientIP` ports, injected once |
| trusted-traffic bypass | `exempt=` predicate on source IP |
