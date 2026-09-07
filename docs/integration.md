# Integrating Limen

Limen runs wherever you can see the request. For a typical **SPA + API** app (a Next.js frontend proxying to a
FastAPI backend — the shape this guide assumes), the enforcement point is **one middleware in the backend**,
optionally with a **thin early reject at the edge**. You supply a few small objects that teach Limen how *your*
app authenticates and finds the client IP; everything else is defaults you tune.

You can follow this start to finish to wire a plain FastAPI app — nothing here is specific to any one product.

There are four decisions: **store**, **identity**, **client IP**, **which guards + modes** — then you turn on
**observability** and (optionally) **challenge**.

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
programmatic API-key traffic (e.g. `sequence_anomaly`/`sec_fetch` only judge `"session"`). Wrap your EXISTING
auth — Limen never decodes tokens itself.

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
    "rate_limit": Mode.ENFORCE,
    "sequence_anomaly": Mode.SHADOW,   # observe for a while, then flip to ENFORCE
    "sec_fetch": Mode.SHADOW,
})
```
Unlisted guards use their own default mode. `config` sets **modes**; to change **thresholds**, add rate-limit
buckets, or scope a guard, use a custom registry (below / see `docs/recipes.md`).

## 5. Enforce — the backend middleware

```python
from limen.adapters import LimenMiddleware
app.add_middleware(LimenMiddleware, limen=limen,
                   client_ip=ClientIP(), identity=Identity(), tarpit_seconds=1.0)
```
The middleware evaluates **pre-request** (BLOCK→403, CHALLENGE→401, TARPIT→`tarpit_seconds` delay then serve)
and **records post-response** (feeds response statuses to guards like `enumeration` that count 404s). Every
route is covered — no per-endpoint code. (`examples/fastapi_app.py` is this, runnable.)

---

## The rollout loop — OFF → SHADOW → watch → ENFORCE

Never flip a new guard straight to ENFORCE in production. The safe path, and how you actually *watch*:

1. **SHADOW** the guard (`config={"sequence_anomaly": Mode.SHADOW}`). It evaluates but never changes the action.
2. **Wire an Observer** so you can SEE what it *would* have done — shadow findings arrive in
   `decision.shadow_reasons` and in your sink:
   ```python
   from limen.adapters import LoggingObserver
   limen = Limen(store, config={"sequence_anomaly": Mode.SHADOW}, observer=LoggingObserver())
   ```
3. **Read the findings** for a while (a day, a week). Confirm real users are not being flagged.
4. **ENFORCE** once you trust it (`Mode.ENFORCE`). Keep the Observer on to watch the real blocks.

Without step 2 you are flying blind — a SHADOW guard with no Observer produces nothing you can act on.

## Observability — the two layers

**Layer A — operational logs (is the engine healthy?).** Standard-library logging, **silent by default**. Turn
it on for dev/CLI:

```python
import limen
limen.enable_logging()                       # -> stderr, INFO
limen.enable_logging(stream=open("limen.log", "a"))
```
In production, configure the `limen` logger yourself (do not call `enable_logging`). A routine BLOCK logs at
INFO; WARNING/ERROR are reserved for Limen's own faults (a guard failed open, the store is down).

**Layer B — the decision stream (what did it decide, and why?).** Pass one or more `Observer` sinks:

```python
from limen.adapters import LoggingObserver, JsonlObserver, PrometheusObserver
limen = Limen(store, observer=[LoggingObserver(), JsonlObserver("limen-audit.jsonl"), PrometheusObserver()],
              log_relevance="relevant_only")
```
- `LoggingObserver` — one structured line per decision through stdlib logging.
- `JsonlObserver(dest)` — one JSON object per line to a file path or an open stream (`sys.stdout` = the screen);
  grep/tail it, ship it to Loki/ELK. This is your inspectable audit log.
- `PrometheusObserver` (`limen[prometheus]`) — counts **every** action including `allow`. Expose and
  **protect** the endpoint yourself:
  ```python
  from prometheus_client import make_asgi_app
  app.mount("/metrics", make_asgi_app())   # internal-only (scraped inside your network), never public
  ```
  `limen_decisions_total{action,guard}` gives "% blocked" = `block / sum(all)`.
- `SentryObserver` (`limen[sentry]`) — reports serious decisions (>= `min_action`, default BLOCK) to Sentry as
  tagged messages, for alerting. Quiet by design (a LOG sink + the `min_action` floor).

`log_relevance` is ONE global switch for the LOG sinks: `"relevant_only"` (default — skip plain ALLOWs),
`"all"`, or `"off"`. The metrics sink ignores it and always counts. Observers never break a request: a sink that
raises is logged and swallowed. (`examples/observability.py` is this, runnable.)

### Write your own observer

Every sink is an `Observer` — an ABC, like a `Guard` or Python's `logging.Handler`. Subclass it, implement
`observe`, optionally set `respects_relevance` (False only for a metrics/always-on sink) or override
`observe_latency`, and reuse `self.event(...)` for the field union. That is the whole extension point — Sentry,
Datadog, Slack, a webhook, OpenTelemetry all plug in the same way:

```python
import urllib.request, json
from limen import Observer

class SlackWebhook(Observer):
    def __init__(self, url): self.url = url
    def observe(self, ctx, decision):
        if decision.action.name in ("BLOCK", "CHALLENGE"):        # only alert on serious ones
            body = json.dumps({"text": f"limen {decision.action.name}: {'; '.join(decision.reasons)}"}).encode()
            urllib.request.urlopen(self.url, data=body, timeout=3)  # (do this off the request path in prod)

limen = Limen(store, observer=[LoggingObserver(), SlackWebhook("https://hooks.slack.com/...")])
```

## Rate-limit recipes

`rate_limit` is one class, one instance per bucket, keyed on any dimension. Register several in a custom
registry:

```python
from limen import Registry
from limen.guards.rate_limit import RateLimit, by_ip, by_account, by_path, per
reg = Registry()
reg.register(RateLimit(name="anon_ip",  key=by_ip,      limit=100, window_s=60))
reg.register(RateLimit(name="acct",     key=by_account, limit=600, window_s=3600, action=Action.TARPIT))
reg.register(RateLimit(name="checkout", key=per(by_account, by_path), limit=20, window_s=60, fail_closed=True))
limen = Limen(store, registry=reg)
```
See **`docs/recipes.md`** for more (composite keys, config-driven registries, denylists, step-up, CSRF).

## Challenge — human verification, provider-agnostic

Any guard returning `Action.CHALLENGE` (e.g. `sec_fetch`, `impossible_travel`, or your own) triggers the flow.
Pass a `Verifier` and the middleware orchestrates it: on CHALLENGE it serves 401 (unless the caller has a recent
passed-marker); the caller solves the challenge and POSTs the token to `verify_path` (default `/_limen/verify`),
which verifies it and writes a marker good for `challenge_ttl` seconds.

```python
from limen.adapters import LimenMiddleware, TurnstileVerifier
app.add_middleware(LimenMiddleware, limen=limen, verifier=TurnstileVerifier(secret="0x..."),
                   challenge_ttl=1800)
```
Three ways to use it, no limitation:
1. **No verifier** — omit it; CHALLENGE is served as 401 and your app handles it however it likes.
2. **Your own provider** — a ~5-line `Verifier` (hCaptcha, reCAPTCHA, an emailed code, an internal risk service).
3. **Turnstile** — the bundled `TurnstileVerifier` (stdlib only).

Two things to know about the flow:
- The passed-marker is keyed on the **account** when known, else the **IP**. An IP key is shared behind
  NAT/CGNAT, so one solved challenge exempts everyone on that egress IP until `challenge_ttl` — keep the TTL
  modest and prefer authenticated (per-account) challenges. The verify route is itself rate-limited
  (`verify_limit` / `verify_window_s`) so it cannot be flooded, and `Verifier.verify` runs off the event loop.
- A captcha proves "human", not "recently re-authenticated". A passed marker therefore does **not** satisfy a
  CHALLENGE raised by `reauth_guards` (default `step_up` / `impossible_travel`) — those clear only via their own
  mechanism (your app writing `limen:reauth:<account>` after a real re-auth).

## 6. (Optional) early reject at the edge — Next.js proxy

If a same-origin proxy sits in front (a Next `route.ts`), you can reject before forwarding with `@limen/proxy`.
Keep **one** engine (the backend); the edge just applies the backend's `Decision`.

```ts
import { buildContext, applyDecision } from "@limen/proxy";
const ctx = buildContext(request, { ip, account_id, auth_kind });
const decision = await askBackendLimen(ctx);   // a small internal endpoint that calls limen.evaluate
const early = applyDecision(decision);          // 403 on BLOCK, 401 on CHALLENGE, else null
if (early) return early;
```
See `examples/nextjs_proxy.md`.

---

## Per-guard tuning quick reference

| guard | keys on | key knobs (default) | default mode |
|---|---|---|---|
| `rate_limit` | whatever `key` picks | `limit`, `window_s`, `action`, `fail_closed` (False) | ENFORCE |
| `enumeration` | IP | `limit` (20), `window_s` (60), `path_prefixes` (all) | ENFORCE |
| `sequence_anomaly` | account | `dominance` (0.9), `min_requests` (20), `exempt_prefixes` (none) | SHADOW |
| `sec_fetch` | session request | `methods` (off), `allowed_origins`, `allowed_sites` | SHADOW |
| `timing` | account, else IP | `max_stdev_s` (0.5), `samples` (8) | SHADOW |
| `denylist` | account / IP | `accounts`, `ips`, `store_backed` (False) | ENFORCE |
| `honeytoken` | path | `paths` (none) | ENFORCE |
| `impossible_travel` | account | `geo` (None → off), `window_s` (3600) | SHADOW |
| `step_up` | account | `sensitive_paths` (none), `max_age_s` (300) | ENFORCE |
| `watermark` | account | `secret` (none), `digits` (16) | SHADOW |

Each guard's module docstring is the full reference (decision math, false positives, what it does not catch).

## Exempting trusted traffic (your own scanner, a partner)

High-volume traffic you *sent* (a security scanner pointed at your own site) will look hostile. `exempt`
short-circuits to ALLOW before any guard runs.

> **DANGER — an IP exempt is a total bypass, and only as trustworthy as your IP source.** `exempt` skips
> *every* guard. If `ctx.ip` comes from a spoofable header (no locked edge / unstripped `x-forwarded-for`), an
> attacker sets that header, matches your allowlist, and turns Limen off entirely — with no auth required.

So gate the exempt on **`ctx.ip_trusted`**, which `LimenMiddleware` stamps True only when you pass
`client_ip_trusted=True` (assert that ONLY behind a locked edge):

```python
TRUSTED_SCANNER_IPS = {"203.0.113.7", "203.0.113.8"}
limen = Limen(store, config={...}, exempt=lambda ctx: ctx.ip_trusted and ctx.ip in TRUSTED_SCANNER_IPS)
app.add_middleware(LimenMiddleware, limen=limen, client_ip=ClientIP(), identity=Identity(),
                   client_ip_trusted=True)  # ONLY if your edge sets the IP header and strips spoofable copies
```

## Custom registry — thresholds, path scoping, canaries

`Limen(store, config=...)` uses the default registry (each guard at its default thresholds). To set thresholds,
add rate-limit buckets, scope `enumeration`, or configure `honeytoken` canaries, build your own registry and
pass it in:

```python
from limen import Registry, Limen
from limen.guards.enumeration import Enumeration
from limen.guards.rate_limit import RateLimit, by_account
from limen.guards.honeytoken import Honeytoken

reg = Registry()
reg.register(Enumeration(window_s=60, limit=15, path_prefixes=("/api/items/", "/orders/")))
reg.register(RateLimit(name="acct", key=by_account, window_s=3600, limit=1000))
reg.register(Honeytoken(paths=("/api/items/__canary_9f3a7c__",)))   # random + unlinked

limen = Limen(store, registry=reg, config={"enumeration": Mode.ENFORCE})
# Only the guards you register run — this is opt-in.
```

## Troubleshooting

- **"My guard never fires."** No trusted IP (per-IP guards self-disable — check your `ClientIP`), the guard is
  in SHADOW (findings only in `decision.shadow_reasons` / your Observer), the store is not shared across workers
  (each counts separately — use `RedisStore`), or a parametric guard is not configured (e.g. `impossible_travel`
  with no `geo`, `honeytoken`/`step_up`/`denylist` with empty config are no-ops by design).
- **"Everything is blocked."** A `fail_closed` bucket plus a store outage denies by design — check the store.
  Or a `rate_limit` limit is too low for real traffic.
- **"Shadow findings are invisible."** You have no Observer wired — add `LoggingObserver`/`JsonlObserver` and
  set `log_relevance="all"` while tuning.
- **"CSRF flags legitimate requests."** You did not list a real front-end origin in `sec_fetch(allowed_origins=…)`,
  or the browser is not sending `Sec-Fetch-Site`/`Origin` on that route.

## New-integration checklist

- [ ] Pick a store (`MemoryStore` dev, `RedisStore` across workers).
- [ ] Write `Identity` (returns `(account_id, auth_kind)`) and `ClientIP` (returns a trusted IP or None).
- [ ] Choose guards + modes; start noisy ones in SHADOW.
- [ ] Wire an `Observer` and watch shadow findings before enforcing.
- [ ] Add the middleware; set `client_ip_trusted=True` ONLY behind a locked edge.
- [ ] Add `rate_limit` buckets for your dimensions (see `docs/recipes.md`).
- [ ] (Optional) wire a `Verifier` for challenge; mount + PROTECT `/metrics` if using `PrometheusObserver`.
- [ ] Flip guards to ENFORCE one at a time, watching the Observer.

## Where things run (summary)

| concern | where |
|---|---|
| enforcement | backend `LimenMiddleware` (has the account + trusted IP) |
| early reject | optional edge proxy (`@limen/proxy`), applies the backend Decision |
| shared counters | `RedisStore` when >1 process |
| "who / what IP" | your `Identity` / `ClientIP` ports, injected once |
| seeing decisions | `Observer` sinks (log / JSONL / metrics) + `log_relevance` |
| challenge | `Verifier` port + the middleware's verify route |
| trusted-traffic bypass | `exempt=` predicate on source IP, gated on `ctx.ip_trusted` |
```
