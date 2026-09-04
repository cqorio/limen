# Limen

> A lightweight, modular abuse-defense engine for your API. *Limen* is Latin for "threshold": it decides what
> crosses yours.

A small registry of independently toggleable **guards** (enumeration, per-account budget, sequence-anomaly, …)
run by one fast **engine**, each with an **off / shadow / enforce** mode so you can roll a defense out safely.
**Zero required dependencies** — the core is pure standard library; bring your own store (in-memory ships built
in, Redis is an optional extra).

Limen is **defense-in-depth, not a WAF replacement**. It shines *behind* your edge, where you know the account
and the request shape: catching a scraper on one account, an id-enumerator, a session behaving like a script.

## Install

```bash
pip install limen                 # core, no dependencies
pip install 'limen[redis]'        # + Redis-backed shared store
pip install 'limen[fastapi]'      # + FastAPI/Starlette middleware
```

## Quickstart

```python
from limen import Limen, RequestContext, Mode
from limen.adapters import MemoryStore

limen = Limen(MemoryStore(), config={"sequence_anomaly": Mode.SHADOW})

decision = limen.evaluate(RequestContext(
    method="GET", path="/api/reports/abc",
    ip="1.2.3.4", account_id="u1", auth_kind="session",
))
if decision.blocked:
    ...  # refuse / challenge / tarpit, per decision.action
```

## Concepts

- **Guard** — one defense. A subclass of `Guard` with a unique `name` and an `evaluate(ctx, store) -> Signal | None`.
- **Registry** — the set of guards. Add one = a module + `@register` + one test file. Nothing else changes.
- **Mode** — per guard: `OFF` (never runs), `SHADOW` (evaluated and logged, never affects the outcome),
  `ENFORCE` (can raise the decision's action). Roll new guards out in `SHADOW`, watch, then `ENFORCE`.
- **Engine** — runs the enabled guards over one `RequestContext` and reduces their signals to a `Decision`
  (the most severe `Action` wins). It **fails open**: a broken guard or a store outage is logged and skipped,
  never a lockout.
- **Ports** — the dependencies you inject (structural, no inheritance): `Store` (counters + kv), `ClientIP`
  (trusted client IP, or `None`), `Identity` (account id + auth kind). Guards keyed on IP self-disable when
  there is no trusted IP, so per-account rules keep working without a WAF in front.

**Actions**, least to most severe: `ALLOW < ALERT < TARPIT < CHALLENGE < BLOCK`.

## Bundled guards

| name | what it catches | default mode |
|---|---|---|
| `enumeration` | an IP racking up not-found responses (id/endpoint guessing) | ENFORCE |
| `account_budget` | one authenticated account pulling far more than a human would | ENFORCE |
| `sequence_anomaly` | a browser session pounding one endpoint with no page fan-out | SHADOW |
| `sec_fetch` | a cookie-session API call from a cross-site context (not your page) | SHADOW |
| `timing` | metronomic, near-constant request intervals (a bot's signature) | SHADOW |
| `honeytoken` | access to a configured canary path/id no legitimate UI surfaces | ENFORCE |
| `watermark` | passive: emits a per-account HMAC tag for leak attribution (never blocks) | SHADOW |

`account_budget` defaults to `TARPIT` (serve, but slowly); the bundled `LimenMiddleware` honours it with a
configurable `tarpit_seconds` delay. `honeytoken` and `watermark` are no-ops until you configure canary paths /
a secret, so their `ENFORCE`/`SHADOW` defaults are safe out of the box.

## Write your own guard

```python
from limen import Guard, register, Action, Mode, Signal

@register
class NoReferer(Guard):
    name = "no_referer"
    default_mode = Mode.ENFORCE
    def evaluate(self, ctx, store):
        if ctx.auth_kind == "session" and not ctx.referer:
            return Signal(Action.CHALLENGE, self.name, "session request with no referer")
        return None
```

That's it — it's now in the registry. See `examples/custom_guard.py`.

## Integration

**[docs/integration.md](docs/integration.md)** is the full walkthrough for wiring Limen into a real app
(a FastAPI backend + a Next.js proxy). The short version — four decisions:

```python
from fastapi import FastAPI
from limen import Limen, Mode
from limen.adapters import RedisStore, LimenMiddleware

class Identity:   # who is this? -> (account_id, auth_kind)
    def resolve(self, request):
        tok = read_session_cookie(request)
        return (account_id_from(tok), "session") if tok else (None, None)

class ClientIP:   # the trusted client IP, or None
    def resolve(self, request):
        return request.headers.get("cf-connecting-ip")

app = FastAPI()
limen = Limen(
    RedisStore(url="redis://localhost"),                 # 1. store (Redis for multi-worker)
    config={"enumeration": Mode.ENFORCE,                 # 4. guards + modes (shadow-first)
            "account_budget": Mode.ENFORCE,
            "sequence_anomaly": Mode.SHADOW},
    exempt=lambda ctx: ctx.ip_trusted and ctx.ip in TRUSTED_SCANNER_IPS,  # skip your own scanner
)
app.add_middleware(LimenMiddleware, limen=limen, client_ip=ClientIP(), identity=Identity(),
                   client_ip_trusted=True)  # 2 & 3 — set client_ip_trusted True ONLY behind a locked edge
```

> An IP `exempt` is a **total bypass** and only as safe as your IP source: gate it on `ctx.ip_trusted`
> (stamped by `client_ip_trusted=True`, which you set only when a locked edge provides an unspoofable IP),
> or a spoofed header turns Limen off. See [the guide](docs/integration.md#exempting-trusted-traffic-your-own-scanner-a-partner).

That's the whole integration: one middleware, two small ports (`Identity`, `ClientIP`), a store, and your guard
config. `examples/fastapi_app.py` is a runnable version.

## Adapters

- `limen.adapters.MemoryStore` — thread-safe, in-process; periodic purge bounds memory (single process / tests).
- `limen.adapters.RedisStore` — shared across workers/replicas (`limen[redis]`).
- `limen.adapters.LimenMiddleware` — FastAPI/Starlette; enforces pre-request (BLOCK→403, CHALLENGE→429, TARPIT→`tarpit_seconds` delay), observes post-response (`limen[fastapi]`).
- `@limen/proxy` (in `js/`) — Next.js/edge helper: `buildContext(request)` + `applyDecision(decision)`. See `examples/nextjs_proxy.md`.

`Limen(store, config=..., registry=..., exempt=...)`: `config` sets per-guard modes; a custom `registry` sets
thresholds / path scoping / canaries; `exempt(ctx)` short-circuits to ALLOW (gate any IP-based exempt on
`ctx.ip_trusted` — see the guide's warning).

## Design principles

Fail-open behind login · shadow-first rollout · per-account keys beat per-IP (IP trust needs a locked origin) ·
thresholds are configuration, not hardcoded · no secrets in the repo. It cannot hide a user's own data from
them (nothing client-side can) — it raises the cost of *abuse*, and makes it detectable.

## Status & license

Alpha (`0.1.0`). MIT. Contributions welcome — see `CONTRIBUTING.md`.
