# Limen

> A lightweight, modular abuse-defense engine for your API. *Limen* is Latin for "threshold": it decides what
> crosses yours.

A small registry of independently toggleable **guards** (rate limiting, enumeration, CSRF, impossible-travel, …)
run by one fast **engine**, each with an **off / shadow / enforce** mode so you can roll a defense out safely.
**Zero required dependencies** — the core is pure standard library; bring your own store (in-memory ships built
in, Redis is an optional extra).

Limen is **defense-in-depth, not a WAF replacement**. It shines *behind* your edge, where you know the account
and the request shape: catching a scraper on one account, an id-enumerator, a session behaving like a script,
a cross-site write, a stolen session hopping continents.

## Install

```bash
pip install limen                      # core, no dependencies
pip install 'limen[redis]'             # + Redis-backed shared store
pip install 'limen[fastapi]'           # + FastAPI/Starlette middleware
pip install 'limen[prometheus]'        # + a Prometheus metrics sink
pip install 'limen[redis,fastapi]'     # extras stack
```

## Quickstart

```python
from limen import Limen, RequestContext, Mode
from limen.adapters import MemoryStore, LoggingObserver

limen = Limen(MemoryStore(),
              config={"sequence_anomaly": Mode.SHADOW},
              observer=LoggingObserver())     # see what it decides

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
  (the most severe `Action` wins; optional score thresholds combine weak signals). It **fails open** by
  default: a broken guard or a store outage is logged and skipped, never a lockout. A guard can opt into
  `fail_closed` to deny instead (per-guard, ENFORCE-only).
- **Ports** — the dependencies you inject (structural, no inheritance): `Store` (counters + kv), `ClientIP`,
  `Identity`, plus `Observer` (decision sink), `Verifier` (challenge), `Geo` (region lookup). Guards keyed on
  IP self-disable when there is no trusted IP, so per-account rules keep working without a WAF in front.

**Actions**, least to most severe: `ALLOW < ALERT < TARPIT < CHALLENGE < BLOCK`.

## Bundled guards

| name | what it catches | default mode |
|---|---|---|
| `rate_limit` | too many requests from one caller — key it on IP / account / endpoint / global / composite | ENFORCE |
| `enumeration` | an IP racking up not-found responses (id/endpoint guessing) | ENFORCE |
| `sequence_anomaly` | a browser session pounding one endpoint with no page fan-out | SHADOW |
| `sec_fetch` | a cross-site cookie-session call; with `methods=` also a CSRF guard on writes | SHADOW |
| `timing` | metronomic, near-constant request intervals (a bot's signature) | SHADOW |
| `denylist` | accounts or IPs you have already judged bad (static or store-backed) | ENFORCE |
| `honeytoken` | access to a configured canary path/id no legitimate UI surfaces | ENFORCE |
| `impossible_travel` | one account seen from two regions too fast (needs a `Geo` port) | SHADOW |
| `step_up` | sensitive paths require a recent re-auth marker | ENFORCE |
| `watermark` | passive: emits a per-account HMAC tag for leak attribution (never blocks) | SHADOW |

`rate_limit`'s bundled default is a per-account request budget served slowly (TARPIT). `denylist`, `honeytoken`,
`impossible_travel`, `step_up` are no-ops until you configure them, so their ENFORCE defaults are safe out of the
box. Every guard's module docstring is a full reference (what it detects, the decision math, a runnable example,
tuning, false positives, and what it does NOT catch).

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

## Seeing what it does (observability)

Two layers, kept separate (see `docs/integration.md`):

- **Operational logs** — is the engine healthy? Standard-library logging, **silent by default**. `import limen;
  limen.enable_logging()` turns it on for dev.
- **The decision stream** — what did it decide, and why? Pass one or more `Observer` sinks:

```python
from limen.adapters import LoggingObserver, JsonlObserver, PrometheusObserver
limen = Limen(store, observer=[LoggingObserver(), JsonlObserver("limen-audit.jsonl")],
              log_relevance="relevant_only")   # skip the ALLOW noise in the logs
```

`log_relevance` is one global switch for the LOG sinks (`"relevant_only"` default / `"all"` / `"off"`). A
`PrometheusObserver` ignores it and counts **every** action including `allow`, so a dashboard can graph "%
blocked". You mount and protect the `/metrics` endpoint yourself. See `examples/observability.py`.

## Challenge (human verification), provider-agnostic

A `CHALLENGE` decision can be satisfied by any `Verifier` — Cloudflare Turnstile ships as one bundled adapter,
your own provider is ~5 lines, or wire none and handle `CHALLENGE` yourself. The FastAPI middleware orchestrates
the serve → verify → passed-marker flow:

```python
from limen.adapters import LimenMiddleware, TurnstileVerifier
app.add_middleware(LimenMiddleware, limen=limen, verifier=TurnstileVerifier(secret="0x..."))
```

## Integration

**[docs/integration.md](docs/integration.md)** is the full walkthrough (a FastAPI backend + a Next.js proxy):
the four ports, shadow-first rollout with the Observer, rate-limit recipes, the challenge flow, and
troubleshooting. **[docs/recipes.md](docs/recipes.md)** shows how to express common needs with the primitives.

## Adapters

- `MemoryStore` — thread-safe, in-process; periodic purge bounds memory (single process / tests).
- `RedisStore` — shared across workers/replicas (`limen[redis]`).
- `LimenMiddleware` — FastAPI/Starlette; enforces pre-request, records post-response, orchestrates challenge (`limen[fastapi]`).
- `LoggingObserver` / `JsonlObserver` — decision sinks (zero-dep). `PrometheusObserver` — metrics (`limen[prometheus]`).
- `TurnstileVerifier` — a bundled `Verifier` (stdlib `urllib`, no extra).
- `@limen/proxy` (in `js/`) — Next.js/edge helper: `buildContext(request)` + `applyDecision(decision)`.

## Design principles

Fail-open behind login (opt-in `fail_closed` per guard) · shadow-first rollout · per-account keys beat per-IP
(IP trust needs a locked origin) · thresholds are configuration, not hardcoded · no framescan-isms, no product
assumptions in the core · no secrets in the repo. It cannot hide a user's own data from them (nothing
client-side can) — it raises the cost of *abuse*, and makes it detectable.

## Status & license

`1.0.0`. MIT. Contributions welcome — see `CONTRIBUTING.md`.
