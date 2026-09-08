# Project: Limen — a modular abuse-defense engine

Limen guards the *threshold* of an API: a registry of small, independently toggleable **guards** (rate_limit,
enumeration, sec_fetch, impossible_travel, …) run by one fast **engine**, each with an `off | shadow | enforce`
mode. It is an **open-source library** — lightweight, fast, intuitive, well-documented. Defense-in-depth
*behind* the edge, NOT a WAF replacement.

## Architecture (the whole thing)
- `limen/core/` — framework-agnostic core. `types.py` (frozen value objects + `Mode`/`Action` enums),
  `ports.py` (`Store`/`ClientIP`/`Identity`/`Verifier`/`Geo` **Protocols** — injected deps you wrap),
  `guard.py` (`Guard(ABC)` + `Registry` + `@register`), `observer.py` (`Observer(ABC)` — the decision-sink base),
  `engine.py` (`Engine`: run enabled guards → aggregate → `Decision`; fail-open; optional score thresholds),
  `config.py` (`EngineConfig`). `facade.py` is the `Limen` entry point.
- `limen/guards/` — ONE module per defense, each a `Guard` subclass. The 10 bundled: `enumeration`,
  `sequence_anomaly`, `sec_fetch`, `timing`, `honeytoken`, `watermark`, `denylist`, `impossible_travel`,
  `step_up`, and the class `rate_limit` (NOT auto-registered — see decision 4).
- `limen/adapters/` — `MemoryStore` (built in), `RedisStore` (`[redis]`), `LimenMiddleware` (`[fastapi]`),
  observers `LoggingObserver`/`JsonlObserver` (built in) · `ReputationObserver` (built in: per-caller risk
  accumulation → auto-ban) · `PrometheusObserver` (`[prometheus]`) · `SentryObserver` (`[sentry]`), and
  `TurnstileVerifier` (stdlib).
- `js/` — `@limen/proxy`, the thin Next.js/edge TS adapter.

## Adding a guard (inherit these)
A `Guard(ABC)` subclass, STATELESS (all state in the injected `Store`), `evaluate(ctx, store) -> Signal | None`
that is TOTAL (never raise on the normal path), handling ONE phase (`ctx.is_pre_request` enforce / status-set
observe). **If it touches the `Store`, ALSO implement `async def evaluate_async(ctx, store)` awaiting the ASYNC
store** (mirror `evaluate` exactly); the base `evaluate_async` RAISES rather than delegating to sync, so a
store-backed guard that omits it fails OPEN under the async engine (an unawaited coroutine is truthy). A
pure-compute guard (no store access) may `return self.evaluate(ctx, store)`. Thresholds are `__init__` args with
defaults. IP-keyed guards self-disable when `ctx.ip` is None.
`default_mode = SHADOW` if it can false-positive. A single-action guard sets `action`; `fail_closed` is opt-in.
Ship a full **8-part docstring** (threat · what & why · decision math · runnable `>>>` example · tuning · false
positives · what it does NOT catch · store keys & cost) using GENERAL paths, and `tests/guards/test_<name>.py`.
Register with `@register` ONLY if it has a safe inert/active zero-config default; otherwise leave it parametric.

## Adding an observer (inherit these)
Subclass `Observer(ABC)`, implement `observe(ctx, decision)`, reuse `self.event(...)`. Set `respects_relevance`
(False ONLY for a metrics/always-on sink) and override `observe_latency` only if you record it. **If it touches
an async `Store`, ALSO implement `async def observe_async(ctx, decision)` awaiting it** — the base
`observe_async` delegates to sync `observe`, so a store-backed sink that omits it blocks the event loop on the
`evaluate_async` path (mirrors the guard `evaluate`/`evaluate_async` split). Cheap, never raises, never logs
secret values. A heavy dep goes behind an extra and is lazy-imported (raise a clear error on construct without
it); ship its own test (inject a fake so it needs no dependency).

## Non-negotiables (a review-blocker to break any of these)
1. **Zero required deps in the core.** stdlib only; any runtime dep goes behind an optional extra.
2. **Fail-open behind login.** A broken guard or store outage must never lock out a user — the engine catches
   and skips. `evaluate` must be total. `fail_closed` is opt-in per guard and mode-aware (ENFORCE denies, SHADOW
   records); the default is fail-OPEN.
3. **Shadow-first.** Anything that can false-positive ships `default_mode = Mode.SHADOW`.
4. **Per-account keys beat per-IP.** IP trust needs a locked origin; IP-keyed guards self-disable when
   `ClientIP` yields `None`.
5. **Thresholds are configuration**, not hardcoded — guards take `__init__` args with defaults.
6. **General, not opinionated.** No product paths/headers/tenant assumptions in `limen/`; exemptions default
   empty; product terms live only in examples/recipes.
7. **Every registered guard has `tests/guards/test_<name>.py`** (`tests/test_registry.py` enforces it).
8. **Every `limen/**/*.py` has a stdlib-grade module docstring that teaches + a usage example** — a runnable
   `>>>` doctest where it needs no external infra, an illustrative code block otherwise. Model on `ports.py`.
9. **No secrets in the repo.**

## Design decisions (the why, one line each)
1. **ABC vs Protocol** — ABC for what you AUTHOR for Limen with shared behavior (`Guard`, `Observer`); Protocol
   for adapters wrapping what you already own (`Store`, `ClientIP`, `Identity`, `Verifier`, `Geo`).
2. **Two registries** — the default `REGISTRY` (zero-config starter set, used by `Limen(store)`) vs a custom
   `Registry` the consumer passes (`registry=`), which replaces it. Real multi-bucket consumers build their own.
3. **Aggregation** — actions by `max` (ALLOW<ALERT<TARPIT<CHALLENGE<THROTTLE<BLOCK; THROTTLE→429, BLOCK→403 at
   the FastAPI edge); optional `score_thresholds` combine
   weak ENFORCE scores; SHADOW never changes the action.
4. **Parametric guards are NOT auto-registered** — `rate_limit` has no meaningful inert default, so it ships the
   class + key builders and is instantiated per-bucket by the consumer; only guards with a safe zero-config
   default `@register`.
5. **Two observability layers** — A: stdlib logs (NullHandler → silent by default; never `basicConfig`/add a
   handler in library code; routine BLOCK is INFO, Limen's own faults WARNING; `enable_logging()` opt-in). B: the
   `Observer` decision stream + the global `log_relevance` switch (metrics sinks ignore it and count every action
   incl. allow, the denominator for "% blocked").
6. **Challenge is provider-agnostic** — a `Verifier` port; Turnstile is one bundled adapter; the verify route is
   rate-limited and runs the verifier off the event loop; a captcha marker never satisfies a re-auth (`step_up`)
   challenge.

## Dev workflow
- **Install for dev** (`dev` pulls in every optional extra, so the whole suite runs, nothing skipped):
  `pip install -e '.[dev]'`.
- **Tests**: `python -m pytest` and `python -m pytest --doctest-modules limen` — the doctests in every module
  are the runnable usage examples. JS edge adapter: `cd js && node --experimental-strip-types test/proxyGuard.test.ts`.

## Definition of done
Guard changes: stateless, thresholds as args, `evaluate` total, 8-part docstring with a doctest, its own test
file, shadow if risky. Observer changes: subclass `Observer`, its own test. Every module: docstring + example
(decision 8). Before opening a PR: `python -m pytest`, `python -m pytest --doctest-modules limen`, and the JS
test all green (CI enforces this across Python 3.10–3.13).
