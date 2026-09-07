# Changelog

All notable changes to this project are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/), and this project adheres to
[Semantic Versioning](https://semver.org/).

## [Unreleased]
### Changed
- **`Observer` is now an abstract base class** (`limen.core.observer.Observer`), not a Protocol — subclass it,
  implement `observe`, inherit `respects_relevance` / a no-op `observe_latency` / the `event()` helper. Matches
  `Guard` and `logging.Handler`. The infrastructure-wrapping ports (`Store`/`ClientIP`/`Identity`/`Verifier`/
  `Geo`) stay Protocols. Bundled sinks now subclass `Observer`.
- **`rate_limit` is no longer auto-registered** — a rate limit has no meaningful zero-config default, so you
  instantiate the buckets you want in your own registry (see docs/recipes.md). `Limen(store)` no longer ships a
  default per-account budget; add a `RateLimit(key=by_account, ...)` bucket for it.

### Added
- **`SentryObserver`** (`limen[sentry]`) — reports serious decisions (>= `min_action`) to Sentry; the Sentry
  call is behind an injectable `capture`, so it is testable without the dependency.
- A **"Write your own observer"** guide (docs/integration.md) and a public `Observer.event()` helper.
- Runnable `>>>` doctests across the non-guard modules (core, facade, memory_store, observers, sentry), so
  `pytest --doctest-modules limen` covers them.

## [1.0.0]

Completeness release: Limen is now a general, single abuse-defense chokepoint (rate limiting, challenge, risk
scoring, session hardening, allow/deny lists) with a real observability story — and no product-specific
assumptions in the core.

### Added
- **`rate_limit`** — one generic fixed-window guard, instantiated per bucket, keyed on any dimension
  (`by_ip` / `by_account` / `by_path` / `global_` / composite `per(...)`). Subsumes bespoke per-dimension
  limiters.
- **`denylist`** (block accounts/IPs, static or store-backed), **`impossible_travel`** (region change in a short
  window, via an injected `Geo` port), **`step_up`** (sensitive paths require a recent re-auth marker).
- **CSRF** in `sec_fetch`: a `methods=` set makes state-changing requests require positive same-origin proof
  (`Sec-Fetch-Site` or `Origin`/`Referer` vs `allowed_origins`), acting on an absent header. New
  `RequestContext.origin` field.
- **Per-guard `fail_closed`** — a guard can deny (its `action`) on a store/guard error instead of failing open;
  mode-aware (ENFORCE only; a SHADOW fail-closed is recorded, never enforced). Default stays fail-OPEN.
- **Score-threshold aggregation** — `EngineConfig(score_thresholds=...)` combines weak ENFORCE-mode signals into
  a graduated action.
- **Observability**: `Observer` port + `LoggingObserver` / `JsonlObserver` (zero-dep) + `PrometheusObserver`
  (`limen[prometheus]`, counts every action incl. `allow` for "% blocked"). A single global `log_relevance`
  switch governs the log sinks; metrics ignore it. `import limen; limen.enable_logging()` for opt-in
  operational logs (the library is silent by default via a `NullHandler`).
- **Challenge subsystem**: `Verifier` port + bundled `TurnstileVerifier` (stdlib `urllib`); the FastAPI
  middleware orchestrates serve → verify → passed-marker. No captcha vendor is required.
- `docs/recipes.md`; a substantially expanded `docs/integration.md`; `examples/observability.py`.

### Changed
- **Removed the `account_budget` guard** — it is `rate_limit(key=by_account, action=TARPIT)`; the bundled
  default `rate_limit` reproduces its behavior.
- **Renamed the facade's post-response `observe()` to `record()`** (it never fired observers; the rename removes
  the collision with the new `Observer.observe`). The middleware and examples updated.
- `sequence_anomaly.exempt_prefixes` now defaults to empty — configure it for your app (no built-in paths).

## [0.1.0] - 2026-09-04

### Added
- Framework-agnostic core: `Guard` (ABC) + `Registry` + `@register`, an `Engine` that aggregates guard
  signals into a `Decision`, frozen value objects (`RequestContext`, `Signal`, `Decision`, `Mode`, `Action`),
  and structural `Store` / `ClientIP` / `Identity` ports.
- Per-guard `off` / `shadow` / `enforce` modes; the engine fails open.
- Seven guards, all implemented: `enumeration`, `account_budget`, `sequence_anomaly`, `sec_fetch`, `timing`,
  `honeytoken`, `watermark` — each with its own test file.
- `RedisStore` sets a TTL on the first hit without `EXPIRE NX`, so it works on every Redis version and never
  leaves an un-expiring key. `MemoryStore` periodically sweeps expired keys, bounding memory to live keys.
  `LimenMiddleware` honours the `TARPIT` action (configurable `tarpit_seconds`). The engine fails open even
  when a guard violates the `Signal | None` contract.
- Adapters: `MemoryStore` (built in), `RedisStore` (`limen[redis]`), `LimenMiddleware` (`limen[fastapi]`),
  and a `@limen/proxy` JS/TS edge helper.
- The `Limen` facade, docs, and runnable examples.
