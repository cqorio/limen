# Changelog

All notable changes to this project are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/), and this project adheres to
[Semantic Versioning](https://semver.org/).

## [Unreleased]

## [1.0.0] - 2026-09-07

First stable release: a general, single abuse-defense chokepoint (rate limiting, challenge, risk scoring,
session hardening, allow/deny lists) with a real observability story, and no product-specific assumptions in
the core. Licensed under Apache-2.0.

### Guards
- **`rate_limit`** — one generic fixed-window guard, instantiated per bucket, keyed on any dimension
  (`by_ip` / `by_account` / `by_path` / `global_` / composite `per(...)`). NOT auto-registered: it has no
  meaningful zero-config default, so you add the buckets you want to your own registry. Replaces the old
  `account_budget` guard.
- **`denylist`** (block accounts/IPs, static or store-backed), **`impossible_travel`** (region change in a short
  window via an injected `Geo` port), **`step_up`** (sensitive paths require a recent re-auth marker).
- **CSRF** in `sec_fetch`: a `methods=` set makes state-changing requests require positive same-origin proof
  (`Sec-Fetch-Site`, or `Origin`/`Referer` vs `allowed_origins`), acting on an absent header. New
  `RequestContext.origin` field.
- `sequence_anomaly.exempt_prefixes` defaults to empty (no built-in paths; configure per app).

### Engine
- **Per-guard `fail_closed`** — deny (the guard's `action`) on a store/guard error instead of failing open;
  mode-aware (ENFORCE only; a SHADOW fail-closed is recorded, never enforced). Default stays fail-OPEN.
- **Score-threshold aggregation** — `EngineConfig(score_thresholds=...)` combines weak ENFORCE-mode signals into
  a graduated action.

### Observability
- **`Observer` is an abstract base class** (like `Guard` and `logging.Handler`): subclass it, implement
  `observe`, reuse the `event()` helper. Bundled sinks: `LoggingObserver`, `JsonlObserver` (zero-dep),
  `PrometheusObserver` (`limen[prometheus]`, counts every action incl. `allow` for "% blocked"), and
  `SentryObserver` (`limen[sentry]`). A single global `log_relevance` switch governs the log sinks; a metrics
  sink ignores it.
- Operational logging is silent by default (`NullHandler`); `import limen; limen.enable_logging()` opts in.

### Challenge
- Provider-agnostic `Verifier` port + bundled `TurnstileVerifier` (stdlib `urllib`); the FastAPI middleware
  orchestrates serve → verify → passed-marker (with a rate-limited verify route). No captcha vendor is required.

### Docs, tests & packaging
- Rewritten README, `docs/recipes.md`, expanded `docs/integration.md` (incl. "write your own observer"),
  `CLAUDE.md` conventions, `examples/observability.py`. Runnable `>>>` doctests across the modules.
- Core stays zero-dependency; `redis` / `fastapi` / `prometheus` / `sentry` are optional extras.

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
