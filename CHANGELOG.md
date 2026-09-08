# Changelog

All notable changes to this project are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/), and this project adheres to
[Semantic Versioning](https://semver.org/).

## [Unreleased]

## [1.2.0] - 2026-09-08

A dedicated **throttle** action so a tripped rate limit maps to `429 Too Many Requests` (with `Retry-After`)
instead of `403 Forbidden`, matching the near-universal HTTP rate-limit contract. Closes #5.

### Added
- **`Action.THROTTLE`** — a retryable rejection ("the caller is going too fast"), ordered between `CHALLENGE`
  and `BLOCK` so a hard `BLOCK` (e.g. a denylist) still wins when both fire.
- **`LimenMiddleware`** serves `THROTTLE` as `429` with a `Retry-After` header; new `retry_after` constructor
  argument (default 60s). `BLOCK` → `403` and `CHALLENGE` → `401` are unchanged. The `@limen/proxy` JS
  `applyDecision` mirrors the same mapping.

### Changed
- **`RateLimit` now defaults to `Action.THROTTLE`** (was `BLOCK`), so a rate-limit bucket returns `429` out of
  the box. Pass `action=Action.BLOCK` to keep the old `403` behaviour for a given bucket.
- `Action.BLOCK` is now the integer `5` (was `4`) because `THROTTLE` takes `4`. Compare by name (`Action.BLOCK`),
  never by the raw int; nothing in the library compares the numeric value.

## [1.1.0] - 2026-09-08

Native **async** support, so Limen runs in async apps (FastAPI on `redis.asyncio`) without blocking the event
loop. Additive and fully backward-compatible — the sync v1.0 API is unchanged.

### Added
- **`AsyncStore`** port (async `incr`/`get`/`set_str`/`get_str`) plus two adapters: **`AsyncRedisStore`**
  (`redis.asyncio`) and **`AsyncMemoryStore`** (in-process, zero-infra — used by the async doctests/tests).
- **`Guard.evaluate_async`**, **`Engine.evaluate_async`**, and **`Limen.evaluate_async` / `record_async`** — an
  awaiting evaluation path. Base `Guard.evaluate_async` **raises** rather than delegating to sync: a store-backed
  guard that forgets its async body is loud, never a silent fail-open (an unawaited coroutine is truthy). Every
  bundled guard implements it (store-backed ones await; pure-compute ones delegate).
- **`LimenMiddleware`** awaits the async engine and the challenge/verify store markers when constructed with an
  async store, and awaits `client_ip` / `identity` ports that are async — so an async account lookup works.

### Fixed
- **`RedisStore.incr` is now atomic** — one Lua `INCR`+`EXPIRE` script instead of two calls, closing the
  orphaned-TTL window where a crash between them could lock a bucket forever. Benefits sync users too.

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
