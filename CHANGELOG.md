# Changelog

All notable changes to this project are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/), and this project adheres to
[Semantic Versioning](https://semver.org/).

## [Unreleased]

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
