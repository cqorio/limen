# Project: Limen — a modular abuse-defense engine

Limen guards the *threshold* of an API: a registry of small, independently toggleable **guards**
(enumeration, per-account budget, sequence-anomaly, …) run by one fast **engine**, each with an
`off | shadow | enforce` mode. It is an **open-source library** — lightweight, fast, intuitive,
well-documented. Defense-in-depth *behind* the edge, NOT a WAF replacement.

## Architecture (the whole thing)
- `limen/core/` — framework-agnostic core. `types.py` (frozen value objects + `Mode`/`Action` enums),
  `ports.py` (`Store`/`ClientIP`/`Identity` Protocols — injected deps), `guard.py` (`Guard(ABC)` +
  `Registry` + `@register`), `engine.py` (`Engine`: run enabled guards → aggregate → `Decision`, fail-open),
  `config.py` (`EngineConfig`). `facade.py` is the `Limen` entry point.
- `limen/guards/` — ONE module per defense, each a `Guard` subclass with `@register`. Adding a guard touches
  only: its module + one line in `guards/__init__.py` + `tests/guards/test_<name>.py`.
- `limen/adapters/` — `MemoryStore` (built in), `RedisStore` (`[redis]`), `LimenMiddleware` (`[fastapi]`).
- `js/` — `@limen/proxy`, the thin Next.js/edge TS adapter.

## Non-negotiables (a review-blocker to break any of these)
1. **Zero required deps in the core.** stdlib only; any runtime dep goes behind an optional extra.
2. **Fail-open behind login.** A broken guard or a store outage must never lock out a user — the engine
   catches and skips. A guard's `evaluate` must be total (never raise on the normal path).
3. **Shadow-first.** Anything that can false-positive ships `default_mode = Mode.SHADOW`.
4. **Per-account keys beat per-IP.** IP trust needs a locked origin; guards keyed on IP self-disable when
   `ClientIP` yields `None`.
5. **Thresholds are configuration**, not hardcoded in the engine — guards take `__init__` args with defaults.
6. **Every registered guard has `tests/guards/test_<name>.py`** (`tests/test_registry.py` enforces it).
7. **No secrets in the repo.**

## Dev workflow — use these
- **graphify**: `graphify query "<question>"` before browsing; `graphify update .` after changing code.
- **ponytail** (always on): climb the ladder, shortest diff that works. `/ponytail-review` on the diff before commit.
- **devil's-advocate**: the Stop hook reviews completed work; clear `[CRITICAL]`/`[HIGH]` before the turn ends.
- **Tests**: `python -m pytest` (core) and `cd js && node --experimental-strip-types test/proxyGuard.test.ts`.

## Definition of done
Guard changes: stateless, thresholds as args, `evaluate` total, its own test file, shadow if risky.
Before commit: tests green both sides; `/ponytail-review`; devil's-advocate `[CRITICAL]`/`[HIGH]` cleared;
`graphify update .`.
