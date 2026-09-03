# Contributing to Limen

Thanks for helping. Limen stays small and predictable on purpose — a new defense should be a self-contained
module, not a change to the engine.

## Add a guard

1. Create `limen/guards/<name>.py` with a `Guard` subclass: a unique `name`, a `default_mode` (use
   `Mode.SHADOW` for anything that could false-positive), and an `evaluate(ctx, store) -> Signal | None`.
   Decorate it with `@register`. All state lives in the injected `store` — guards stay stateless and cheap.
2. Import it in `limen/guards/__init__.py`.
3. Add `tests/guards/test_<name>.py`. This is required: `tests/test_registry.py` fails if a registered guard
   has no test file.

Keep thresholds as `__init__` arguments with sane defaults (configuration, not hardcoded), and keep `evaluate`
total — never raise on the normal path (the engine fails open, so a raising guard is silently disabled).

## Run the checks

```bash
python -m pytest                                   # Python core + guards
cd js && node --experimental-strip-types test/proxyGuard.test.ts   # the edge adapter
```

## Principles (please preserve)

Fail-open behind login · shadow-first rollout · per-account keys over per-IP · zero required deps in the core
(new runtime deps go behind an optional extra) · no secrets in the repo.
