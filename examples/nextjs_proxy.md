# Next.js / edge proxy adapter

The guard logic runs in your Python backend (the `limen` engine). At the edge — a Next.js `route.ts` proxy or
a middleware — use `@limen/proxy` to build the request context and to turn a `Decision` into an early response.

```ts
import { buildContext, applyDecision } from "@limen/proxy";

export async function proxy(request: Request) {
  // Resolve ip / account / auth_kind from your reverse proxy + session, then:
  const ctx = buildContext(request, { ip, account_id, auth_kind });

  // Ask the Python Limen service for a decision (an internal endpoint you expose over your backend):
  const decision = await fetch("http://backend/_limen/evaluate", {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify(ctx),
  }).then((r) => r.json());

  const early = applyDecision(decision); // 403 on BLOCK, 401 on CHALLENGE, else null
  if (early) return early;

  return forwardToBackend(request);
}
```

`applyDecision` returns `null` for `ALLOW`/`ALERT`/`TARPIT` (let the request proceed; add latency yourself for
tarpit). Keeping the engine in one place (Python) means one set of guards and thresholds, not two.
