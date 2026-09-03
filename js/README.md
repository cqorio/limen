# @limen/proxy

The edge / Next.js adapter for [Limen](../README.md). The guard engine runs in your Python backend; this
package is the thin wiring at the boundary: build a `RequestContext` from an incoming request, and turn a
`Decision` (from the Python core) into an early `Response`.

```ts
import { buildContext, applyDecision } from "@limen/proxy";

const ctx = buildContext(request, { ip, account_id, auth_kind });
const decision = await askLimen(ctx);        // your call to the Python engine
const early = applyDecision(decision);       // 403 on BLOCK, 429 on CHALLENGE, else null
if (early) return early;
```

Zero dependencies. Test: `node --experimental-strip-types test/proxyGuard.test.ts`.
