// Run: node --experimental-strip-types test/proxyGuard.test.ts
import assert from "node:assert";
import { applyDecision, buildContext } from "../src/proxyGuard.ts";
import { Action, type Decision } from "../src/types.ts";

let n = 0;
const t = (name: string, fn: () => void) => { fn(); n++; console.log("  ok", name); };
const decision = (action: Action): Decision => ({ action, score: 0, reasons: [], shadow_reasons: [] });

t("buildContext extracts method/path/sec-fetch and merges extras", () => {
  const req = new Request("https://x.test/api/me?a=1", { headers: { "sec-fetch-site": "same-origin" } });
  const ctx = buildContext(req, { ip: "1.2.3.4", account_id: "u1", auth_kind: "session" });
  assert.equal(ctx.method, "GET");
  assert.equal(ctx.path, "/api/me");
  assert.equal(ctx.sec_fetch_site, "same-origin");
  assert.equal(ctx.ip, "1.2.3.4");
  assert.equal(ctx.account_id, "u1");
});

t("applyDecision: ALLOW/ALERT proceed (null)", () => {
  assert.equal(applyDecision(decision(Action.ALLOW)), null);
  assert.equal(applyDecision(decision(Action.ALERT)), null);
});

t("applyDecision: BLOCK -> 403, THROTTLE -> 429, CHALLENGE -> 401", () => {
  assert.equal(applyDecision(decision(Action.BLOCK))?.status, 403);
  assert.equal(applyDecision(decision(Action.THROTTLE))?.status, 429);
  assert.equal(applyDecision(decision(Action.CHALLENGE))?.status, 401);
});

console.log(`proxyGuard: ${n} passed`);
