// The thin edge counterpart: at a Next.js / edge proxy, build a Limen RequestContext from the incoming
// request and turn a Decision (computed by the Python core, e.g. over an internal call) into an early
// Response. The guard logic itself lives in the Python engine; this is the wiring at the boundary.

import { Action, type Decision, type RequestContext } from "./types.ts";

// `ip` / `account_id` / `auth_kind` come from your reverse proxy + session and are passed in `extra` —
// a Request alone cannot resolve them safely.
export function buildContext(request: Request, extra: Partial<RequestContext> = {}): RequestContext {
  const url = new URL(request.url);
  return {
    method: request.method,
    path: url.pathname,
    sec_fetch_site: request.headers.get("sec-fetch-site"),
    sec_fetch_mode: request.headers.get("sec-fetch-mode"),
    referer: request.headers.get("referer"),
    ...extra,
  };
}

// Returns an early Response to short-circuit the request, or null to let it proceed. TARPIT proceeds here
// (add latency yourself if you want it); ALERT proceeds (it is a flag, not a block).
export function applyDecision(d: Decision): Response | null {
  if (d.action >= Action.BLOCK) return new Response("Forbidden", { status: 403 });
  if (d.action === Action.CHALLENGE) return new Response("Verification required", { status: 429 });
  return null;
}
