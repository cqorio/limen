// Mirrors limen.core.types on the Python side. `Action` is a const object (not a TS `enum`) so the file is
// strippable by `node --experimental-strip-types` (enums need codegen; const objects don't).

export const Action = {
  ALLOW: 0,
  ALERT: 1,
  TARPIT: 2,
  CHALLENGE: 3,
  BLOCK: 4,
} as const;
export type Action = (typeof Action)[keyof typeof Action];

export interface RequestContext {
  method: string;
  path: string;
  status?: number | null;
  sec_fetch_site?: string | null;
  sec_fetch_mode?: string | null;
  ip?: string | null;
  account_id?: string | null;
  auth_kind?: string | null;
  referer?: string | null;
}

export interface Decision {
  action: Action;
  score: number;
  reasons: string[];
  shadow_reasons: string[];
}

export function isBlocked(d: Decision): boolean {
  return d.action >= Action.TARPIT;
}
