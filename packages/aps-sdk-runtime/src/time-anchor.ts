/**
 * Gateway time anchor poll client — Prototype 1 scaffold.
 *
 * The real client polls the gateway time-anchor endpoint, verifies
 * the signed anchor against the gateway's published key, and exposes
 * a monotonically-non-decreasing anchor to the verifier. Stub only.
 */

function todo(): never {
  throw new Error("not implemented (Prototype 1 scaffold)");
}

export interface TimeAnchorOptions {
  readonly endpoint: string;
  readonly pollIntervalMs: number;
}

export interface TimeAnchor {
  readonly anchor: string;
  readonly signature: string;
  readonly fetchedAt: string;
}

export async function startTimeAnchor(
  _options: TimeAnchorOptions,
): Promise<TimeAnchor> {
  return todo();
}

export async function currentAnchor(): Promise<TimeAnchor> {
  return todo();
}
