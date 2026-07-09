// Fuzz target: canonicalizeJCS (src/core/canonical-jcs.ts), the RFC 8785
// implementation. Same byte-exactness rationale as canonicalize.ts: this
// is the strict RFC 8785 path new signatures use, so any divergence from
// a pure function of its input (nondeterminism) or a crash/hang on a
// value that came from valid JSON text is a real finding. The documented
// throw ("JCS does not support Infinity or NaN") can never fire on
// JSON.parse output either, since JSON text cannot represent Infinity or
// NaN literals.
import { canonicalizeJCS } from "../../src/core/canonical-jcs.js";

export function fuzz(data: Buffer): void {
  const text = data.toString("utf8");

  let value: unknown;
  try {
    value = JSON.parse(text);
  } catch {
    return;
  }

  const first = canonicalizeJCS(value);
  const second = canonicalizeJCS(value);
  if (first !== second) {
    throw new Error(
      "canonicalizeJCS() is non-deterministic: two calls on the same JSON-derived value produced different output",
    );
  }
}
