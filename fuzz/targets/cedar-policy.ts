// Fuzz target: cedarPolicyToTuples (src/adapters/ibac-cedar.ts).
// Historical finding: the original "when { ... }" constraint parser used a
// single combined regex (\w+ / \s* / alternation / \S+) vulnerable to
// catastrophic backtracking, empirically 16.7s on a 200KB adversarial
// input. Fixed with a linear indexOf-based operator scan. This function
// never throws by design (unparseable lines are silently skipped), so ANY
// throw here is itself a finding, not just a hang.
import { cedarPolicyToTuples } from "../../src/adapters/ibac-cedar.js";

export function fuzz(data: Buffer): void {
  const policy = data.toString("utf8");
  // No try/catch: cedarPolicyToTuples is documented (by its own
  // implementation, confirmed by reading the full function) to never
  // throw, only to skip lines it cannot parse. An uncaught throw here is
  // therefore always a genuine regression, and a hang is caught by
  // Jazzer's own per-input timeout.
  cedarPolicyToTuples(policy);
}
