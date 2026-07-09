// Fuzz target: didWebToUrl (src/core/did-interop.ts).
// This is the pure, synchronous string-parsing half of the did:web
// pipeline; resolveDIDWeb (the async half) is deliberately NOT fuzzed
// directly (see fuzz/README.md): it performs a real outbound network
// fetch after this parsing step, which makes it unsuitable for a
// coverage-guided fuzz loop (unbounded, non-hermetic, and the fetch
// target itself is what the earlier SSRF fix (assertSafeDidWebTarget)
// already guards; that is a network-boundary property, not a parsing
// one). didWebToUrl itself throws plain Error instances by design on
// malformed did:web strings ("must include a domain", "Invalid did:web
// format", etc., confirmed by reading the full function) -- that is
// expected rejection behavior, not a finding. Anything else (a hang, a
// non-Error throw, a Jazzer bug-detector trigger) is a real finding.
import { didWebToUrl } from "../../src/core/did-interop.js";

export function fuzz(data: Buffer): void {
  const didWeb = data.toString("utf8");
  try {
    didWebToUrl(didWeb);
  } catch (e) {
    if (!(e instanceof Error)) throw e;
  }
}
