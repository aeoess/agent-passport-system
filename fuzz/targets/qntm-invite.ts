// Copyright (c) 2026 Tymofii Pidlisnyi
// SPDX-License-Identifier: Apache-2.0
// Fuzz target: decodeQntmInvite (src/interop/qntm-bridge.ts).
// Exercises cborDecodeMap indirectly (it is module-private, not exported);
// decodeQntmInvite is the real exported entry point that feeds attacker/
// remote-peer-controlled bytes into it. Historical finding: a CBOR map key
// of "__proto__" reassigned the decoded object's prototype (fixed via
// Object.create(null) plus an explicit key denylist). This harness treats
// prototype pollution as a first-class finding, not just crashes/hangs.
import { decodeQntmInvite } from "../../src/interop/qntm-bridge.js";

// Baseline snapshot of Object.prototype's own property names, taken once
// before any fuzz input is processed. The real invariant under test is
// "decoding untrusted CBOR never adds an own property to Object.prototype",
// checked generically (not against one hardcoded key name), so this catches
// pollution via "__proto__", "constructor.prototype", or any other vector,
// not just the specific key this function was originally found vulnerable
// through.
const PROTOTYPE_BASELINE = new Set(Object.getOwnPropertyNames(Object.prototype));

export function fuzz(data: Buffer): void {
  const token = data.toString("utf8");

  try {
    decodeQntmInvite(token);
  } catch (e) {
    // decodeQntmInvite has no documented validation-error contract of its
    // own (it is a thin wrapper); any Error from malformed base64url/CBOR
    // input is expected rejection behavior, not a finding. Anything that
    // is not a plain Error (e.g. a hang, or a Jazzer bug-detector trigger)
    // still propagates and is treated as a real finding.
    if (!(e instanceof Error)) throw e;
  }

  // The real finding this target exists to catch: global prototype
  // pollution surviving past the call, detected generically rather than
  // tied to one hardcoded key name, independent of whether decodeQntmInvite
  // itself threw.
  const current = Object.getOwnPropertyNames(Object.prototype);
  for (const name of current) {
    if (!PROTOTYPE_BASELINE.has(name)) {
      throw new Error(
        `prototype pollution: Object.prototype gained an own property "${name}" after decodeQntmInvite() was called`,
      );
    }
  }
}
