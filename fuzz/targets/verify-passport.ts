// Copyright (c) 2026 Tymofii Pidlisnyi
// SPDX-License-Identifier: Apache-2.0
// Fuzz target: verifyPassport (src/verification/verify.ts).
// Read the full function first: its documented contract is to NEVER
// throw, only to return a VerificationResult with valid=false and an
// errors[] array for any malformed input (confirmed by its early-return
// pattern on missing passport/signature, before any crypto or
// canonicalize() call). Unlike the other targets in this suite, there is
// no "expected Error" class to catch here at all: for this specific
// function, any uncaught throw of any kind is itself the finding, since
// throwing at all is a contract violation, not just a crash/hang.
//
// Fuzzer input is treated as JSON text describing a candidate
// SignedPassport-shaped object (the real, wire-level shape this function
// is always called with in practice); non-JSON text is skipped rather
// than passed through, since the property under test is "does the
// verifier handle malformed SignedPassport objects gracefully," not
// "does it handle arbitrary non-JSON garbage as a JS value."
import { verifyPassport } from "../../src/verification/verify.js";
import type { SignedPassport } from "../../src/types/passport.js";

export function fuzz(data: Buffer): void {
  const text = data.toString("utf8");

  let candidate: unknown;
  try {
    candidate = JSON.parse(text);
  } catch {
    return;
  }

  // No try/catch around the call itself: verifyPassport's documented
  // contract is to never throw, so any exception here (of any type) is
  // the real finding this target exists to catch.
  verifyPassport(candidate as SignedPassport);
}
