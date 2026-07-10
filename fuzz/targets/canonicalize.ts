// Copyright (c) 2026 Tymofii Pidlisnyi
// SPDX-License-Identifier: Apache-2.0
// Fuzz target: canonicalize (src/core/canonical.ts).
// Byte-exactness here is load-bearing for cross-implementation signature
// verification (SDK, Gateway, Python must all agree byte-for-byte). The
// fuzzer input is treated as JSON text; if it parses, the resulting value
// can never contain a genuine reference cycle (JSON has no way to express
// one), so canonicalize's own documented cycle-detection throw
// ("Circular reference detected") can never legitimately fire on
// JSON.parse output. Any throw on a value that came from JSON.parse is
// therefore an unexpected finding, not a validation rejection.
import { canonicalize } from "../../src/core/canonical.js";

export function fuzz(data: Buffer): void {
  const text = data.toString("utf8");

  let value: unknown;
  try {
    value = JSON.parse(text);
  } catch {
    // Not valid JSON text; canonicalize's own contract is about arbitrary
    // JS values, and this input isn't exercising that, so skip it rather
    // than pass raw non-JSON text as if it were a value under test.
    return;
  }

  const first = canonicalize(value);
  // Determinism: canonicalizing the same value twice must produce
  // byte-identical output (a real property of this function, not an
  // assumption): the whole point of a canonical form is that it IS a
  // function of the value, not of call order or hidden state.
  const second = canonicalize(value);
  if (first !== second) {
    throw new Error(
      "canonicalize() is non-deterministic: two calls on the same JSON-derived value produced different output",
    );
  }
}
