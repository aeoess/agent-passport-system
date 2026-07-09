# Fuzzing findings

Two real bugs were found by running the fuzz targets in this directory
locally (`npx jazzer dist-fuzz/fuzz/targets/<target>.js fuzz/corpus/<target> -- -max_total_time=65 --sync`,
after compiling with `npx tsc -p fuzz/tsconfig.json`). Neither has been
patched. Both are written up here for separate review, per the rule that
a genuine crash found by fuzzing should not be silently fixed inline.

Both reproducing inputs are also saved as corpus regression seeds, so
any future fuzzing run (local or CI) re-checks them automatically:

- `fuzz/corpus/qntm-invite/finding-unbounded-map-length-hang`
- `fuzz/corpus/verify-passport/finding-non-array-delegations-crash.json`
  (the exact 942-byte fuzzer-minimized artifact)
- `fuzz/corpus/verify-passport/finding-non-array-delegations-minimal.json`
  (a hand-minimized 1-line version of the same bug, for readability)

## Finding 1: unbounded CBOR map length causes `decodeQntmInvite` to hang

**Where:** `src/interop/qntm-bridge.ts`, `cborDecodeMap` (lines 109-161),
specifically the major-type-5 (map) branch at lines 140-155 and the
length-reading branches of `readMajor` at lines 118-122.

**What:** The CBOR decoder reads a map's declared entry count (`info`)
straight from the input bytes and uses it unchecked as a loop bound:

```ts
case 5: { // map
  const result: Record<string, any> = Object.create(null)
  for (let i = 0; i < info; i++) {
    const key = String(readValue())
    const value = readValue()
    ...
  }
  return result
}
```

`info` can come from a 1, 2, or 4-byte length field in the CBOR header
(the `additional === 26` branch reads 4 bytes as an unsigned 32-bit
integer, so `info` can be as large as 4,294,967,295) with no check that
the input actually contains that many bytes, or even that `info` is
small relative to the remaining buffer length. Once `readByte()` runs
past the end of the buffer it does not throw: `data[pos]` is
`undefined`, and `undefined >> 5` coerces to `0`, so an out-of-bounds
read is silently treated as `major=0, info=0` rather than raising a
"truncated input" error. That makes the runaway loop cheap per iteration
(each generates a fast placeholder value once past the real bytes), but
the iteration count itself is fully attacker-controlled and unbounded.

**Reproducing input:** a 54-byte token (the fuzzer's minimized artifact),
which base64url-decodes to just 6 raw bytes: `a6 ba 2d a2 dc a9`.

- `a6` = major 5 (map), additional 6 -> outer map declares 6 entries.
- The very first key read for that map is itself major 5 with
  additional 26, consuming the next 4 bytes (`2d a2 dc a9`) as the
  nested map's declared length: 765,648,041.

That single 6-byte CBOR payload asks the decoder to read 765 million
map entries from a 6-byte buffer. Confirmed independently of Jazzer
(not just a fuzzer timeout artifact): calling
`decodeQntmInvite(',#prototype' + '\x0f'.repeat(43))` directly and
killing the process after 10 wall-clock seconds shows it is still
running (traced with an instrumented copy of the decoder capped at
100,000 steps: still climbing at `pos` past 100,000 with `depth: 2`,
i.e. still inside that single nested-map loop).

**Impact:** any code path that calls `decodeQntmInvite` on
attacker-supplied input (the invite token is exactly the kind of value
that arrives over the wire from an untrusted peer) can be tied up for
an effectively unbounded amount of CPU time from a token only 54
characters long. This is a denial-of-service vector, not a memory-safety
one: no crash, no memory corruption, just a declared-length amplification
similar in spirit to a zip bomb, but via a length field rather than
actual repeated data.

**Not fixed.** A fix would need to bound `info` against the remaining
buffer length before allocating the loop (e.g. reject if
`info > (data.length - pos)`, since even the smallest possible encoding
of each map entry's key and value is 1 byte), and treat an
out-of-bounds `readByte()` as a hard decode error instead of a silent
`0`. Left for review since it changes CBOR decode error behavior for
malformed/truncated input generally, not just this one shape.

## Finding 2: non-array `delegations` crashes `verifyPassport`

**Where:** `src/verification/verify.ts`, line 104.

```ts
// Check delegations
for (const delegation of passport.delegations || []) {
```

**What:** `verifyPassport` is documented (and used throughout the
codebase) as never throwing: malformed input is supposed to come back
as `{ valid: false, errors: [...], warnings }`. This line assumes
`passport.delegations` is either falsy or an array. If it is present
and truthy but not iterable (a plain object, a number, `true`, ...),
`for...of` throws `TypeError: object is not iterable` instead of being
caught by that contract.

**Reproducing input:**

```json
{"passport": {"delegations": {}}, "signature": "x"}
```

Confirmed directly (not just via the fuzzer log):

```
$ node -e "import('./dist-fuzz/src/verification/verify.js').then(({verifyPassport}) => {
  try { console.log(verifyPassport({ passport: { delegations: {} }, signature: 'x' })) }
  catch (e) { console.log('THROWS:', e.constructor.name, e.message) }
})"
THROWS: TypeError object is not iterable (cannot read property Symbol(Symbol.iterator))
```

The fuzzer's own minimized artifact (a 942-byte mutated JSON blob derived
from the `valid-signed-passport.json` seed) hits the same line the same
way: it mutates the seed's `delegations` array into an object.

**Impact:** any caller that passes a deserialized, not-yet-validated
`SignedPassport`-shaped object straight to `verifyPassport` (which is
exactly what the function exists to do: validate untrusted input) can
be crashed by a single malformed field, rather than getting back the
graceful `{valid: false, errors: [...]}` the rest of the codebase
assumes it always returns. Anywhere that assumption is relied on without
its own try/catch around the call is a potential unhandled-exception
DoS.

**Not fixed.** A fix would need to guard the loop with something like
`Array.isArray(passport.delegations) ? passport.delegations : []`
instead of `passport.delegations || []`. Left for review since it is a
one-line change but touches the verification hot path.
