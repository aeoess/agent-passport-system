# OAuth composition vectors for the Liu draft family

Three runnable vectors that carry inputs shaped by the Liu OAuth drafts into
signed APS records another party can verify later. The pinned draft texts and
the field extraction live in drafts/. The full field map is MAPPING-TABLE.md.

## The vectors

vectors/v1-permit: an allow under a two-hop delegation_chain whose final hop
narrows the action set. The receipt binds the authorization evidence and the
chain state by digest.

vectors/v2-denial: the requested action falls outside the final hop's narrowed
subset. The signed denial names the requested action and the subset it
exceeded.

vectors/v3-observation: the Section 10.8 case where per-hop introspection is
impractical. A signed revocation observation captures what the relying party
consulted and decided; the field layout is in MAPPING-TABLE.md.

## Verify without the SDK

Node 18 or later, no installs:

    node independent-verify.mjs

From the committed files alone it recomputes:

- the strict JCS (RFC 8785) canonical form of every signed body
- each receipt_id
- the evidence digests from the fixtures in vectors/*/input.json
- every Ed25519 signature

## Verify through the SDK

From the repo root:

    npm ci
    npx tsx interop/oauth-liu-composition/verify-vectors.ts
    npx tsx --test interop/oauth-liu-composition/test.ts

The suite re-emits the vectors and checks byte stability, then runs tamper
cases on in-memory copies.

## Boundaries

The signing keys are fixed test keys published with the vectors; never reuse
them for any real identity. Evidence refs are digest-only, so re-deriving them
needs the input artifact, which is the intended model. Section 9.7 of the Rego
draft prescribes the audit tuple's content but not its JSON spellings; the
constructed spellings are marked in MAPPING-TABLE.md. The SET binding in v3
comes from APS record vocabulary; the chain-delegation draft names back-channel
notification without citing RFC 8417.
