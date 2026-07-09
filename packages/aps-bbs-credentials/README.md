# @aeoess/aps-bbs-credentials (EXPERIMENTAL, ISOLATED)

> Status: EXPERIMENTAL. Not core-reviewed cryptography. The crypto-review
> burden is outstanding. Do not use this in production or for any decision that
> carries real consequence until an independent cryptographic review has
> landed.

BBS selective-disclosure scope credentials over BLS12-381. A signer binds an
ordered list of scope strings (for example delegation scopes such as
`read:repo` or `settle:usd:<=100`) into a single fixed-size signature. The
holder can later derive a zero-knowledge proof that reveals only a chosen
SUBSET of those scopes, without revealing the undisclosed scopes or the
original signature. This lets a holder show "I hold a credential that grants
`read:repo`" without disclosing the rest of the delegation chain.

## Isolation contract

This package is deliberately walled off from the SDK core.

- It is NOT imported by core and adds NO weight to the core bundle.
- It adds NO dependency to the repository root `package.json`. Its one runtime
  dependency lives in this directory's own `package.json` and `node_modules`.
- It modifies NO file under `src/`. It changes no existing semantics, no
  signing path, and no canonical encoding.
- There is no core merge path this round. It lands as an experimental package
  only.

The `ScopeOfClaim` shape used here is a structural COPY of the core type, not an
import, so that the package can dogfood the honest-scope convention while
staying fully isolated.

## Cryptographic backing

This package uses
[`@grottonetworking/bbs-signatures`](https://github.com/Wind4Greg/grotto-bbs-signatures)
at version `0.1.5`, a pure-JavaScript implementation of the IETF/IRTF BBS
Signature Scheme built on the audited `@noble/curves` BLS12-381 primitives. No
WASM and no native build step.

Scheme and draft notes that callers MUST respect:

- This is IETF/IRTF "BBS", which is a DIFFERENT construction from legacy
  "BBS+". A signature from one will not verify under the other. This package is
  BBS, not BBS+.
- Version `0.1.5` conforms to draft-05 of
  `draft-irtf-cfrg-bbs-signatures`. The draft has since advanced. Ciphersuite
  constants, generator seeds, and domain-separation tags are not byte-identical
  across drafts. Tests in this package validate behavior against the pinned
  library, not against the latest published draft vectors. Treat conformance as
  draft-05 only.
- Public keys live in G2 (96-byte compressed points), signatures live in G1
  (80 bytes total: one 48-byte G1 point plus one 32-byte scalar). Secret keys
  and message scalars are 32 bytes.

## Proof box

Specified, tested, validated against the pinned library's draft-05 behavior.
This is NOT core-reviewed cryptography this round.

Proves:

- A derived disclosure proof shows the holder possesses a credential, signed by
  the named public key, that asserts the disclosed scope subset, WITHOUT
  revealing the undisclosed scopes or the original signature. The proof is bound
  to a verifier-supplied presentation header to resist replay.

Does not prove:

- That the undisclosed scopes are narrow or harmless. Hidden scopes could be
  broad. Absence of disclosure is not evidence of limited authority.
- That the signer was entitled to assert any of these scopes. This is a
  possession proof over a signature, not an authorization decision.
- Anything about freshness or revocation. Bind those out of band.
- Truth of the scope strings. The credential asserts a signed claim, not a fact
  about the world.
- Production-grade security. Constants track an IETF draft, not an RFC, and
  this module has not had an independent cryptographic review.

## API

```ts
import {
  generateKeyPair,
  issueScopeCredential,
  verifyScopeCredential,
  deriveDisclosureProof,
  verifyDisclosureProof,
} from '@aeoess/aps-bbs-credentials'

// Issuer side. keyMaterial MUST come from a CSPRNG in production.
const keyPair = await generateKeyPair(crypto.getRandomValues(new Uint8Array(32)))
const credential = await issueScopeCredential(keyPair, [
  'read:repo',
  'write:repo',
  'settle:usd:<=100',
  'invoke:tool:search',
])

// Holder side. Reveal only a subset. ph is a fresh verifier challenge.
const ph = crypto.getRandomValues(new Uint8Array(16))
const presentation = await deriveDisclosureProof(
  credential,
  ['read:repo', 'invoke:tool:search'],
  ph,
)

// Verifier side. True only if the proof is valid for the disclosed subset
// under this presentation header.
const ok = await verifyDisclosureProof(presentation)
```

Disclosure indexes are resolved from the disclosed scope strings against the
credential's ordered scope vector, then normalized to ascending order.
Revealing zero scopes and revealing all scopes are both valid; a zero-disclosure
proof still proves possession of a valid credential. Proof size grows with the
number of HIDDEN scopes.

## Security notes for callers

- `deriveDisclosureProof` accepts an optional deterministic scalar source. That
  parameter exists for test reproduction only. Never supply fixed randomness in
  production; omit it so a secure random source is used.
- Always pass a fresh, verifier-supplied `presentationHeader` to bind the proof
  to a presentation context and resist replay.
- This package carries no validity window. Freshness, expiry, and revocation
  must be handled outside the proof.

## Running the tests

```
npm install
npm test
```

The suite includes negative-path fixtures: a tampered proof fails, a swapped
disclosed value fails, a mismatched presentation header fails, and disclosing a
scope that is not in the credential is rejected. Revealing zero and all scopes
are both covered.

## License

Apache-2.0. Copyright 2026 Tymofii Pidlisnyi.
