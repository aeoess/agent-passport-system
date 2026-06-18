# Key Resolution (M3)

A standardized `KeyResolver` interface plus a reference resolver that maps a
DID (`did:key`, `did:web`, `did:cycles`) or a direct JWKS endpoint to a single
Ed25519 verification key. The returned key is a 64-char hex string the existing
`crypto/keys.ts` `verify()` consumes, so a Cycles envelope signature check can
run end to end.

This is an SDK protocol primitive: an interface and a reference implementation.
It is **not** a hosted resolution service. There is no cross-tenant aggregation,
no registry, no alerting, and no network endpoint exposed by this module.

## What it does

- **`KeyResolver` interface**: `canResolve(locator)` and `resolve(locator)`.
  A resolver answers "which public key does this locator assert?" and performs
  no signature verification itself.
- **`CyclesKeyResolver`**: one reference resolver behind that interface:
  - `did:key`: self-certifying, no network (reuses existing `fromDIDKey`).
  - `did:web`: fetches the DID Document (reuses existing `resolveDIDWeb`),
    selects a `verificationMethod` by fragment.
  - `did:cycles` / direct `jwksUrl`: fetches a JWKS (RFC 7517), selects an
    Ed25519 key (RFC 8037) by `kid`, with an optional validity-window gate
    (`issuedAtMs`) and raw-hex signer match (`publicKeyHex`). `did:cycles` is
    hash-bound and NOT self-locating — the caller supplies `jwksUrl` (see below).
- **Caching**: in-process TTL cache with distinct hit/miss handling. A cached
  miss is never promoted to a key.
- **Failure policy**: explicit `fail-open` vs `fail-closed`, defaulting to
  `fail-closed`.

## did:cycles method shape

`did:cycles` is an AEOESS-defined method for Cycles evidence signers, settled
with the Cycles maintainers on `runcycles/cycles-protocol` (#43, spec
`drafts/cycles-evidence-v0.1`). The subject is a **hash, not a host** — it is the
lowercase hex `sha256(server_id)`, a BINDING value, not a locator:

```
did:cycles:<sha256(server_id)>            (optionally with #<kid>)
```

A hash cannot be reversed to a URL, so `did:cycles` is **not self-locating**.
The JWK Set is located from the envelope's own `server_id`, API-base-relative
(NOT origin-rooted — `server_id` carries its path):

```
{server_id}/.well-known/cycles-jwks.json     (see cyclesJwksUrl)
```

The cycles verify layer (which holds the envelope) checks
`sha256(server_id) === <subject>` and hands the resolver the derived `jwksUrl`.
Keeping the JWKS under the same base anchors key authority to the exact
`server_id` the DID hash commits to, closing the cross-tenant key-confusion path
an origin-rooted JWKS would open under a path-multi-tenant host.

A DID-URL fragment is the `kid`: `did:cycles:<hash>#2026-06` selects the JWK
whose `kid === "2026-06"`. Selection adds a validity-WINDOW gate over the kid
match: the key whose `[cycles_nbf_ms, cycles_exp_ms)` covers the envelope's
`issued_at_ms` — never "the current key", so a receipt verified after a rotation
checks against the key valid when it was signed. Zero/ambiguous matches fail
closed.

## Key selection

1. Resolve to a JWKS; assert `keys` is a non-empty array.
2. Filter to Ed25519 signing candidates: `kty==="OKP" && crv==="Ed25519"`,
   `use` absent or `"sig"`, `alg` absent or `"EdDSA"`, `key_ops` absent or
   includes `"verify"`.
3. With a requested `kid`: exactly one candidate must match (exact,
   case-sensitive). Zero matches fails closed (unknown key); duplicate `kid`
   fails closed (ambiguous).
4. With no `kid`: exactly one candidate is used; otherwise fails closed.
5. Decode `x` base64url to exactly 32 bytes; that is the Ed25519 public key.

A private JWK `d` member is a misconfiguration and is never used.

## Security posture: fail-closed by default

Any unreachable endpoint, network error, timeout, non-200 HTTP, non-JSON body,
malformed JWKS, missing or extra `keys`, unknown or duplicate `kid`, unsupported
`kty`/`crv`, or `x` that does not decode to 32 bytes yields **no key**, and the
signature check rejects. "Could not fetch the key" is never "signature valid".

`fail-open` is an explicit, opt-in, documented-degraded mode. It relaxes **only**
the unreachable/transient-network case into a degraded result that carries **no
key material** and is flagged `degraded: true`. A JWKS that loads but is
malformed, or a requested `kid` that is absent, still fails closed. HTTPS only;
off-host redirects are not followed.

## Proof box

> **Proves:** Resolving a key shows which public key a DID or JWKS endpoint
> asserts for that locator **at resolution time**.
>
> **Does not prove:** that the key is uncompromised or under sole control of the
> named party; that the endpoint asserts the same key at any later time; or that
> any signature made with the key is authorized. Under `fail-open`, an
> unreachable endpoint yields a degraded result that carries no key material and
> must not be read as a positive verification.

## Spec sources

- JWK Set + `kid`/`use`/`alg`: RFC 7517.
- OKP/Ed25519 JWK (`kty`/`crv`/`x`, EdDSA): RFC 8037.
- Ed25519 algorithm + Test 1 vector: RFC 8032 §7.1.
- base64url: RFC 7515 §2 / RFC 4648 §5.
- `did:cycles`: hash-bound (subject = `sha256(server_id)`) + API-base-relative
  JWKS + validity-window selection, settled with the Cycles maintainers on
  `runcycles/cycles-protocol` (#43; spec `drafts/cycles-evidence-v0.1`). NOT a
  did:web-style host mapping — that earlier M3 shape was dropped.
