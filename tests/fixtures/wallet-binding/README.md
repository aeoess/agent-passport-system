# Wallet Binding Fixture — `aeoess-bound-demo`

Canonical fixture holding real Ed25519 `binding_signature` values for the
`aeoess-bound-demo` agent on two EVM chains (ethereum, base), both bound to
the same external address `0x742d35Cc6634C0532925a3b844Bc9e7595f7E2c1`.

This fixture is what the gateway's live `aeoess-bound-demo` agent should
serve via `/api/v1/public/trust/by-wallet/...` once
`scripts/seed-bound-demo.ts` (in `aeoess-gateway`) writes it to prod. External
verifiers (see `insumer-examples#1`) can reconstruct each canonical payload
and verify `binding_signature` against `fixture_public_key` with any standard
Ed25519 library.

## Canonical payload (what gets signed)

Each `binding_signature` is `sign(canonicalize(payload), fixture_private_key)`
where `payload` is:

```json
{
  "passport_id": "aeoess-bound-demo",
  "chain": "<chain>",
  "address": "<address>",
  "bound_at": "<bound_at>"
}
```

`canonicalize()` is APS's deterministic JSON serializer (sorted keys, stripped
nulls). See `src/core/canonical.ts`.

This is the same payload that `bindWallet()` in `src/v2/wallet-binding/bind.ts`
produces, and the same one `verifyBoundWallet()` reconstructs on the verify
side.

## Deterministic fixture keypair — regeneration

The fixture uses a deterministic Ed25519 keypair so anyone can reproduce the
signatures byte-for-byte. It is a **fixture-only key — never used by the
gateway, never used by the issuer, never used by any production agent**.

**Seed derivation:**

```
private_key (hex, 32 bytes) =
    sha256("aeoess-bound-demo/v1/fixture-key")
  = 0adc3fadd8e823da5ef0b64668bd8f6dce61c71d271978c9bcf3110e87c0ac0d
```

**Public key (hex, 32 bytes):**

```
c7cdce4d15b0c175a3fec538202e1ba9f6e351e4fbb16998bb42265a1542d5bb
```

Matches `fixture_public_key` in `aeoess-bound-demo.json`.

## Regeneration script

```ts
import { sign, publicKeyFromPrivate } from '../../../src/crypto/keys.js'
import { canonicalize } from '../../../src/core/canonical.js'
import { createHash } from 'node:crypto'

const seed = createHash('sha256')
  .update('aeoess-bound-demo/v1/fixture-key')
  .digest('hex')
const pub = publicKeyFromPrivate(seed)

const passport_id = 'aeoess-bound-demo'
const address = '0x742d35Cc6634C0532925a3b844Bc9e7595f7E2c1'
const entries = [
  { chain: 'ethereum', bound_at: '2026-04-10T12:00:00.000Z' },
  { chain: 'base',     bound_at: '2026-04-10T12:00:01.000Z' },
]

const bound_wallets = entries.map(e => {
  const payload = canonicalize({ passport_id, chain: e.chain, address, bound_at: e.bound_at })
  return {
    chain: e.chain,
    address,
    bound_at: e.bound_at,
    binding_signature: sign(payload, seed),
  }
})

console.log(JSON.stringify({ passport_id, fixture_public_key: pub, bound_wallets }, null, 2))
```

Running this script produces `aeoess-bound-demo.json` byte-for-byte (the test
in `tests/v2/wallet-binding-fixture.test.ts` checks every signature against
`fixture_public_key` on each test run).

## Why a minimal shape, not a full `SignedPassport`

This fixture is the payload an external verifier receives via the gateway's
`wallet_ref` array on a trust-profile response — it's not a full APS passport.
The gateway emits
`{ chain, address, bound_at, binding_sig }` tuples alongside the rest of the
trust envelope, and downstream verifiers (like
`insumer-examples`) resolve the passport public key separately (from the
passport object, the gateway's `/api/v1/public/trust/{agentId}` response, or
whatever identity resolver they prefer).

This fixture lets those verifiers prove the end-to-end verification path
without fetching anything live: take the canonical payload, the
`binding_signature`, and `fixture_public_key` — then verify offline.

At test time, APS's own `verifyBoundWallet()` consumes a `SignedPassport`
object. The test file wraps the fixture in a minimal `SignedPassport`-shaped
object (only `agentId`, `publicKey`, and `bound_wallets` are read by
`verifyBoundWallet`), so the same verification path the SDK ships exercises
the fixture directly.
