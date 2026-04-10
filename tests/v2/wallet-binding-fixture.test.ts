// Copyright 2024-2026 Tymofii Pidlisnyi. Apache-2.0 license. See LICENSE.
// ──────────────────────────────────────────────────────────────────
// Fixture test — aeoess-bound-demo wallet_ref binding signatures.
//
// Verifies that the canonical fixture at
//   tests/fixtures/wallet-binding/aeoess-bound-demo.json
// contains real, verifiable Ed25519 `binding_signature` values for every
// bound_wallets entry, and that tampering with any signature breaks
// verification. This is the artifact promised to
// @douglasborthwick-crypto on insumer-examples#1 (the gateway's live
// wallet_ref payload previously carried DEMO_FIXTURE_SIG_NOT_PRODUCTION_VALID
// placeholders in the DB — the seed script in ~/aeoess-gateway refreshes
// the live record from this file).
// ──────────────────────────────────────────────────────────────────

import { describe, it } from 'node:test'
import assert from 'node:assert/strict'
import { readFileSync } from 'node:fs'
import { fileURLToPath } from 'node:url'
import { dirname, join } from 'node:path'
import { verifyBoundWallet } from '../../src/v2/wallet-binding/bind.js'
import type { BoundWallet } from '../../src/v2/wallet-binding/types.js'
import type { SignedPassport } from '../../src/types/passport.js'

const __dirname = dirname(fileURLToPath(import.meta.url))
const FIXTURE_PATH = join(
  __dirname,
  '..',
  'fixtures',
  'wallet-binding',
  'aeoess-bound-demo.json'
)

interface Fixture {
  passport_id: string
  fixture_public_key: string
  bound_wallets: BoundWallet[]
}

function loadFixture(): Fixture {
  return JSON.parse(readFileSync(FIXTURE_PATH, 'utf8')) as Fixture
}

/**
 * verifyBoundWallet() takes a SignedPassport and only reads agentId,
 * publicKey, and bound_wallets off it. The fixture stores the minimal
 * shape (passport_id + fixture_public_key + bound_wallets) so external
 * wallet_ref consumers can ingest it without a full passport. Wrap it in
 * a SignedPassport-shaped object so the SDK's own verifier exercises the
 * same code path the gateway and third parties use in production.
 */
function asSignedPassport(f: Fixture): SignedPassport {
  return {
    passport: {
      agentId: f.passport_id,
      publicKey: f.fixture_public_key,
      bound_wallets: f.bound_wallets,
    } as SignedPassport['passport'],
    signature: '',
    signedAt: '',
  } as SignedPassport
}

describe('wallet_ref fixture — aeoess-bound-demo.json', () => {
  it('fixture loads and has the expected shape', () => {
    const f = loadFixture()
    assert.equal(f.passport_id, 'aeoess-bound-demo')
    assert.equal(typeof f.fixture_public_key, 'string')
    assert.equal(f.fixture_public_key.length, 64, 'Ed25519 public key is 32 bytes hex')
    assert.ok(Array.isArray(f.bound_wallets))
    assert.equal(f.bound_wallets.length, 2, 'fixture has ethereum + base entries')

    const chains = f.bound_wallets.map((w) => w.chain).sort()
    assert.deepEqual(chains, ['base', 'ethereum'])

    // Both entries sign the same external address.
    const addresses = new Set(f.bound_wallets.map((w) => w.address))
    assert.equal(addresses.size, 1)
    assert.equal(
      [...addresses][0],
      '0x742d35Cc6634C0532925a3b844Bc9e7595f7E2c1'
    )
  })

  it('every binding_signature verifies against fixture_public_key (positive path)', () => {
    const f = loadFixture()
    const sp = asSignedPassport(f)
    for (const w of f.bound_wallets) {
      const ok = verifyBoundWallet(sp, w.chain, w.address)
      assert.equal(
        ok,
        true,
        `binding_signature for chain=${w.chain} must verify against fixture_public_key`
      )
    }
  })

  it('each binding_signature is distinct (no accidental reuse across chains)', () => {
    const f = loadFixture()
    const sigs = f.bound_wallets.map((w) => w.binding_signature)
    assert.equal(
      new Set(sigs).size,
      sigs.length,
      'every wallet entry must have its own signature'
    )
  })

  it('corrupted binding_signature fails verification (negative path)', () => {
    const f = loadFixture()
    // Flip one hex character in each signature and confirm verification fails.
    for (let i = 0; i < f.bound_wallets.length; i++) {
      const w = f.bound_wallets[i]
      const sig = w.binding_signature
      const corruptedChar = sig[0] === '0' ? '1' : '0'
      const corrupted = corruptedChar + sig.slice(1)
      assert.notEqual(corrupted, sig, 'sanity: corruption actually changes the string')

      const tampered: Fixture = {
        ...f,
        bound_wallets: f.bound_wallets.map((bw, j) =>
          j === i ? { ...bw, binding_signature: corrupted } : bw
        ),
      }
      const sp = asSignedPassport(tampered)
      assert.equal(
        verifyBoundWallet(sp, w.chain, w.address),
        false,
        `corrupted ${w.chain} binding_signature must NOT verify`
      )

      // Other entries (untouched) still verify — tampering is localized.
      for (let k = 0; k < tampered.bound_wallets.length; k++) {
        if (k === i) continue
        const other = tampered.bound_wallets[k]
        assert.equal(
          verifyBoundWallet(sp, other.chain, other.address),
          true,
          `untouched ${other.chain} entry must still verify when a different entry is corrupted`
        )
      }
    }
  })

  it('corrupted bound_at (canonical payload tamper) fails verification', () => {
    const f = loadFixture()
    // Change bound_at so the canonical payload hashes differently; the
    // original signature must no longer verify even though the sig itself
    // is untouched.
    const tampered: Fixture = {
      ...f,
      bound_wallets: [
        {
          ...f.bound_wallets[0],
          bound_at: '2099-01-01T00:00:00.000Z',
        },
        ...f.bound_wallets.slice(1),
      ],
    }
    const sp = asSignedPassport(tampered)
    const w = tampered.bound_wallets[0]
    assert.equal(
      verifyBoundWallet(sp, w.chain, w.address),
      false,
      'tampering with bound_at must break verification even when sig bytes are unchanged'
    )
  })

  it('wrong public key (different fixture) fails verification', () => {
    const f = loadFixture()
    // Any valid-shaped but unrelated Ed25519 pubkey must not verify.
    const unrelatedPub =
      '0000000000000000000000000000000000000000000000000000000000000001'
    const tampered: Fixture = { ...f, fixture_public_key: unrelatedPub }
    const sp = asSignedPassport(tampered)
    for (const w of f.bound_wallets) {
      assert.equal(
        verifyBoundWallet(sp, w.chain, w.address),
        false,
        `wrong pubkey must not verify ${w.chain} binding`
      )
    }
  })
})
