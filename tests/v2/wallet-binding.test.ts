// Copyright 2024-2026 Tymofii Pidlisnyi. Apache-2.0 license. See LICENSE.
// Wallet Binding — agent-native structural attestation tests

import { describe, it } from 'node:test'
import assert from 'node:assert/strict'
import {
  createPassport,
  bindWallet,
  unbindWallet,
  verifyBoundWallet,
  verifyUnbindEvent,
  verifyPassport,
  generateKeyPair,
  checkWalletGate,
  createCommerceDelegation,
  canonicalize,
} from '../../src/index.js'
import { verify as ed25519Verify } from '../../src/crypto/keys.js'

function makeFixture() {
  const { signedPassport, keyPair } = createPassport({
    agentId: `agent-wallet-${Date.now()}-${Math.random().toString(36).slice(2, 8)}`,
    agentName: 'WalletBindingTest',
    ownerAlias: 'tima',
    mission: 'Test agent-native wallet binding',
    capabilities: ['commerce', 'wallet'],
    runtime: { platform: 'node', models: ['test'], toolsCount: 1, memoryType: 'session' },
  })
  return { signedPassport, keyPair }
}

describe('bindWallet — happy path', () => {
  it('binds a Nano wallet, verifies binding, returns true', () => {
    const { signedPassport, keyPair } = makeFixture()
    const nanoAddr = 'nano_3jb1fp4diu79wggp7e171jdpxp95auji4moste6tfqzh1m1independent'

    const bound = bindWallet({
      passport: signedPassport,
      privateKey: keyPair.privateKey,
      chain: 'nano',
      address: nanoAddr,
    })

    assert.ok(bound.passport.bound_wallets, 'bound_wallets should be present')
    assert.equal(bound.passport.bound_wallets!.length, 1)
    assert.equal(bound.passport.bound_wallets![0].chain, 'nano')
    assert.equal(bound.passport.bound_wallets![0].address, nanoAddr)
    assert.ok(bound.passport.bound_wallets![0].binding_signature.length > 0)
    assert.ok(verifyBoundWallet(bound, 'nano', nanoAddr))
  })

  it('the re-signed passport itself still verifies (signature integrity)', () => {
    const { signedPassport, keyPair } = makeFixture()
    const bound = bindWallet({
      passport: signedPassport,
      privateKey: keyPair.privateKey,
      chain: 'nano',
      address: 'nano_3test',
    })
    const result = verifyPassport(bound)
    assert.equal(result.valid, true, `passport should verify after binding: ${result.errors.join(', ')}`)
  })

  it('preserves verification_challenge when provided', () => {
    const { signedPassport, keyPair } = makeFixture()
    const bound = bindWallet({
      passport: signedPassport,
      privateKey: keyPair.privateKey,
      chain: 'ethereum',
      address: '0xabcdef1234567890abcdef1234567890abcdef12',
      verificationChallenge: {
        challenge: 'aps-binding-2026',
        signature: '0xdeadbeef',
        scheme: 'secp256k1',
      },
    })
    const w = bound.passport.bound_wallets![0]
    assert.ok(w.verification_challenge)
    assert.equal(w.verification_challenge!.scheme, 'secp256k1')
    assert.equal(w.verification_challenge!.challenge, 'aps-binding-2026')
  })
})

describe('bindWallet — multi-chain', () => {
  it('binds Nano + Solana + Ethereum to same passport, all three verify independently', () => {
    const { signedPassport, keyPair } = makeFixture()

    let p = signedPassport
    p = bindWallet({ passport: p, privateKey: keyPair.privateKey, chain: 'nano', address: 'nano_3multi' })
    p = bindWallet({ passport: p, privateKey: keyPair.privateKey, chain: 'solana', address: 'So11111111111111111111111111111111111111112' })
    p = bindWallet({ passport: p, privateKey: keyPair.privateKey, chain: 'ethereum', address: '0x1234567890abcdef1234567890abcdef12345678' })

    assert.equal(p.passport.bound_wallets!.length, 3)
    assert.ok(verifyBoundWallet(p, 'nano', 'nano_3multi'))
    assert.ok(verifyBoundWallet(p, 'solana', 'So11111111111111111111111111111111111111112'))
    assert.ok(verifyBoundWallet(p, 'ethereum', '0x1234567890abcdef1234567890abcdef12345678'))

    // Each chain has a distinct binding_signature
    const sigs = p.passport.bound_wallets!.map(w => w.binding_signature)
    assert.equal(new Set(sigs).size, 3, 'each binding_signature should be unique')

    // Passport itself still verifies after all three binds
    assert.equal(verifyPassport(p).valid, true)
  })

  it('extensible chain string accepted (e.g. "polkadot")', () => {
    const { signedPassport, keyPair } = makeFixture()
    const p = bindWallet({
      passport: signedPassport,
      privateKey: keyPair.privateKey,
      chain: 'polkadot',
      address: '15oF4uVJwmo4TdGW7VfQxNLavjCXviqxT9S1MgbjMNHr6Sp5',
    })
    assert.ok(verifyBoundWallet(p, 'polkadot', '15oF4uVJwmo4TdGW7VfQxNLavjCXviqxT9S1MgbjMNHr6Sp5'))
  })
})

describe('verifyBoundWallet — object-form overload (v2.1.0 UX)', () => {
  it('object form returns true for a bound Ethereum wallet', () => {
    const { signedPassport, keyPair } = makeFixture()
    const addr = '0xabcdef1234567890abcdef1234567890abcdef12'
    const p = bindWallet({
      passport: signedPassport, privateKey: keyPair.privateKey,
      chain: 'ethereum', address: addr,
    })
    assert.equal(verifyBoundWallet({ passport: p, chain: 'ethereum', address: addr }), true)
  })

  it('object form returns true for a bound Solana wallet', () => {
    const { signedPassport, keyPair } = makeFixture()
    const addr = 'So11111111111111111111111111111111111111112'
    const p = bindWallet({
      passport: signedPassport, privateKey: keyPair.privateKey,
      chain: 'solana', address: addr,
    })
    assert.equal(verifyBoundWallet({ passport: p, chain: 'solana', address: addr }), true)
  })

  it('object form returns false for an unbound address', () => {
    const { signedPassport, keyPair } = makeFixture()
    const p = bindWallet({
      passport: signedPassport, privateKey: keyPair.privateKey,
      chain: 'ethereum', address: '0x1111111111111111111111111111111111111111',
    })
    assert.equal(
      verifyBoundWallet({ passport: p, chain: 'ethereum', address: '0x2222222222222222222222222222222222222222' }),
      false
    )
  })

  it('positional form still works (no regression)', () => {
    const { signedPassport, keyPair } = makeFixture()
    const addr = '0x1234567890abcdef1234567890abcdef12345678'
    const p = bindWallet({
      passport: signedPassport, privateKey: keyPair.privateKey,
      chain: 'ethereum', address: addr,
    })
    assert.equal(verifyBoundWallet(p, 'ethereum', addr), true)
  })

  it('missing field in object form falls through to positional branch and fails gracefully', () => {
    const { signedPassport, keyPair } = makeFixture()
    const addr = 'nano_3fallthrough'
    const p = bindWallet({
      passport: signedPassport, privateKey: keyPair.privateKey,
      chain: 'nano', address: addr,
    })
    // Missing .address — discriminator treats arg1 as positional SignedPassport.
    // Without chain+address positional args, the lookup finds no match → false.
    assert.equal(
      verifyBoundWallet({ passport: p, chain: 'nano' } as any),
      false
    )
  })
})

describe('bindWallet — wrong key fails', () => {
  it('throws when binding with a non-matching private key', () => {
    const { signedPassport } = makeFixture()
    const wrongKeys = generateKeyPair()

    assert.throws(
      () =>
        bindWallet({
          passport: signedPassport,
          privateKey: wrongKeys.privateKey,
          chain: 'nano',
          address: 'nano_3wrong',
        }),
      /does not verify against passport public key/
    )
  })

  it('throws on empty address', () => {
    const { signedPassport, keyPair } = makeFixture()
    assert.throws(
      () => bindWallet({ passport: signedPassport, privateKey: keyPair.privateKey, chain: 'nano', address: '' }),
      /address must be a non-empty string/
    )
  })

  it('throws on empty chain', () => {
    const { signedPassport, keyPair } = makeFixture()
    assert.throws(
      () => bindWallet({ passport: signedPassport, privateKey: keyPair.privateKey, chain: '' as any, address: 'nano_3x' }),
      /chain must be a non-empty string/
    )
  })
})

describe('unbindWallet', () => {
  it('removes wallet from bound_wallets and verifyBoundWallet returns false', () => {
    const { signedPassport, keyPair } = makeFixture()
    const bound = bindWallet({
      passport: signedPassport,
      privateKey: keyPair.privateKey,
      chain: 'nano',
      address: 'nano_3unbind',
    })
    assert.ok(verifyBoundWallet(bound, 'nano', 'nano_3unbind'))

    const { passport: unbound, unbindEvent } = unbindWallet({
      passport: bound,
      privateKey: keyPair.privateKey,
      chain: 'nano',
      address: 'nano_3unbind',
    })

    assert.equal(unbound.passport.bound_wallets!.length, 0)
    assert.equal(verifyBoundWallet(unbound, 'nano', 'nano_3unbind'), false)

    // History preserved: the unbind event is itself signed and verifiable
    assert.equal(unbindEvent.chain, 'nano')
    assert.equal(unbindEvent.address, 'nano_3unbind')
    assert.equal(unbindEvent.passport_id, bound.passport.agentId)
    assert.ok(unbindEvent.unbind_signature.length > 0)
    assert.ok(verifyUnbindEvent(unbindEvent, bound.passport.publicKey))

    // Passport itself still verifies after unbind
    assert.equal(verifyPassport(unbound).valid, true)
  })

  it('throws when unbinding a wallet that is not currently bound', () => {
    const { signedPassport, keyPair } = makeFixture()
    assert.throws(
      () =>
        unbindWallet({
          passport: signedPassport,
          privateKey: keyPair.privateKey,
          chain: 'nano',
          address: 'nano_3nope',
        }),
      /no bound wallet matches/
    )
  })

  it('preserves other bound wallets when unbinding one of many', () => {
    const { signedPassport, keyPair } = makeFixture()
    let p = signedPassport
    p = bindWallet({ passport: p, privateKey: keyPair.privateKey, chain: 'nano', address: 'nano_a' })
    const solAddr = 'So11111111111111111111111111111111111111112'
    p = bindWallet({ passport: p, privateKey: keyPair.privateKey, chain: 'solana', address: solAddr })
    p = bindWallet({ passport: p, privateKey: keyPair.privateKey, chain: 'ethereum', address: '0xC' })

    const { passport: after } = unbindWallet({
      passport: p,
      privateKey: keyPair.privateKey,
      chain: 'solana',
      address: solAddr,
    })

    assert.equal(after.passport.bound_wallets!.length, 2)
    assert.ok(verifyBoundWallet(after, 'nano', 'nano_a'))
    assert.equal(verifyBoundWallet(after, 'solana', solAddr), false)
    assert.ok(verifyBoundWallet(after, 'ethereum', '0xC'))
  })
})

describe('bindWallet — Solana chain validation', () => {
  it('accepts a valid Solana wallet_ref (base58, 32-44 chars)', () => {
    const { signedPassport, keyPair } = makeFixture()
    const solAddr = 'DRiP2Pn2K6fuMLKQmt5rZWxa91GPqgT4gJZN6fyUoF3z'
    const bound = bindWallet({
      passport: signedPassport,
      privateKey: keyPair.privateKey,
      chain: 'solana',
      address: solAddr,
      boundAt: '2026-04-15T10:00:00.000Z',
    })
    const w = bound.passport.bound_wallets![0]
    assert.equal(w.chain, 'solana')
    assert.equal(w.address, solAddr)
    assert.equal(w.bound_at, '2026-04-15T10:00:00.000Z')
    assert.ok(verifyBoundWallet(bound, 'solana', solAddr))
  })

  it('rejects invalid base58 (contains forbidden char "0")', () => {
    const { signedPassport, keyPair } = makeFixture()
    assert.throws(
      () =>
        bindWallet({
          passport: signedPassport,
          privateKey: keyPair.privateKey,
          chain: 'solana',
          address: '0000000000000000000000000000000000000000000',
        }),
      /not valid base58/
    )
  })

  it('rejects Solana address outside the 32-44 char range', () => {
    const { signedPassport, keyPair } = makeFixture()
    assert.throws(
      () =>
        bindWallet({
          passport: signedPassport,
          privateKey: keyPair.privateKey,
          chain: 'solana',
          address: 'So11',
        }),
      /expected 32-44 base58 chars/
    )
  })

  it('mixed chain array (EVM + Solana) accepted; bound_at preserved for Solana entries', () => {
    const { signedPassport, keyPair } = makeFixture()
    const solAddr = '7xKXtg2CW87d97TXJSDpbD5jBkheTqA83TZRuJosgAsU'
    const solAt = '2026-04-15T11:22:33.000Z'

    let p = signedPassport
    p = bindWallet({
      passport: p,
      privateKey: keyPair.privateKey,
      chain: 'ethereum',
      address: '0x1234567890abcdef1234567890abcdef12345678',
    })
    p = bindWallet({
      passport: p,
      privateKey: keyPair.privateKey,
      chain: 'solana',
      address: solAddr,
      boundAt: solAt,
    })

    assert.equal(p.passport.bound_wallets!.length, 2)
    const sol = p.passport.bound_wallets!.find(w => w.chain === 'solana')!
    assert.equal(sol.bound_at, solAt, 'bound_at must be preserved exactly for Solana entries')
    assert.ok(verifyBoundWallet(p, 'solana', solAddr))
    assert.ok(verifyBoundWallet(p, 'ethereum', '0x1234567890abcdef1234567890abcdef12345678'))
    assert.equal(verifyPassport(p).valid, true)
  })
})

describe('Cross-verification (offline, no passport object)', () => {
  it('external party with only the passport public key verifies the binding signature offline', () => {
    const { signedPassport, keyPair } = makeFixture()
    const bound = bindWallet({
      passport: signedPassport,
      privateKey: keyPair.privateKey,
      chain: 'base',
      address: '0xbase00000000000000000000000000000000000000',
      boundAt: '2026-04-10T12:00:00.000Z',
    })

    const w = bound.passport.bound_wallets![0]

    // External verifier reconstructs the canonical payload from public fields
    const payload = canonicalize({
      passport_id: bound.passport.agentId,
      chain: w.chain,
      address: w.address,
      bound_at: w.bound_at,
    })

    // And checks the signature against ONLY the passport public key
    const externallyValid = ed25519Verify(payload, w.binding_signature, bound.passport.publicKey)
    assert.equal(externallyValid, true)

    // Wrong public key from a different agent must NOT verify
    const otherKeys = generateKeyPair()
    assert.equal(ed25519Verify(payload, w.binding_signature, otherKeys.publicKey), false)
  })
})

describe('checkWalletGate predicate (commerce orchestrator tests moved to gateway)', () => {
  function passportFixture() {
    const { signedPassport, keyPair } = createPassport({
      agentId: `shopper-wallet-${Date.now()}-${Math.random().toString(36).slice(2, 6)}`,
      agentName: 'WalletShopper',
      ownerAlias: 'tima',
      mission: 'Spend Nano via bound wallet',
      capabilities: ['commerce'],
      runtime: { platform: 'node', models: ['test'], toolsCount: 1, memoryType: 'session' },
    })
    return { signedPassport, keyPair }
  }

  it('denies action referencing an unbound wallet (WALLET_NOT_BOUND)', () => {
    const { signedPassport } = passportFixture()
    const check = checkWalletGate(signedPassport, { chain: 'nano', address: 'nano_3unbound' })
    assert.equal(check.check, 'wallet_bound')
    assert.equal(check.passed, false)
    assert.match(check.detail, /WALLET_NOT_BOUND/)
  })

  it('permits action when wallet IS bound', () => {
    const { signedPassport, keyPair } = passportFixture()
    const bound = bindWallet({
      passport: signedPassport,
      privateKey: keyPair.privateKey,
      chain: 'nano',
      address: 'nano_3bound',
    })
    const check = checkWalletGate(bound, { chain: 'nano', address: 'nano_3bound' })
    assert.equal(check.passed, true)
  })

  it('createCommerceDelegation still exposes spend limits for caller-side gating', () => {
    const d = createCommerceDelegation({
      agentId: 'a',
      delegationId: 'd',
      spendLimit: 100,
      approvedMerchants: ['ApprovedMerchant'],
    })
    assert.equal(d.spendLimit, 100)
    assert.deepEqual(d.approvedMerchants, ['ApprovedMerchant'])
  })
})
