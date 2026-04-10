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
  commercePreflight,
  createCommerceDelegation,
  canonicalize,
} from '../../src/index.js'
import { verify as ed25519Verify } from '../../src/crypto/keys.js'
import type { CommercePreflightResult } from '../../src/index.js'

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
    p = bindWallet({ passport: p, privateKey: keyPair.privateKey, chain: 'solana', address: 'sol_b' })
    p = bindWallet({ passport: p, privateKey: keyPair.privateKey, chain: 'ethereum', address: '0xC' })

    const { passport: after } = unbindWallet({
      passport: p,
      privateKey: keyPair.privateKey,
      chain: 'solana',
      address: 'sol_b',
    })

    assert.equal(after.passport.bound_wallets!.length, 2)
    assert.ok(verifyBoundWallet(after, 'nano', 'nano_a'))
    assert.equal(verifyBoundWallet(after, 'solana', 'sol_b'), false)
    assert.ok(verifyBoundWallet(after, 'ethereum', '0xC'))
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

describe('commercePreflight — wallet_bound gate', () => {
  function commerceFixture() {
    const { signedPassport, keyPair } = createPassport({
      agentId: `shopper-wallet-${Date.now()}`,
      agentName: 'WalletShopper',
      ownerAlias: 'tima',
      mission: 'Spend Nano via bound wallet',
      capabilities: ['commerce'],
      runtime: { platform: 'node', models: ['test'], toolsCount: 1, memoryType: 'session' },
    })
    const delegation = createCommerceDelegation({
      agentId: signedPassport.passport.agentId,
      delegationId: `del-wallet-${Date.now()}`,
      spendLimit: 100000,
      currency: 'usd',
      approvedMerchants: ['ApprovedMerchant'],
    })
    return { signedPassport, keyPair, delegation }
  }

  it('denies commerce action referencing an unbound wallet with WALLET_NOT_BOUND', () => {
    const { signedPassport, delegation } = commerceFixture()
    const result = commercePreflight({
      signedPassport,
      delegation,
      merchantName: 'ApprovedMerchant',
      estimatedTotal: { amount: 1000, currency: 'usd' },
      walletRef: { chain: 'nano', address: 'nano_3unbound' },
    }) as CommercePreflightResult

    assert.equal(result.permitted, false)
    const walletCheck = result.checks.find(c => c.check === 'wallet_bound')
    assert.ok(walletCheck, 'wallet_bound check should be present when walletRef provided')
    assert.equal(walletCheck!.passed, false)
    assert.match(walletCheck!.detail, /WALLET_NOT_BOUND/)
  })

  it('permits commerce action when wallet IS bound', () => {
    const { signedPassport, keyPair, delegation } = commerceFixture()
    const bound = bindWallet({
      passport: signedPassport,
      privateKey: keyPair.privateKey,
      chain: 'nano',
      address: 'nano_3bound',
    })

    const result = commercePreflight({
      signedPassport: bound,
      delegation,
      merchantName: 'ApprovedMerchant',
      estimatedTotal: { amount: 1000, currency: 'usd' },
      walletRef: { chain: 'nano', address: 'nano_3bound' },
    }) as CommercePreflightResult

    assert.equal(result.permitted, true, `expected permit, blocked: ${result.blockedReason}`)
    const walletCheck = result.checks.find(c => c.check === 'wallet_bound')
    assert.ok(walletCheck)
    assert.equal(walletCheck!.passed, true)
  })

  it('5-gate flow without walletRef is unchanged (wallet_bound check absent)', () => {
    const { signedPassport, delegation } = commerceFixture()
    const result = commercePreflight({
      signedPassport,
      delegation,
      merchantName: 'ApprovedMerchant',
      estimatedTotal: { amount: 1000, currency: 'usd' },
    }) as CommercePreflightResult

    assert.equal(result.permitted, true)
    const walletCheck = result.checks.find(c => c.check === 'wallet_bound')
    assert.equal(walletCheck, undefined, 'wallet_bound check should not appear when walletRef omitted')
  })
})
