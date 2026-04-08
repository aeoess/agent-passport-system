// Copyright 2024-2026 Tymofii Pidlisnyi. Apache-2.0 license. See LICENSE.
import { describe, it } from 'node:test'
import assert from 'node:assert/strict'
import { generateKeyPair, createDelegation, subDelegate } from '../src/index.js'

const pk = generateKeyPair()
const ak = generateKeyPair()
const bk = generateKeyPair()

describe('Telemetry Scope + Derivation Rights', () => {
  it('telemetry scope requires derivation_rights', () => {
    assert.throws(() => createDelegation({
      delegatedTo: ak.publicKey,
      delegatedBy: pk.publicKey,
      scope: ['telemetry:email'],
      privateKey: pk.privateKey,
    }), /telemetry scopes require derivation_rights/)
  })

  it('telemetry scope with derivation_rights succeeds', () => {
    const d = createDelegation({
      delegatedTo: ak.publicKey,
      delegatedBy: pk.publicKey,
      scope: ['telemetry:email', 'telemetry:calendar'],
      spendLimit: 100,
      derivation_rights: {
        retention_permitted: true,
        retention_ttl: 86400,
        derivation_classes: ['communication', 'scheduling'],
        export_permitted: false,
      },
      observation_policy: {
        continuous_access: true,
        review_interval: 604800,
        revocation_behavior: 'purge',
      },
      privateKey: pk.privateKey,
    })
    assert.ok(d.derivation_rights)
    assert.equal(d.derivation_rights!.retention_permitted, true)
    assert.equal(d.derivation_rights!.retention_ttl, 86400)
    assert.ok(d.observation_policy)
    assert.equal(d.observation_policy!.revocation_behavior, 'purge')
  })

  it('non-telemetry scopes work without derivation_rights', () => {
    const d = createDelegation({
      delegatedTo: ak.publicKey,
      delegatedBy: pk.publicKey,
      scope: ['data:read', 'tool:search'],
      spendLimit: 100,
      privateKey: pk.privateKey,
    })
    assert.equal(d.derivation_rights, undefined)
  })
})

describe('Derivation Rights Monotonic Narrowing', () => {
  const parent = createDelegation({
    delegatedTo: ak.publicKey,
    delegatedBy: pk.publicKey,
    scope: ['telemetry:email', 'telemetry:calendar'],
    spendLimit: 500,
    maxDepth: 2,
    derivation_rights: {
      retention_permitted: true,
      retention_ttl: 86400,
      derivation_classes: ['communication', 'scheduling'],
      export_permitted: false,
    },
    observation_policy: {
      continuous_access: true,
      review_interval: 604800,
      revocation_behavior: 'purge',
    },
    privateKey: pk.privateKey,
  })

  it('child can narrow retention_ttl', () => {
    const child = subDelegate({
      parentDelegation: parent,
      delegatedTo: bk.publicKey,
      scope: ['telemetry:email'],
      spendLimit: 100,
      derivation_rights: {
        retention_permitted: true,
        retention_ttl: 3600, // narrower than parent's 86400
        derivation_classes: ['communication'],
        export_permitted: false,
      },
      privateKey: ak.privateKey,
    })
    assert.equal(child.derivation_rights!.retention_ttl, 3600)
  })

  it('child cannot widen retention_ttl beyond parent', () => {
    assert.throws(() => subDelegate({
      parentDelegation: parent,
      delegatedTo: bk.publicKey,
      scope: ['telemetry:email'],
      spendLimit: 100,
      derivation_rights: {
        retention_permitted: true,
        retention_ttl: 999999, // wider than parent's 86400
        derivation_classes: ['communication'],
        export_permitted: false,
      },
      privateKey: ak.privateKey,
    }), /retention_ttl/)
  })

  it('child cannot set retention_permitted=true if parent is false', () => {
    const restrictedParent = createDelegation({
      delegatedTo: ak.publicKey,
      delegatedBy: pk.publicKey,
      scope: ['telemetry:email'],
      spendLimit: 100,
      maxDepth: 2,
      derivation_rights: {
        retention_permitted: false,
        export_permitted: false,
      },
      privateKey: pk.privateKey,
    })
    assert.throws(() => subDelegate({
      parentDelegation: restrictedParent,
      delegatedTo: bk.publicKey,
      scope: ['telemetry:email'],
      spendLimit: 50,
      derivation_rights: {
        retention_permitted: true, // parent says false
        export_permitted: false,
      },
      privateKey: ak.privateKey,
    }), /parent does not permit retention/)
  })

  it('child cannot add derivation_classes parent does not have', () => {
    assert.throws(() => subDelegate({
      parentDelegation: parent,
      delegatedTo: bk.publicKey,
      scope: ['telemetry:email'],
      spendLimit: 100,
      derivation_rights: {
        retention_permitted: true,
        retention_ttl: 3600,
        derivation_classes: ['communication', 'financial'], // 'financial' not in parent
        export_permitted: false,
      },
      privateKey: ak.privateKey,
    }), /classes.*not in parent/)
  })

  it('child cannot enable export if parent disables it', () => {
    assert.throws(() => subDelegate({
      parentDelegation: parent,
      delegatedTo: bk.publicKey,
      scope: ['telemetry:email'],
      spendLimit: 100,
      derivation_rights: {
        retention_permitted: true,
        retention_ttl: 3600,
        derivation_classes: ['communication'],
        export_permitted: true, // parent says false
      },
      privateKey: ak.privateKey,
    }), /parent does not permit export/)
  })
})
