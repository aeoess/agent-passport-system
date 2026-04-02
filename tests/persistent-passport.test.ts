import { describe, it } from 'node:test'
import assert from 'node:assert/strict'
import { joinSocialContract, isPassportValid } from '../src/index.js'

describe('Persistent Passport Mode', () => {
  it('creates passport with validityWindow', () => {
    const agent = joinSocialContract({
      name: 'daemon-agent', mission: 'Background processing', owner: 'test',
      capabilities: ['data_read'], platform: 'node', models: ['gpt-4'],
      validityWindow: {
        notBefore: '2026-01-01T00:00:00Z',
        notAfter: '2026-12-31T23:59:59Z',
      },
    })
    assert.ok(agent.passport.passport.notBefore)
    assert.equal(agent.passport.passport.expiresAt, '2026-12-31T23:59:59Z')
    assert.equal(agent.passport.passport.notBefore, '2026-01-01T00:00:00Z')
  })

  it('isPassportValid: valid for current window', () => {
    const agent = joinSocialContract({
      name: 'valid-daemon', mission: 'Test', owner: 'test',
      capabilities: ['read'], platform: 'node', models: ['test'],
      validityWindow: { notBefore: '2025-01-01T00:00:00Z', notAfter: '2027-12-31T23:59:59Z' },
    })
    const r = isPassportValid(agent.passport.passport)
    assert.equal(r.valid, true)
  })

  it('isPassportValid: NOT_YET_VALID for future notBefore', () => {
    const agent = joinSocialContract({
      name: 'future-daemon', mission: 'Test', owner: 'test',
      capabilities: ['read'], platform: 'node', models: ['test'],
      validityWindow: { notBefore: '2028-01-01T00:00:00Z', notAfter: '2028-12-31T23:59:59Z' },
    })
    const r = isPassportValid(agent.passport.passport)
    assert.equal(r.valid, false)
    assert.equal(r.reason, 'NOT_YET_VALID')
  })

  it('isPassportValid: EXPIRED for past notAfter', () => {
    const agent = joinSocialContract({
      name: 'expired-daemon', mission: 'Test', owner: 'test',
      capabilities: ['read'], platform: 'node', models: ['test'],
      validityWindow: { notBefore: '2024-01-01T00:00:00Z', notAfter: '2025-01-01T00:00:00Z' },
    })
    const r = isPassportValid(agent.passport.passport)
    assert.equal(r.valid, false)
    assert.equal(r.reason, 'EXPIRED')
  })

  it('session passport (no validityWindow) is valid', () => {
    const agent = joinSocialContract({
      name: 'session-agent', mission: 'Test', owner: 'test',
      capabilities: ['read'], platform: 'node', models: ['test'],
    })
    assert.equal(agent.passport.passport.notBefore, undefined)
    assert.equal(isPassportValid(agent.passport.passport).valid, true)
  })

  it('validityWindow defaults notBefore to creation time', () => {
    const before = new Date().toISOString()
    const agent = joinSocialContract({
      name: 'default-nb', mission: 'Test', owner: 'test',
      capabilities: ['read'], platform: 'node', models: ['test'],
      validityWindow: { notAfter: '2027-12-31T23:59:59Z' },
    })
    assert.ok(agent.passport.passport.notBefore)
    assert.ok(agent.passport.passport.notBefore! >= before)
  })
})
