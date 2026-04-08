import { describe, it } from 'node:test'
import assert from 'node:assert/strict'
import { validateCredentialLifecycle } from '../src/core/governance.js'
import type { CredentialLifecyclePolicy } from '../src/types/governance.js'

describe('Credential Lifecycle Validation (#1717)', () => {
  const policy: CredentialLifecyclePolicy = {
    maxSessionDurationSeconds: 3600,       // 1 hour
    credentialTTLSeconds: 86400,           // 24 hours
    revocationCheckFrequencySeconds: 300,  // 5 minutes
  }

  const baseTime = '2026-04-07T12:00:00.000Z'

  describe('credential TTL', () => {
    it('valid: credential within TTL', () => {
      const result = validateCredentialLifecycle(policy, {
        sessionStartedAt: '2026-04-07T11:30:00.000Z',
        credentialIssuedAt: '2026-04-07T00:00:00.000Z', // 12h ago, TTL is 24h
        now: baseTime,
      })
      assert.equal(result.valid, true)
      assert.equal(result.reason, undefined)
    })

    it('invalid: credential TTL expired', () => {
      const result = validateCredentialLifecycle(policy, {
        sessionStartedAt: '2026-04-07T11:30:00.000Z',
        credentialIssuedAt: '2026-04-06T00:00:00.000Z', // 36h ago, TTL is 24h
        now: baseTime,
      })
      assert.equal(result.valid, false)
      assert.ok(result.reason?.includes('TTL expired'))
    })

    it('invalid: credential TTL just barely expired', () => {
      const result = validateCredentialLifecycle(policy, {
        sessionStartedAt: '2026-04-07T11:59:00.000Z',
        credentialIssuedAt: '2026-04-06T11:59:59.000Z', // 86401s ago
        now: baseTime,
      })
      assert.equal(result.valid, false)
      assert.ok(result.reason?.includes('TTL expired'))
    })
  })

  describe('session duration', () => {
    it('valid: session within max duration', () => {
      const result = validateCredentialLifecycle(policy, {
        sessionStartedAt: '2026-04-07T11:30:00.000Z', // 30 min ago
        credentialIssuedAt: '2026-04-07T10:00:00.000Z',
        now: baseTime,
      })
      assert.equal(result.valid, true)
    })

    it('invalid: session exceeds max duration', () => {
      const result = validateCredentialLifecycle(policy, {
        sessionStartedAt: '2026-04-07T10:00:00.000Z', // 2h ago, max is 1h
        credentialIssuedAt: '2026-04-07T10:00:00.000Z',
        now: baseTime,
      })
      assert.equal(result.valid, false)
      assert.ok(result.reason?.includes('Session duration'))
      assert.ok(result.reason?.includes('exceeds max'))
    })

    it('session check runs before TTL check (early exit)', () => {
      // Both expired, but session check should trigger first
      const result = validateCredentialLifecycle(policy, {
        sessionStartedAt: '2026-04-06T00:00:00.000Z', // 36h session
        credentialIssuedAt: '2026-04-05T00:00:00.000Z', // 60h credential
        now: baseTime,
      })
      assert.equal(result.valid, false)
      assert.ok(result.reason?.includes('Session duration'))
    })
  })

  describe('edge cases', () => {
    it('both at exact boundary: session=3600s, TTL=86400s', () => {
      const result = validateCredentialLifecycle(policy, {
        sessionStartedAt: '2026-04-07T11:00:00.000Z', // exactly 3600s
        credentialIssuedAt: '2026-04-06T12:00:00.000Z', // exactly 86400s
        now: baseTime,
      })
      // At exactly the boundary, not exceeded (> not >=)
      assert.equal(result.valid, true)
    })

    it('policy with revocation endpoint set', () => {
      const policyWithEndpoint: CredentialLifecyclePolicy = {
        ...policy,
        revocationEndpoint: 'https://gateway.aeoess.com/api/v1/revocation-check',
      }
      const result = validateCredentialLifecycle(policyWithEndpoint, {
        sessionStartedAt: '2026-04-07T11:30:00.000Z',
        credentialIssuedAt: '2026-04-07T10:00:00.000Z',
        now: baseTime,
      })
      assert.equal(result.valid, true)
    })

    it('short-lived policy: 60s session, 300s TTL', () => {
      const shortPolicy: CredentialLifecyclePolicy = {
        maxSessionDurationSeconds: 60,
        credentialTTLSeconds: 300,
        revocationCheckFrequencySeconds: 10,
      }
      const result = validateCredentialLifecycle(shortPolicy, {
        sessionStartedAt: '2026-04-07T11:59:30.000Z', // 30s ago
        credentialIssuedAt: '2026-04-07T11:58:00.000Z', // 2min ago
        now: baseTime,
      })
      assert.equal(result.valid, true)

      const expired = validateCredentialLifecycle(shortPolicy, {
        sessionStartedAt: '2026-04-07T11:58:00.000Z', // 120s ago, max 60
        credentialIssuedAt: '2026-04-07T11:58:00.000Z',
        now: baseTime,
      })
      assert.equal(expired.valid, false)
    })
  })
})
