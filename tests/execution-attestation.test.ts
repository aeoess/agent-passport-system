// Execution Attestation Tests — Checkpoint 3
// Proves that infrastructure witnesses what ACTUALLY ran, not just what was authorized.

import { describe, it } from 'node:test'
import assert from 'node:assert/strict'
import {
  generateKeyPair,
  createExecutionAttestation,
  verifyExecutionAttestation,
  detectExecutionDrift,
  DEFAULT_DRIFT_RULES,
} from '../src/index.js'
import type { CreateExecutionAttestationInput } from '../src/index.js'

// ── Helpers ──

const sandbox = generateKeyPair()   // infrastructure attestor
const agent = generateKeyPair()      // the agent being attested

function makeInput(overrides?: Partial<CreateExecutionAttestationInput>): CreateExecutionAttestationInput {
  return {
    agentId: 'agent-001',
    attestorId: 'sandbox://runner-42',
    attestorType: 'sandbox',
    toolName: 'web_search',
    actualParameters: { query: 'weather in tokyo', limit: 10 },
    actualResult: { results: ['sunny', '25C'] },
    policyReceiptId: 'pr-001',
    executionFrameId: 'frame-001',
    intentParameters: { query: 'weather in tokyo', limit: 10 },
    executionStartedAt: '2026-04-01T10:00:00Z',
    executionCompletedAt: '2026-04-01T10:00:01Z',
    ...overrides,
  }
}


// ══════════════════════════════════════════════════════════════════
// 1. Matching execution (no drift)
// ══════════════════════════════════════════════════════════════════

describe('Execution Attestation — Checkpoint 3', () => {

  describe('matching execution (no drift)', () => {
    it('creates attestation with match=true when params identical', () => {
      const att = createExecutionAttestation(makeInput(), sandbox.privateKey)
      assert.equal(att.match, true)
      assert.equal(att.drift.severity, 'none')
      assert.equal(att.drift.fields.length, 0)
      assert.equal(att.toolName, 'web_search')
      assert.equal(att.attestorType, 'sandbox')
      assert.ok(att.signature.length > 0)
      assert.ok(att.executionId.length > 0)
    })

    it('verifies valid attestation successfully', () => {
      const att = createExecutionAttestation(makeInput(), sandbox.privateKey)
      const result = verifyExecutionAttestation(att, sandbox.publicKey)
      assert.equal(result.valid, true)
      assert.equal(result.signatureValid, true)
      assert.equal(result.parameterMatch, true)
      assert.equal(result.timingValid, true)
      assert.equal(result.errors.length, 0)
    })
  })


  // ══════════════════════════════════════════════════════════════════
  // 2. Parameter drift (agent changed search query)
  // ══════════════════════════════════════════════════════════════════

  describe('parameter drift detection', () => {
    it('detects query modification as suspicious drift', () => {
      const att = createExecutionAttestation(makeInput({
        intentParameters: { query: 'weather in tokyo', limit: 10 },
        actualParameters: { query: 'how to hack nasa', limit: 10 },
      }), sandbox.privateKey)

      assert.equal(att.match, false)
      assert.ok(att.drift.fields.length > 0)
      assert.equal(att.drift.severity, 'suspicious')
      assert.equal(att.drift.fields.length, 1)
      assert.equal(att.drift.fields[0].field, 'query')
    })

    it('detects target change as critical drift', () => {
      const att = createExecutionAttestation(makeInput({
        intentParameters: { target: 'api.safe.com', method: 'GET' },
        actualParameters: { target: 'api.evil.com', method: 'GET' },
      }), sandbox.privateKey)

      assert.equal(att.match, false)
      assert.equal(att.drift.severity, 'critical')
    })

    it('detects amount change as critical drift', () => {
      const att = createExecutionAttestation(makeInput({
        intentParameters: { recipient: 'alice', amount: 100 },
        actualParameters: { recipient: 'alice', amount: 999999 },
      }), sandbox.privateKey)

      assert.equal(att.drift.severity, 'critical')
      assert.equal(att.drift.fields.length, 1)
      assert.equal(att.drift.fields[0].field, 'amount')
    })

    it('classifies timestamp drift as benign', () => {
      const att = createExecutionAttestation(makeInput({
        intentParameters: { timestamp: '2026-04-01T10:00:00Z', data: 'hello' },
        actualParameters: { timestamp: '2026-04-01T10:00:05Z', data: 'hello' },
      }), sandbox.privateKey)

      assert.equal(att.match, false)
      assert.equal(att.drift.severity, 'benign')
    })

    it('detects multiple field drift with highest severity', () => {
      const att = createExecutionAttestation(makeInput({
        intentParameters: { query: 'safe search', recipient: 'alice@safe.com' },
        actualParameters: { query: 'different search', recipient: 'eve@evil.com' },
      }), sandbox.privateKey)

      // recipient=critical > query=suspicious → severity is critical
      assert.equal(att.drift.severity, 'critical')
      assert.equal(att.drift.fields.length, 2)
    })

    it('detects added fields not in intent', () => {
      const att = createExecutionAttestation(makeInput({
        intentParameters: { query: 'weather' },
        actualParameters: { query: 'weather', exfiltrate: 'secrets.db' },
      }), sandbox.privateKey)

      assert.equal(att.match, false)
      assert.ok(att.drift.fields.some(f => f.field === 'exfiltrate'))
    })

    it('detects removed fields from intent', () => {
      const att = createExecutionAttestation(makeInput({
        intentParameters: { query: 'weather', safetyFlag: true },
        actualParameters: { query: 'weather' },
      }), sandbox.privateKey)

      assert.equal(att.match, false)
      assert.ok(att.drift.fields.some(f => f.field === 'safetyFlag'))
    })
  })


  // ══════════════════════════════════════════════════════════════════
  // 3. Attestation signature verification
  // ══════════════════════════════════════════════════════════════════

  describe('signature verification', () => {
    it('rejects attestation signed by wrong key', () => {
      const att = createExecutionAttestation(makeInput(), sandbox.privateKey)
      // Verify with agent's key instead of sandbox's key
      const result = verifyExecutionAttestation(att, agent.publicKey)
      assert.equal(result.valid, false)
      assert.equal(result.signatureValid, false)
      assert.ok(result.errors.some(e => e.includes('signature invalid')))
    })

    it('rejects tampered attestation', () => {
      const att = createExecutionAttestation(makeInput(), sandbox.privateKey)
      // Tamper with the tool name after signing
      const tampered = { ...att, toolName: 'send_money' }
      const result = verifyExecutionAttestation(tampered, sandbox.publicKey)
      assert.equal(result.valid, false)
      assert.equal(result.signatureValid, false)
    })

    it('each attestation gets unique executionId', () => {
      const att1 = createExecutionAttestation(makeInput(), sandbox.privateKey)
      const att2 = createExecutionAttestation(makeInput(), sandbox.privateKey)
      assert.notEqual(att1.executionId, att2.executionId)
    })
  })


  // ══════════════════════════════════════════════════════════════════
  // 4. Cross-reference with PolicyReceipt (binding)
  // ══════════════════════════════════════════════════════════════════

  describe('receipt binding verification', () => {
    it('validates matching receipt binding', () => {
      const att = createExecutionAttestation(makeInput({
        policyReceiptId: 'pr-abc',
        executionFrameId: 'frame-xyz',
      }), sandbox.privateKey)

      const result = verifyExecutionAttestation(att, sandbox.publicKey, {
        policyReceiptId: 'pr-abc',
        executionFrameId: 'frame-xyz',
      })
      assert.equal(result.valid, true)
      assert.equal(result.receiptBindingValid, true)
    })

    it('detects receipt ID mismatch', () => {
      const att = createExecutionAttestation(makeInput({
        policyReceiptId: 'pr-abc',
      }), sandbox.privateKey)

      const result = verifyExecutionAttestation(att, sandbox.publicKey, {
        policyReceiptId: 'pr-WRONG',
      })
      assert.equal(result.valid, false)
      assert.equal(result.receiptBindingValid, false)
      assert.ok(result.errors.some(e => e.includes('Receipt ID mismatch')))
    })

    it('detects frame ID mismatch', () => {
      const att = createExecutionAttestation(makeInput({
        policyReceiptId: 'pr-abc',
        executionFrameId: 'frame-xyz',
      }), sandbox.privateKey)

      const result = verifyExecutionAttestation(att, sandbox.publicKey, {
        policyReceiptId: 'pr-abc',
        executionFrameId: 'frame-WRONG',
      })
      assert.equal(result.valid, false)
      assert.equal(result.receiptBindingValid, false)
      assert.ok(result.errors.some(e => e.includes('Frame ID mismatch')))
    })

    it('passes when no receipt provided for comparison', () => {
      const att = createExecutionAttestation(makeInput(), sandbox.privateKey)
      const result = verifyExecutionAttestation(att, sandbox.publicKey)
      assert.equal(result.valid, true)
      assert.equal(result.receiptBindingValid, true)
    })
  })


  // ══════════════════════════════════════════════════════════════════
  // 5. Timing validation
  // ══════════════════════════════════════════════════════════════════

  describe('timing validation', () => {
    it('rejects execution that completed before it started', () => {
      const att = createExecutionAttestation(makeInput({
        executionStartedAt: '2026-04-01T10:00:05Z',
        executionCompletedAt: '2026-04-01T10:00:00Z',
      }), sandbox.privateKey)

      const result = verifyExecutionAttestation(att, sandbox.publicKey)
      assert.equal(result.valid, false)
      assert.equal(result.timingValid, false)
    })

    it('accepts zero-duration execution (start === end)', () => {
      const att = createExecutionAttestation(makeInput({
        executionStartedAt: '2026-04-01T10:00:00Z',
        executionCompletedAt: '2026-04-01T10:00:00Z',
      }), sandbox.privateKey)

      const result = verifyExecutionAttestation(att, sandbox.publicKey)
      assert.equal(result.timingValid, true)
    })
  })


  // ══════════════════════════════════════════════════════════════════
  // 6. detectExecutionDrift standalone
  // ══════════════════════════════════════════════════════════════════

  describe('detectExecutionDrift standalone', () => {
    it('returns severity none for matching attestation', () => {
      const att = createExecutionAttestation(makeInput(), sandbox.privateKey)
      const drift = detectExecutionDrift(att)
      assert.equal(drift.severity, 'none')
      assert.equal(drift.fields.length, 0)
    })

    it('returns drift for mismatched attestation', () => {
      const att = createExecutionAttestation(makeInput({
        intentParameters: { query: 'safe' },
        actualParameters: { query: 'malicious' },
      }), sandbox.privateKey)

      const drift = detectExecutionDrift(att)
      assert.ok(drift.severity !== 'none')
      assert.equal(drift.fields.length, 1)
    })
  })


  // ══════════════════════════════════════════════════════════════════
  // 7. Custom drift rules
  // ══════════════════════════════════════════════════════════════════

  describe('custom drift rules', () => {
    it('applies custom rules for domain-specific fields', () => {
      const att = createExecutionAttestation(
        makeInput({
          intentParameters: { model: 'gpt-4', temperature: 0.7 },
          actualParameters: { model: 'gpt-4', temperature: 0.9 },
        }),
        sandbox.privateKey,
        {
          driftRules: [
            { field: 'temperature', severity: 'benign', reason: 'Model temp varies' },
            { field: 'model', severity: 'critical', reason: 'Model swap is critical' },
            { field: '*', severity: 'suspicious', reason: 'Default' },
          ],
        }
      )

      assert.equal(att.drift.severity, 'benign')
      assert.equal(att.drift.fields[0].field, 'temperature')
    })

    it('classifies nonce as critical in payment context (desiorac field-semantic)', () => {
      const att = createExecutionAttestation(
        makeInput({
          intentParameters: { nonce: 'abc', amount: 100 },
          actualParameters: { nonce: 'xyz', amount: 100 },
        }),
        sandbox.privateKey,
        {
          executionContext: 'payment',
          driftRules: [
            { field: 'nonce', context: 'payment', severity: 'critical', reason: 'Nonce in payment is replay-critical' },
            { field: 'nonce', context: '*', severity: 'benign', reason: 'Nonce generally benign' },
            { field: '*', severity: 'suspicious', reason: 'Default' },
          ],
        }
      )
      assert.equal(att.drift.severity, 'critical')
    })

    it('classifies nonce as benign in search context', () => {
      const att = createExecutionAttestation(
        makeInput({
          intentParameters: { nonce: 'abc', amount: 100 },
          actualParameters: { nonce: 'xyz', amount: 100 },
        }),
        sandbox.privateKey,
        {
          executionContext: 'search',
          driftRules: [
            { field: 'nonce', context: 'payment', severity: 'critical', reason: 'Nonce in payment is replay-critical' },
            { field: 'nonce', context: '*', severity: 'benign', reason: 'Nonce generally benign' },
            { field: '*', severity: 'suspicious', reason: 'Default' },
          ],
        }
      )
      assert.equal(att.drift.severity, 'benign')
    })
  })


  // ══════════════════════════════════════════════════════════════════
  // 8. Attestor types
  // ══════════════════════════════════════════════════════════════════

  describe('attestor types', () => {
    for (const aType of ['sandbox', 'container', 'runtime', 'gateway', 'orchestrator'] as const) {
      it(`accepts attestorType=${aType}`, () => {
        const att = createExecutionAttestation(
          makeInput({ attestorType: aType }),
          sandbox.privateKey
        )
        assert.equal(att.attestorType, aType)
        const result = verifyExecutionAttestation(att, sandbox.publicKey)
        assert.equal(result.valid, true)
      })
    }
  })


  // ══════════════════════════════════════════════════════════════════
  // 9. Result hash integrity
  // ══════════════════════════════════════════════════════════════════

  describe('result hash integrity', () => {
    it('produces different result hashes for different results', () => {
      const att1 = createExecutionAttestation(makeInput({
        actualResult: { data: 'result-A' },
      }), sandbox.privateKey)

      const att2 = createExecutionAttestation(makeInput({
        actualResult: { data: 'result-B' },
      }), sandbox.privateKey)

      assert.notEqual(att1.resultHash, att2.resultHash)
    })

    it('produces same parameter hash for identical params regardless of key order', () => {
      const att1 = createExecutionAttestation(makeInput({
        actualParameters: { a: 1, b: 2 },
        intentParameters: { a: 1, b: 2 },
      }), sandbox.privateKey)

      const att2 = createExecutionAttestation(makeInput({
        actualParameters: { b: 2, a: 1 },
        intentParameters: { b: 2, a: 1 },
      }), sandbox.privateKey)

      // Both should match (canonical serialization sorts keys)
      assert.equal(att1.match, true)
      assert.equal(att2.match, true)
      assert.equal(att1.parameterHash, att2.parameterHash)
    })
  })


  // ══════════════════════════════════════════════════════════════════
  // 10. DEFAULT_DRIFT_RULES coverage
  // ══════════════════════════════════════════════════════════════════

  describe('DEFAULT_DRIFT_RULES', () => {
    it('has rules for known critical fields', () => {
      const criticalFields = DEFAULT_DRIFT_RULES.filter(r => r.severity === 'critical')
      const criticalNames = criticalFields.map(r => r.field)
      assert.ok(criticalNames.includes('target'))
      assert.ok(criticalNames.includes('recipient'))
      assert.ok(criticalNames.includes('amount'))
    })

    it('has wildcard fallback rule', () => {
      const wildcard = DEFAULT_DRIFT_RULES.find(r => r.field === '*')
      assert.ok(wildcard)
      assert.equal(wildcard!.severity, 'suspicious')
    })

    it('unknown field falls through to wildcard as suspicious', () => {
      const att = createExecutionAttestation(makeInput({
        intentParameters: { obscureField: 'a' },
        actualParameters: { obscureField: 'b' },
      }), sandbox.privateKey)

      assert.equal(att.drift.severity, 'suspicious')
    })
  })


  // ══════════════════════════════════════════════════════════════════
  // 11. Context-aware drift classification (desiorac qntm#6)
  // ══════════════════════════════════════════════════════════════════

  describe('context-aware drift classification', () => {
    it('classifies nonce as critical in payment context', () => {
      const att = createExecutionAttestation(
        makeInput({
          intentParameters: { nonce: 'abc', amount: 100 },
          actualParameters: { nonce: 'xyz', amount: 100 },
        }),
        sandbox.privateKey,
        {
          executionContext: 'payment',
          driftRules: [
            { field: 'nonce', context: 'payment', severity: 'critical', reason: 'Nonce in payment is replay-critical' },
            { field: 'nonce', context: '*', severity: 'benign', reason: 'Nonce normally varies' },
            { field: '*', severity: 'suspicious', reason: 'Default' },
          ],
        }
      )
      assert.equal(att.drift.severity, 'critical')
    })

    it('classifies nonce as benign in search context', () => {
      const att = createExecutionAttestation(
        makeInput({
          intentParameters: { nonce: 'abc', query: 'test' },
          actualParameters: { nonce: 'xyz', query: 'test' },
        }),
        sandbox.privateKey,
        {
          executionContext: 'search',
          driftRules: [
            { field: 'nonce', context: 'payment', severity: 'critical', reason: 'Nonce in payment is replay-critical' },
            { field: 'nonce', context: '*', severity: 'benign', reason: 'Nonce normally varies' },
            { field: '*', severity: 'suspicious', reason: 'Default' },
          ],
        }
      )
      assert.equal(att.drift.severity, 'benign')
    })

    it('falls through to wildcard context when no specific match', () => {
      const att = createExecutionAttestation(
        makeInput({
          intentParameters: { data: 'a' },
          actualParameters: { data: 'b' },
        }),
        sandbox.privateKey,
        {
          executionContext: 'unknown_context',
          driftRules: [
            { field: 'data', context: 'payment', severity: 'critical', reason: 'Data in payment' },
            { field: '*', severity: 'suspicious', reason: 'Default' },
          ],
        }
      )
      assert.equal(att.drift.severity, 'suspicious')
    })
  })

}) // end top-level describe
