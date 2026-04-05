import { describe, it } from 'node:test'
import assert from 'node:assert/strict'
import { classifyEvidenceQuality, evidenceQualityToGrade } from '../src/core/attestation.js'

describe('Evidence-Based Grade Assignment (A2A#1712 — VCOne-AI)', () => {
  it('did:key with no evidence → Grade 0', () => {
    const q = classifyEvidenceQuality({ method: 'did:key' })
    assert.equal(q, 'none')
    assert.equal(evidenceQualityToGrade(q), 0)
  })

  it('did:key with TPM quote evidence → Grade 2 (the key fix)', () => {
    const q = classifyEvidenceQuality({
      method: 'did:key',
      evidence: { tpm_quote: 'abc123...' }
    })
    assert.equal(q, 'infrastructure')
    assert.equal(evidenceQualityToGrade(q), 2)
  })

  it('did:key with issuer countersignature → Grade 1', () => {
    const q = classifyEvidenceQuality({
      method: 'did:key',
      hasIssuerSignature: true
    })
    assert.equal(q, 'issuer_vouched')
    assert.equal(evidenceQualityToGrade(q), 1)
  })

  it('SPIFFE with no special evidence → Grade 2 (preserves existing behavior)', () => {
    const q = classifyEvidenceQuality({ method: 'spiffe' })
    assert.equal(q, 'infrastructure')
    assert.equal(evidenceQualityToGrade(q), 2)
  })

  it('SPIFFE URI prefix → Grade 2', () => {
    const q = classifyEvidenceQuality({ method: 'spiffe://prod.example.com/workload' })
    assert.equal(q, 'infrastructure')
  })

  it('any method with principal binding → Grade 3', () => {
    const q = classifyEvidenceQuality({
      method: 'did:key',
      hasPrincipalBinding: true,
      hasIssuerSignature: true
    })
    assert.equal(q, 'principal_bound')
    assert.equal(evidenceQualityToGrade(q), 3)
  })

  it('did:key with hardware_attestation evidence → Grade 2', () => {
    const q = classifyEvidenceQuality({
      method: 'did:key',
      evidence: { hardware_attestation: { vendor: 'intel', type: 'sgx' } }
    })
    assert.equal(q, 'infrastructure')
    assert.equal(evidenceQualityToGrade(q), 2)
  })

  it('unknown method with infrastructure_binding evidence → Grade 2', () => {
    const q = classifyEvidenceQuality({
      method: 'did:custom',
      evidence: { infrastructure_binding: true }
    })
    assert.equal(q, 'infrastructure')
    assert.equal(evidenceQualityToGrade(q), 2)
  })

  it('tee_proof evidence → Grade 2', () => {
    const q = classifyEvidenceQuality({
      method: 'oauth',
      evidence: { tee_proof: 'report...' }
    })
    assert.equal(q, 'infrastructure')
  })

  it('camelCase evidence keys also detected (tpmQuote, hardwareAttestation)', () => {
    assert.equal(
      classifyEvidenceQuality({ method: 'did:key', evidence: { tpmQuote: 'x' } }),
      'infrastructure'
    )
    assert.equal(
      classifyEvidenceQuality({ method: 'did:key', evidence: { hardwareAttestation: {} } }),
      'infrastructure'
    )
  })

  it('backward compat: no evidence + no flags → Grade 0', () => {
    assert.equal(classifyEvidenceQuality({}), 'none')
    assert.equal(classifyEvidenceQuality({ method: 'did:web' }), 'none')
  })

  it('backward compat: issuer signature alone → Grade 1', () => {
    assert.equal(
      classifyEvidenceQuality({ method: 'did:web', hasIssuerSignature: true }),
      'issuer_vouched'
    )
  })

  it('precedence: principal_bound beats infrastructure beats issuer_vouched', () => {
    // principal beats everything
    assert.equal(
      classifyEvidenceQuality({
        method: 'spiffe',
        hasIssuerSignature: true,
        hasPrincipalBinding: true,
        evidence: { tpm_quote: 'x' }
      }),
      'principal_bound'
    )
    // infrastructure beats issuer_vouched
    assert.equal(
      classifyEvidenceQuality({
        method: 'did:key',
        hasIssuerSignature: true,
        evidence: { tpm_quote: 'x' }
      }),
      'infrastructure'
    )
  })

  it('null/undefined evidence values are not treated as present', () => {
    assert.equal(
      classifyEvidenceQuality({ method: 'did:key', evidence: { tpm_quote: null } }),
      'none'
    )
    assert.equal(
      classifyEvidenceQuality({ method: 'did:key', evidence: { tpm_quote: undefined } }),
      'none'
    )
  })

  it('evidenceQualityToGrade covers all quality levels', () => {
    assert.equal(evidenceQualityToGrade('none'), 0)
    assert.equal(evidenceQualityToGrade('issuer_vouched'), 1)
    assert.equal(evidenceQualityToGrade('infrastructure'), 2)
    assert.equal(evidenceQualityToGrade('principal_bound'), 3)
  })
})
