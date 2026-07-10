// Copyright (c) 2026 Tymofii Pidlisnyi
// SPDX-License-Identifier: Apache-2.0
// ══════════════════════════════════════════════════════════════════
// CyclesEvidence signer-AUTHORITY conformance (#43, verify-path wiring)
// ══════════════════════════════════════════════════════════════════
// Byte-for-byte vectors: the 13 Cycles golden envelopes (copied verbatim
// from runcycles/cycles-server-events, the same fixtures the Cycles
// reference verifier and canonicalizer validate against) plus the
// published JWK Set. Proves a key RESOLVED from the server's JWK Set —
// under the issuance-time validity window — verifies the envelope's own
// Ed25519 signature → `authentic`, and that each degraded path maps to its
// DISTINCT disposition (binding_only only for a valid raw-hex signature with
// no resolver; signer_resolution_failed / signer_authority_failed /
// signature_invalid otherwise) per the #43 five-disposition model.
//
// Edge coverage requested on the cycles-server#194 / APS#46 merge:
//   - open-ended cycles_exp_ms (active key)  → the golden JWKS key
//   - rotation overlap, two in-window keys    → ambiguous fails closed
//   - path/fragment-bearing server_id         → golden raw-hex (/v1 path)
//                                                + a signed did:cycles round-trip
// ══════════════════════════════════════════════════════════════════

import { describe, it } from 'node:test'
import assert from 'node:assert/strict'
import { readFileSync } from 'node:fs'
import { CyclesKeyResolver } from '../../../src/v2/key-resolution/index.js'
import { verifyCyclesEvidenceSignerAuthority } from '../../../src/v2/payment-rails/cycles/index.js'
import { canonicalizeJCS } from '../../../src/core/canonical-jcs.js'
import { sha256Hex } from '../../../src/v2/payment-rails/canonicalize.js'
import { sign, publicKeyFromPrivate } from '../../../src/crypto/keys.js'

const VEC_DIR = new URL('./cycles-evidence-vectors/', import.meta.url)
function load(name: string): Record<string, unknown> {
  return JSON.parse(readFileSync(new URL(name, VEC_DIR), 'utf8'))
}

/** A KeyResolver whose JWKS transport returns a fixed body (no real egress). */
function resolverServing(jwks: unknown, status = 200): CyclesKeyResolver {
  const impl = (async () => ({
    ok: status >= 200 && status < 300,
    status,
    json: async () => jwks,
  } as unknown as Response)) as unknown as typeof fetch
  return new CyclesKeyResolver({ fetchImpl: impl })
}
function throwingResolver(): CyclesKeyResolver {
  const impl = (async () => { throw new Error('ECONNREFUSED (simulated)') }) as unknown as typeof fetch
  return new CyclesKeyResolver({ fetchImpl: impl })
}

const GOLDEN = [
  '01-decide-allow', '02-reserve-allow', '03-reserve-dry-run-deny',
  '04-reserve-allow-with-caps', '05-commit-success', '06-release-success',
  '07-release-with-reason', '08-reserve-allow-no-trace-id',
  '09-decide-risk-points-allow', '10-reserve-credits-allow',
  '11-reserve-live-budget-exceeded', '12-decide-live-forbidden',
  '13-commit-with-metrics',
]
const JWKS = load('cycles-jwks.json')                       // active key, open-ended exp

// ── Golden vectors → authentic (raw-hex signer; server_id carries /v1) ──
describe('CyclesEvidence authority: 13 golden vectors resolve to authentic', () => {
  for (const name of GOLDEN) {
    it(`${name} → authentic (key resolved from JWKS under the window)`, async () => {
      const env = load(`${name}.json`)
      const res = await verifyCyclesEvidenceSignerAuthority(env, {
        cyclesKeyResolver: resolverServing(JWKS),
      })
      assert.equal(res.disposition, 'authentic', res.reason)
      assert.equal(res.resolvedKid, (JWKS.keys as Array<{ kid: string }>)[0].kid)
    })
  }
})

// ── Strict, DISTINCT dispositions for each degraded path ──
describe('CyclesEvidence authority: distinct dispositions per failure mode', () => {
  const env = () => load('02-reserve-allow.json')

  it('no resolver + raw-hex signer + VALID signature → binding_only', async () => {
    const res = await verifyCyclesEvidenceSignerAuthority(env(), {})
    assert.equal(res.disposition, 'binding_only')
  })

  it('no resolver + raw-hex signer + TAMPERED signature → signature_invalid (binding_only implies valid sig)', async () => {
    const e = env()
    const sig = e.signature as string
    e.signature = (sig[0] === '0' ? '1' : '0') + sig.slice(1)
    const res = await verifyCyclesEvidenceSignerAuthority(e, {})
    assert.equal(res.disposition, 'signature_invalid')
  })

  it('unreachable JWKS → signer_resolution_failed (not a forgery, not authority)', async () => {
    const res = await verifyCyclesEvidenceSignerAuthority(env(), { cyclesKeyResolver: throwingResolver() })
    assert.equal(res.disposition, 'signer_resolution_failed')
  })

  it('a resolver that REJECTS → signer_resolution_failed (verify path never throws)', async () => {
    // A non-conformant resolver that rejects its promise (the reference
    // CyclesKeyResolver never does, but a caller-supplied one might).
    const rejecting = {
      canResolve: () => true,
      resolve: async () => { throw new Error('resolver blew up') },
    } as unknown as CyclesKeyResolver
    const res = await verifyCyclesEvidenceSignerAuthority(env(), { cyclesKeyResolver: rejecting })
    assert.equal(res.disposition, 'signer_resolution_failed')
  })

  it('signer key absent from the set → signer_authority_failed', async () => {
    const other = { ...JWKS, keys: [{ ...(JWKS.keys as object[])[0], x: 'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA' }] }
    const res = await verifyCyclesEvidenceSignerAuthority(env(), { cyclesKeyResolver: resolverServing(other) })
    assert.equal(res.disposition, 'signer_authority_failed')
  })

  it('key window does not cover issued_at_ms → signer_authority_failed', async () => {
    const e = env()
    const future = { ...JWKS, keys: [{ ...(JWKS.keys as Array<Record<string, unknown>>)[0], cycles_nbf_ms: (e.issued_at_ms as number) + 1 }] }
    const res = await verifyCyclesEvidenceSignerAuthority(e, { cyclesKeyResolver: resolverServing(future) })
    assert.equal(res.disposition, 'signer_authority_failed')
  })

  it('tampered signature → signature_invalid (NOT binding_only)', async () => {
    const e = env()
    const sig = e.signature as string
    e.signature = (sig[0] === '0' ? '1' : '0') + sig.slice(1)
    const res = await verifyCyclesEvidenceSignerAuthority(e, { cyclesKeyResolver: resolverServing(JWKS) })
    assert.equal(res.disposition, 'signature_invalid')
  })

  it('wrong evidence_id (does not re-derive) → signature_invalid, even with an authorized key', async () => {
    // A valid signature over a WRONG evidence_id must NOT read as authentic:
    // the content id is re-derived and byte-compared first.
    const e = env()
    e.evidence_id = '0'.repeat(64)
    const res = await verifyCyclesEvidenceSignerAuthority(e, { cyclesKeyResolver: resolverServing(JWKS) })
    assert.equal(res.disposition, 'signature_invalid')
  })
})

// ── Rotation overlap: two in-window keys ──
describe('CyclesEvidence authority: rotation overlap (two in-window keys)', () => {
  it('two in-window keys, only one carries the signer → authentic', async () => {
    const k0 = (JWKS.keys as Array<Record<string, unknown>>)[0]
    const decoy = { ...k0, kid: 'decoy', x: 'BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBA' }
    const res = await verifyCyclesEvidenceSignerAuthority(load('02-reserve-allow.json'), {
      cyclesKeyResolver: resolverServing({ keys: [decoy, k0] }),
    })
    assert.equal(res.disposition, 'authentic', res.reason)
  })

  it('two in-window keys BOTH carrying the signer → signer_authority_failed (ambiguous, fail closed)', async () => {
    const k0 = (JWKS.keys as Array<Record<string, unknown>>)[0]
    const dup = { ...k0, kid: 'rotated' } // same x, different kid, both in-window
    const res = await verifyCyclesEvidenceSignerAuthority(load('02-reserve-allow.json'), {
      cyclesKeyResolver: resolverServing({ keys: [k0, dup] }),
    })
    assert.equal(res.disposition, 'signer_authority_failed')
  })
})

// ── did:cycles round-trip: hash-binding + path-bearing server_id ──
describe('CyclesEvidence authority: did:cycles signer (hash-binding, path server_id)', () => {
  // RFC 8032 Test-1 seed → its public key + base64url x.
  const SEED = '9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60'
  const PUB = publicKeyFromPrivate(SEED)
  const X = Buffer.from(PUB, 'hex').toString('base64url')
  const SERVER_ID = 'https://cyc.test/v1'                    // carries a path
  const HASH = sha256Hex(SERVER_ID)
  const KID = '2026-06'

  function signedDidCyclesEnvelope() {
    const env: Record<string, unknown> = {
      schema_version: 'cycles-evidence/v0.1',
      artifact_type: 'reserve',
      server_id: SERVER_ID,
      signer_did: `did:cycles:${HASH}#${KID}`,
      issued_at_ms: 1810000000100,
      payload: { reserve: { request: {}, response: {} } },
      evidence_id: '',
      signature: '',
    }
    // cycles recipe: evidence_id = sha256(JCS with id+sig empty), then sign the
    // JCS with id populated + sig empty.
    env.evidence_id = sha256Hex(canonicalizeJCS({ ...env, evidence_id: '', signature: '' }))
    env.signature = sign(canonicalizeJCS({ ...env, signature: '' }), SEED)
    return env
  }
  const jwks = { keys: [{ kty: 'OKP', crv: 'Ed25519', alg: 'EdDSA', x: X, kid: KID, cycles_nbf_ms: 0, status: 'active' }] }

  it('binds sha256(server_id), resolves under the window, verifies → authentic', async () => {
    const res = await verifyCyclesEvidenceSignerAuthority(signedDidCyclesEnvelope(), {
      cyclesKeyResolver: resolverServing(jwks),
    })
    assert.equal(res.disposition, 'authentic', res.reason)
    assert.equal(res.resolvedKid, KID)
  })

  it('DID subject hash != sha256(server_id) → signer_authority_failed (cross-server confusion blocked)', async () => {
    // A CONSISTENTLY-signed envelope (evidence_id re-derives) whose did:cycles
    // subject commits to a DIFFERENT server_id than the envelope's own. The
    // sha256 binding is what fails — not content integrity.
    const wrongHash = sha256Hex('https://other.test/v1')
    const env: Record<string, unknown> = {
      schema_version: 'cycles-evidence/v0.1', artifact_type: 'reserve',
      server_id: SERVER_ID, signer_did: `did:cycles:${wrongHash}#${KID}`,
      issued_at_ms: 1810000000100, payload: { reserve: { request: {}, response: {} } },
      evidence_id: '', signature: '',
    }
    env.evidence_id = sha256Hex(canonicalizeJCS({ ...env, evidence_id: '', signature: '' }))
    env.signature = sign(canonicalizeJCS({ ...env, signature: '' }), SEED)
    const res = await verifyCyclesEvidenceSignerAuthority(env, { cyclesKeyResolver: resolverServing(jwks) })
    assert.equal(res.disposition, 'signer_authority_failed')
  })

  it('did:cycles signer with NO resolver → signer_authority_failed (not checkable, never binding_only)', async () => {
    const res = await verifyCyclesEvidenceSignerAuthority(signedDidCyclesEnvelope(), {})
    assert.equal(res.disposition, 'signer_authority_failed')
  })

  it('selected key (by kid) with malformed x → signer_authority_failed (not resolution_failed)', async () => {
    // The kid matches but its x is not a 32-byte key: a malformed selected KEY
    // is an authority failure, distinct from an unparseable JWK Set body.
    const badKey = { kty: 'OKP', crv: 'Ed25519', alg: 'EdDSA', x: 'AA', kid: KID, cycles_nbf_ms: 0, status: 'active' }
    const res = await verifyCyclesEvidenceSignerAuthority(signedDidCyclesEnvelope(), {
      cyclesKeyResolver: resolverServing({ keys: [badKey] }),
    })
    assert.equal(res.disposition, 'signer_authority_failed')
  })
})

// ── Verified signer identity surfaced on authentic / binding_only (#43) ──
describe('CyclesEvidence authority: signerDid surfacing', () => {
  const SIGNER = 'ec52b49b81eb29ef6f62947cade245c715bf943b7ef2a5f2789288574466fc43'

  it('authentic surfaces the verified signerDid alongside resolvedKid', async () => {
    const res = await verifyCyclesEvidenceSignerAuthority(load('02-reserve-allow.json'), {
      cyclesKeyResolver: resolverServing(JWKS),
    })
    assert.equal(res.disposition, 'authentic', res.reason)
    assert.equal(res.signerDid, SIGNER)
    assert.equal(res.resolvedKid, (JWKS.keys as Array<{ kid: string }>)[0].kid)
  })

  it('binding_only surfaces the verified signerDid (identity, not endorsement)', async () => {
    const res = await verifyCyclesEvidenceSignerAuthority(load('02-reserve-allow.json'), {})
    assert.equal(res.disposition, 'binding_only')
    assert.equal(res.signerDid, SIGNER)
  })

  it('non-verified dispositions carry no signerDid', async () => {
    const e = load('02-reserve-allow.json')
    e.evidence_id = '0'.repeat(64) // tamper → signature_invalid before any sig check passes
    const res = await verifyCyclesEvidenceSignerAuthority(e, { cyclesKeyResolver: resolverServing(JWKS) })
    assert.equal(res.disposition, 'signature_invalid')
    assert.equal(res.signerDid, undefined)
  })
})

// ── expectedEvidenceSigner pin: fail closed on mismatch (#43) ──
describe('CyclesEvidence authority: expectedEvidenceSigner pin', () => {
  const SIGNER = 'ec52b49b81eb29ef6f62947cade245c715bf943b7ef2a5f2789288574466fc43'
  const OTHER = 'f'.repeat(64)

  it('pin matches → authentic stands', async () => {
    const res = await verifyCyclesEvidenceSignerAuthority(load('02-reserve-allow.json'), {
      cyclesKeyResolver: resolverServing(JWKS),
      expectedEvidenceSigner: SIGNER,
    })
    assert.equal(res.disposition, 'authentic', res.reason)
  })

  it('pin mismatches an otherwise authentic envelope → signer_authority_failed (fail closed)', async () => {
    const res = await verifyCyclesEvidenceSignerAuthority(load('02-reserve-allow.json'), {
      cyclesKeyResolver: resolverServing(JWKS),
      expectedEvidenceSigner: OTHER,
    })
    assert.equal(res.disposition, 'signer_authority_failed')
  })

  it('pin mismatches a binding_only envelope → signer_authority_failed (fail closed)', async () => {
    const res = await verifyCyclesEvidenceSignerAuthority(load('02-reserve-allow.json'), {
      expectedEvidenceSigner: OTHER,
    })
    assert.equal(res.disposition, 'signer_authority_failed')
  })

  it('empty-string pin is honored (presence, not truthiness) → signer_authority_failed', async () => {
    // A supplied-but-empty pin can never equal a non-empty signer_did; it must
    // fail closed, not be treated as "no pin".
    const res = await verifyCyclesEvidenceSignerAuthority(load('02-reserve-allow.json'), {
      cyclesKeyResolver: resolverServing(JWKS),
      expectedEvidenceSigner: '',
    })
    assert.equal(res.disposition, 'signer_authority_failed')
  })
})

// ── maxEvidenceClockSkewMs: opt-in freshness bound (#43 defense-in-depth) ──
describe('CyclesEvidence authority: maxEvidenceClockSkewMs drift bound', () => {
  const ISSUED = 1810000000100 // 02-reserve-allow.json issued_at_ms

  it('issued_at_ms within the bound → authentic (bound does not interfere)', async () => {
    const res = await verifyCyclesEvidenceSignerAuthority(load('02-reserve-allow.json'), {
      cyclesKeyResolver: resolverServing(JWKS),
      now: new Date(ISSUED + 30_000),
      maxEvidenceClockSkewMs: 60_000,
    })
    assert.equal(res.disposition, 'authentic', res.reason)
  })

  it('issued_at_ms beyond the bound → signer_authority_failed, before key resolution', async () => {
    const res = await verifyCyclesEvidenceSignerAuthority(load('02-reserve-allow.json'), {
      cyclesKeyResolver: resolverServing(JWKS),
      now: new Date(ISSUED + 600_000), // 10 min drift
      maxEvidenceClockSkewMs: 60_000,
    })
    assert.equal(res.disposition, 'signer_authority_failed')
  })

  it('backdated issued_at_ms beyond the bound → signer_authority_failed (both directions)', async () => {
    const res = await verifyCyclesEvidenceSignerAuthority(load('02-reserve-allow.json'), {
      cyclesKeyResolver: resolverServing(JWKS),
      now: new Date(ISSUED - 600_000),
      maxEvidenceClockSkewMs: 60_000,
    })
    assert.equal(res.disposition, 'signer_authority_failed')
  })

  it('NaN bound → signer_authority_failed (degenerate config fails closed, never skips)', async () => {
    const res = await verifyCyclesEvidenceSignerAuthority(load('02-reserve-allow.json'), {
      cyclesKeyResolver: resolverServing(JWKS),
      now: new Date(ISSUED),
      maxEvidenceClockSkewMs: NaN,
    })
    assert.equal(res.disposition, 'signer_authority_failed')
  })

  it('invalid now Date → signer_authority_failed (non-finite clock fails closed)', async () => {
    const res = await verifyCyclesEvidenceSignerAuthority(load('02-reserve-allow.json'), {
      cyclesKeyResolver: resolverServing(JWKS),
      now: new Date('not-a-date'),
      maxEvidenceClockSkewMs: 60_000,
    })
    assert.equal(res.disposition, 'signer_authority_failed')
  })
})
