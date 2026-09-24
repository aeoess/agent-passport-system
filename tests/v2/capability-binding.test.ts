// Copyright (c) 2026 Tymofii Pidlisnyi
// SPDX-License-Identifier: Apache-2.0
//
// Conformance and cross-language parity for the PROPOSED capability-binding module.
//
// Every expectation comes from conformance/capability-binding/v0/vectors.json, which is the
// SHARED fixture: the Python SDK vendors a byte-identical copy and runs the same cases
// through its own port. Expectations are hand specified in the vectors, never computed by
// the code under test, so the test is not circular. The file's SHA-256 is pinned in both
// repositories, so the two copies can be shown identical without either repo importing the
// other.
//
// The identifier records are stored UNSIGNED and are signed here, by this SDK's own `sign`
// over this SDK's own `identifierRecordSignedBytes`. That is deliberate: a canonical-byte
// divergence between the two SDKs shows up as a failed signature check in one of them
// rather than as two runners agreeing on a stored blob neither of them produced.

import { test, describe } from 'node:test'
import assert from 'node:assert/strict'
import { createHash } from 'node:crypto'
import { readFileSync } from 'node:fs'
import { dirname, join } from 'node:path'
import { fileURLToPath } from 'node:url'

import {
  CAPABILITY_BINDING_REASON_CODES,
  IDENTIFIER_CONTINUITY_REASON_CODES,
  CAPABILITY_METADATA_DOMAIN_CBD_V0,
  IDENTIFIER_BINDING_UNSIGNED_FIELDS,
  IDENTIFIER_RETENTION_UNSIGNED_FIELDS,
  CapabilityBindingError,
  capabilityImplementationDigest,
  capabilityMetadataDigest,
  capabilityPinIsEmpty,
  capabilityPinScopeGrants,
  evaluateCapabilityBinding,
  evaluateIdentifierContinuity,
  identifierControllerPinScopeGrant,
  identifierDependencyScopeGrant,
  identifierRecordSignedBytes,
  observeToolAttestation,
  parseCapabilityPinFromScopeGrants,
  parseIdentifierControllerPins,
  projectBoundaryOutcomeToCandidateV0,
  referentBindingResult,
  toolScopeGrant,
  type CapabilityPin,
  type IdentifierBindingRecord,
  type IdentifierRetentionRecord,
  type ToolAttestationObservation,
} from '../../src/v2/capability-binding/index.js'
import { BOUNDARY_OUTCOMES, ESTABLISHMENT_GAPS } from '../../src/v2/lifecycle-state/index.js'
import { createToolRegistryEntry, verifyToolIntegrity } from '../../src/core/tool-integrity.js'
import { generateKeyPair, sign } from '../../src/crypto/keys.js'

const here = dirname(fileURLToPath(import.meta.url))
const vectorsPath = join(here, '..', '..', 'conformance', 'capability-binding', 'v0', 'vectors.json')
const vectorsBytes = readFileSync(vectorsPath)

/** Pinned so the Python SDK's vendored copy can be shown byte identical. If this moves, the
 *  Python repo's copy and its own pin move with it, in the same change. */
const VECTORS_SHA256 = 'd25efe67c9b065caa72045613430bb238b52aaafe8c0c0aa354bb31696cf3829'

interface ExpectedBinding {
  outcome: string
  continuity: string
  reason_code: string
  missing?: string[]
  controller_at_instant?: string | null
}

interface Vectors {
  profile: string
  status: string
  tool_name: string
  metadata_digest_domain: string
  implementation_digest_cases: Array<{ label: string; implementation: string; expected: string }>
  metadata_digest_cases: Array<{ label: string; metadata: unknown; expected: string }>
  metadata_digest_domain_required: { error_code: string }
  scope_grant_parse_cases: Array<{
    label: string
    grants: string[]
    tool_name: string
    expected: CapabilityPin | null
  }>
  scope_grant_write_cases: Array<{
    label: string
    pin: CapabilityPin
    expected?: string[]
    expected_error_code?: string
  }>
  record_signed_bytes_cases: Array<{
    label: string
    record: Record<string, unknown>
    unsigned_fields: string[]
    expected: string
  }>
  capability_binding_cases: Array<{
    id: string
    note: string
    input: {
      requestedToolName: string
      grantedScopes: string[]
      requiredScopes?: string[]
      pin: CapabilityPin | null
      attestation: ToolAttestationObservation | null
      observedImplementationDigest: string | null
      observedMetadataDigest: string | null
    }
    expected: ExpectedBinding
  }>
  identifier_continuity: {
    custodian_private_keys: Record<string, string>
    custodian_public_keys: Record<string, string>
    custodian_standing: Record<string, string>
    invalid_signature_literal: string
    cases: Array<{
      id: string
      note: string
      input: {
        identifierKind: string
        identifier: string
        grantedScopes: string[]
        grantIssuedAt: string
        at: string
        bindings: Array<{
          record: Record<string, unknown>
          sign_as: string | null
          signature_literal?: string
        }>
        retentions: Array<{
          record: Record<string, unknown>
          sign_as: string | null
          signature_literal?: string
        }>
        custodian_standing_override?: Record<string, string>
      }
      expected: ExpectedBinding
    }>
  }
}

const vectors = JSON.parse(vectorsBytes.toString('utf8')) as Vectors
const ic = vectors.identifier_continuity

function assertBinding(actual: Record<string, unknown>, expected: ExpectedBinding, id: string): void {
  assert.equal(actual.outcome, expected.outcome, `${id}: outcome`)
  assert.equal(actual.continuity, expected.continuity, `${id}: continuity`)
  assert.equal(actual.reason_code, expected.reason_code, `${id}: reason_code`)
  if (expected.missing === undefined) {
    assert.equal(actual.missing, undefined, `${id}: missing must be absent`)
  } else {
    assert.deepEqual([...(actual.missing as string[])], expected.missing, `${id}: missing`)
  }
  if ('controller_at_instant' in expected) {
    assert.equal(actual.controller_at_instant, expected.controller_at_instant, `${id}: controller`)
  }
}

describe('capability-binding: shared fixture', () => {
  test('the vectors file is the pinned bytes', () => {
    assert.equal(createHash('sha256').update(vectorsBytes).digest('hex'), VECTORS_SHA256)
  })

  test('the fixture states its own specification position', () => {
    assert.equal(vectors.profile, 'aps-capability-binding-v0')
    assert.equal(vectors.status, 'candidate_against_proposed')
  })

  test('every reason code the fixture expects is in the module enumeration', () => {
    const capability = new Set<string>(CAPABILITY_BINDING_REASON_CODES)
    for (const c of vectors.capability_binding_cases) {
      assert.ok(capability.has(c.expected.reason_code), `${c.id}: ${c.expected.reason_code}`)
    }
    const identifier = new Set<string>(IDENTIFIER_CONTINUITY_REASON_CODES)
    for (const c of ic.cases) {
      assert.ok(identifier.has(c.expected.reason_code), `${c.id}: ${c.expected.reason_code}`)
    }
  })

  test('every reason code in the module enumeration is exercised by the fixture', () => {
    const used = new Set(vectors.capability_binding_cases.map(c => c.expected.reason_code))
    for (const code of CAPABILITY_BINDING_REASON_CODES) {
      assert.ok(used.has(code), `unexercised capability reason code: ${code}`)
    }
    const usedId = new Set(ic.cases.map(c => c.expected.reason_code))
    for (const code of IDENTIFIER_CONTINUITY_REASON_CODES) {
      assert.ok(usedId.has(code), `unexercised identifier reason code: ${code}`)
    }
  })

  test('every expected outcome is a lifecycle-state boundary outcome, never an artifact verdict', () => {
    const outcomes = new Set<string>(BOUNDARY_OUTCOMES)
    for (const c of [...vectors.capability_binding_cases, ...ic.cases]) {
      assert.ok(outcomes.has(c.expected.outcome), `${c.id}: ${c.expected.outcome}`)
      for (const gap of c.expected.missing ?? []) {
        assert.ok((ESTABLISHMENT_GAPS as readonly string[]).includes(gap), `${c.id}: ${gap}`)
      }
    }
  })
})

describe('capability-binding: digests', () => {
  for (const c of vectors.implementation_digest_cases) {
    test(`implementation digest: ${c.label}`, () => {
      assert.equal(capabilityImplementationDigest(c.implementation), c.expected)
    })
  }

  for (const c of vectors.metadata_digest_cases) {
    test(`metadata digest: ${c.label}`, () => {
      assert.equal(capabilityMetadataDigest(c.metadata, vectors.metadata_digest_domain), c.expected)
    })
  }

  test('the offered domain label is the one the fixture declares', () => {
    assert.equal(CAPABILITY_METADATA_DOMAIN_CBD_V0, vectors.metadata_digest_domain)
  })

  test('an absent metadata domain is a call error, not a verdict', () => {
    assert.throws(
      () => capabilityMetadataDigest({}, ''),
      (err: unknown) =>
        err instanceof CapabilityBindingError &&
        err.code === vectors.metadata_digest_domain_required.error_code,
    )
  })

  test('the implementation digest equals what createToolRegistryEntry computes', () => {
    const attestor = generateKeyPair()
    const implementation = vectors.implementation_digest_cases[0]!.implementation
    const entry = createToolRegistryEntry({
      toolName: vectors.tool_name,
      implementation,
      attestorId: 'did:aps:example:cb-attestor',
      attestorPrivateKey: attestor.privateKey,
      verifiedAt: '2026-09-23T00:00:00.000Z',
    })
    assert.equal(entry.implementationHash, capabilityImplementationDigest(implementation))
  })
})

describe('capability-binding: the scope_grant_v0 pin encoding', () => {
  for (const c of vectors.scope_grant_parse_cases) {
    test(`parse: ${c.label}`, () => {
      const pin = parseCapabilityPinFromScopeGrants(c.grants, c.tool_name)
      if (c.expected === null) {
        assert.equal(pin, null)
        return
      }
      assert.notEqual(pin, null)
      assert.equal(pin!.tool_name, c.expected.tool_name)
      assert.deepEqual([...pin!.implementation_digests], c.expected.implementation_digests)
      assert.deepEqual([...pin!.metadata_digests], c.expected.metadata_digests)
      assert.equal(pin!.encoding, c.expected.encoding)
    })
  }

  for (const c of vectors.scope_grant_write_cases) {
    test(`write: ${c.label}`, () => {
      if (c.expected_error_code !== undefined) {
        assert.throws(
          () => capabilityPinScopeGrants(c.pin),
          (err: unknown) =>
            err instanceof CapabilityBindingError && err.code === c.expected_error_code,
        )
        return
      }
      assert.deepEqual([...capabilityPinScopeGrants(c.pin)], c.expected)
    })
  }

  test('write then parse round trips', () => {
    for (const c of vectors.scope_grant_write_cases) {
      if (c.expected_error_code !== undefined) continue
      const grants = capabilityPinScopeGrants(c.pin)
      const parsed = parseCapabilityPinFromScopeGrants(grants, c.pin.tool_name)
      assert.notEqual(parsed, null)
      assert.deepEqual([...parsed!.implementation_digests], [...c.pin.implementation_digests])
      assert.deepEqual([...parsed!.metadata_digests], [...c.pin.metadata_digests])
    }
  })

  test('the tool grant and the two pin prefixes are what the fixture grants use', () => {
    assert.equal(toolScopeGrant('ledger.export'), 'tool:ledger.export')
    const both = vectors.scope_grant_parse_cases[0]!
    assert.ok(both.grants.includes(toolScopeGrant('ledger.export')))
  })

  test('named-and-unpinned is not the same answer as not named', () => {
    const named = parseCapabilityPinFromScopeGrants(['tool:t'], 't')
    assert.notEqual(named, null)
    assert.equal(capabilityPinIsEmpty(named!), true)
    assert.equal(parseCapabilityPinFromScopeGrants(['other:grant'], 't'), null)
  })
})

describe('capability-binding: evaluateCapabilityBinding', () => {
  for (const c of vectors.capability_binding_cases) {
    test(`${c.id}: ${c.note}`, () => {
      const result = evaluateCapabilityBinding(c.input)
      assertBinding(result as unknown as Record<string, unknown>, c.expected, c.id)
    })
  }

  test('no case returns an artifact verdict and none makes a delegation invalid', () => {
    for (const c of vectors.capability_binding_cases) {
      const result = evaluateCapabilityBinding(c.input) as unknown as Record<string, unknown>
      assert.ok((BOUNDARY_OUTCOMES as readonly string[]).includes(result.outcome as string), c.id)
      assert.equal('verdict' in result, false, `${c.id}: no artifact verdict member`)
      assert.equal('valid' in result, false, `${c.id}: no truthiness shortcut`)
    }
  })

  test('a pin for a different tool than the action is a call error, not a verdict', () => {
    assert.throws(
      () =>
        evaluateCapabilityBinding({
          requestedToolName: 'a',
          grantedScopes: ['tool:b'],
          pin: {
            tool_name: 'b',
            implementation_digests: [],
            metadata_digests: [],
            encoding: 'scope_grant_v0',
          },
          attestation: null,
          observedImplementationDigest: null,
          observedMetadataDigest: null,
        }),
      (err: unknown) => err instanceof CapabilityBindingError && err.code === 'PIN_TOOL_MISMATCH',
    )
  })

  test('results are frozen', () => {
    const result = evaluateCapabilityBinding(vectors.capability_binding_cases[0]!.input)
    assert.equal(Object.isFrozen(result), true)
  })
})

describe('capability-binding: observeToolAttestation over the existing tool-integrity layer', () => {
  const attestor = generateKeyPair()
  const other = generateKeyPair()
  const implementation = vectors.implementation_digest_cases[0]!.implementation
  const drifted = vectors.implementation_digest_cases[1]!.implementation
  const entry = createToolRegistryEntry({
    toolName: vectors.tool_name,
    implementation,
    attestorId: 'did:aps:example:cb-attestor',
    attestorPrivateKey: attestor.privateKey,
    verifiedAt: '2026-09-23T00:00:00.000Z',
  })

  test('a resolved key over an unchanged implementation is an accepted attestation', () => {
    const observed = observeToolAttestation({
      registryEntry: entry,
      requestedToolName: vectors.tool_name,
      observedImplementation: implementation,
      resolveTrustedAttestorKey: () => attestor.publicKey,
    })
    assert.deepEqual({ ...observed }, {
      attested_tool_name: vectors.tool_name,
      attested_implementation_digest: capabilityImplementationDigest(implementation),
      attestor_key_resolved: true,
      attestor_signature_valid: true,
    })
  })

  test('standing is resolved by tool, never from the attestorId the entry asserts', () => {
    const observed = observeToolAttestation({
      registryEntry: entry,
      requestedToolName: vectors.tool_name,
      observedImplementation: implementation,
      resolveTrustedAttestorKey: () => other.publicKey,
    })
    assert.equal(observed.attestor_key_resolved, true)
    assert.equal(observed.attestor_signature_valid, false)
  })

  test('no resolvable key means no accepted attestation and no signature claim', () => {
    const observed = observeToolAttestation({
      registryEntry: entry,
      requestedToolName: vectors.tool_name,
      observedImplementation: implementation,
      resolveTrustedAttestorKey: () => null,
    })
    assert.equal(observed.attestor_key_resolved, false)
    assert.equal(observed.attestor_signature_valid, false)
  })

  test('end to end: a signed entry that no longer describes the tool is stale, not unsigned', () => {
    const observed = observeToolAttestation({
      registryEntry: entry,
      requestedToolName: vectors.tool_name,
      observedImplementation: drifted,
      resolveTrustedAttestorKey: () => attestor.publicKey,
    })
    assert.equal(observed.attestor_signature_valid, true)
    const result = evaluateCapabilityBinding({
      requestedToolName: vectors.tool_name,
      grantedScopes: [toolScopeGrant(vectors.tool_name)],
      pin: parseCapabilityPinFromScopeGrants([toolScopeGrant(vectors.tool_name)], vectors.tool_name),
      attestation: observed,
      observedImplementationDigest: capabilityImplementationDigest(drifted),
      observedMetadataDigest: null,
    })
    assert.equal(result.outcome, 'not_established')
    assert.equal(result.reason_code, 'REGISTRY_ENTRY_IMPLEMENTATION_MISMATCH')
    assert.deepEqual([...result.missing!], ['freshness'])
  })

  test('end to end: a pinned digest established to have changed is a denial', () => {
    const observed = observeToolAttestation({
      registryEntry: createToolRegistryEntry({
        toolName: vectors.tool_name,
        implementation: drifted,
        attestorId: 'did:aps:example:cb-attestor',
        attestorPrivateKey: attestor.privateKey,
        verifiedAt: '2026-09-23T00:00:00.000Z',
      }),
      requestedToolName: vectors.tool_name,
      observedImplementation: drifted,
      resolveTrustedAttestorKey: () => attestor.publicKey,
    })
    const grants = [
      toolScopeGrant(vectors.tool_name),
      `${toolScopeGrant(vectors.tool_name)}:impl:${capabilityImplementationDigest(implementation)}`,
    ]
    const result = evaluateCapabilityBinding({
      requestedToolName: vectors.tool_name,
      grantedScopes: grants,
      pin: parseCapabilityPinFromScopeGrants(grants, vectors.tool_name),
      attestation: observed,
      observedImplementationDigest: capabilityImplementationDigest(drifted),
      observedMetadataDigest: null,
    })
    assert.equal(result.outcome, 'denied')
    assert.equal(result.continuity, 'mismatch')
    assert.equal(result.reason_code, 'PINNED_IMPLEMENTATION_DIGEST_MISMATCH')
    assert.equal(result.missing, undefined)
  })
})

describe('capability-binding: the verifiedAt override is additive', () => {
  const attestor = generateKeyPair()
  const implementation = 'x'

  test('supplying it makes the entry reproducible byte for byte', () => {
    const args = {
      toolName: 't',
      implementation,
      attestorId: 'did:aps:example:cb-attestor',
      attestorPrivateKey: attestor.privateKey,
      verifiedAt: '2026-09-23T00:00:00.000Z',
    }
    assert.deepEqual(createToolRegistryEntry(args), createToolRegistryEntry(args))
  })

  test('omitting it leaves the old behaviour: a real timestamp and a valid entry', () => {
    const before = Date.now()
    const entry = createToolRegistryEntry({
      toolName: 't',
      implementation,
      attestorId: 'did:aps:example:cb-attestor',
      attestorPrivateKey: attestor.privateKey,
    })
    const stamped = Date.parse(entry.verifiedAt)
    assert.ok(Number.isFinite(stamped))
    assert.ok(stamped >= before - 1000 && stamped <= Date.now() + 1000)
    const integrity = verifyToolIntegrity({
      registryEntry: entry,
      currentImplementation: implementation,
      attestorPublicKey: attestor.publicKey,
    })
    assert.equal(integrity.attestorSignatureValid, true)
  })

  test('an overridden entry still verifies through the unchanged verifier', () => {
    const entry = createToolRegistryEntry({
      toolName: 't',
      implementation,
      attestorId: 'did:aps:example:cb-attestor',
      attestorPrivateKey: attestor.privateKey,
      verifiedAt: '2026-09-23T00:00:00.000Z',
    })
    assert.equal(entry.verifiedAt, '2026-09-23T00:00:00.000Z')
    const integrity = verifyToolIntegrity({
      registryEntry: entry,
      currentImplementation: implementation,
      attestorPublicKey: attestor.publicKey,
    })
    assert.equal(integrity.attestorSignatureValid, true)
    assert.equal(integrity.implementationVerified, true)
  })
})

describe('capability-binding: identifier records', () => {
  for (const c of vectors.record_signed_bytes_cases) {
    test(`signed bytes: ${c.label}`, () => {
      assert.equal(identifierRecordSignedBytes(c.record, c.unsigned_fields), c.expected)
    })
  }

  test('the unsigned-field lists are what the fixture uses', () => {
    assert.deepEqual([...IDENTIFIER_BINDING_UNSIGNED_FIELDS], ['binding_id', 'signature'])
    assert.deepEqual([...IDENTIFIER_RETENTION_UNSIGNED_FIELDS], ['retention_id', 'signature'])
  })

  test('the scope grants are the two the fixture grants use', () => {
    assert.equal(
      identifierDependencyScopeGrant('mail-domain', 'acme-legal.example'),
      'extid:mail-domain:acme-legal.example',
    )
    assert.equal(
      identifierControllerPinScopeGrant('mail-domain', 'acme-legal.example', 'did:aps:example:cb-org'),
      'extid:mail-domain:acme-legal.example:controller:did:aps:example:cb-org',
    )
  })

  test('controller pins are read only for the identifier asked about', () => {
    const grants = [
      'extid:mail-domain:a.example:controller:did:one',
      'extid:mail-domain:b.example:controller:did:two',
    ]
    assert.deepEqual([...parseIdentifierControllerPins(grants, 'mail-domain', 'a.example')], [
      'did:one',
    ])
  })
})

function signRecords<T>(
  entries: Array<{ record: Record<string, unknown>; sign_as: string | null; signature_literal?: string }>,
  unsignedFields: readonly string[],
): T[] {
  return entries.map(entry => {
    const signature =
      entry.signature_literal !== undefined
        ? entry.signature_literal
        : entry.sign_as === null
          ? ic.invalid_signature_literal
          : sign(
              identifierRecordSignedBytes(entry.record, unsignedFields),
              ic.custodian_private_keys[entry.sign_as]!,
            )
    return { ...entry.record, signature } as T
  })
}

describe('capability-binding: evaluateIdentifierContinuity', () => {
  for (const c of ic.cases) {
    test(`${c.id}: ${c.note}`, () => {
      const standing = c.input.custodian_standing_override ?? ic.custodian_standing
      const result = evaluateIdentifierContinuity({
        identifierKind: c.input.identifierKind,
        identifier: c.input.identifier,
        grantedScopes: c.input.grantedScopes,
        grantIssuedAt: c.input.grantIssuedAt,
        at: c.input.at,
        bindings: signRecords<IdentifierBindingRecord>(
          c.input.bindings,
          IDENTIFIER_BINDING_UNSIGNED_FIELDS,
        ),
        retentions: signRecords<IdentifierRetentionRecord>(
          c.input.retentions,
          IDENTIFIER_RETENTION_UNSIGNED_FIELDS,
        ),
        resolveCustodianStanding: kind => standing[kind] ?? null,
        resolveCustodianKey: custodian => ic.custodian_public_keys[custodian] ?? null,
      })
      assertBinding(result as unknown as Record<string, unknown>, c.expected, c.id)
    })
  }

  test('no case returns an artifact verdict', () => {
    for (const c of ic.cases) {
      assert.ok((BOUNDARY_OUTCOMES as readonly string[]).includes(c.expected.outcome), c.id)
    }
  })

  test('a denial on a changed controller names who holds the identifier now', () => {
    for (const c of ic.cases) {
      if (c.expected.reason_code !== 'IDENTIFIER_CONTROLLER_CHANGED') continue
      assert.equal(typeof c.expected.controller_at_instant, 'string', c.id)
      assert.notEqual(c.expected.controller_at_instant, null, c.id)
    }
  })
})

describe('capability-binding: the constructor and the known divergence', () => {
  test('a not_established outcome must name at least one limb', () => {
    assert.throws(
      () =>
        referentBindingResult({
          outcome: 'not_established',
          continuity: 'not_established',
          reason_code: 'X',
        }),
      (err: unknown) => err instanceof CapabilityBindingError && err.code === 'MISSING_REQUIRED',
    )
  })

  test('a reached outcome must not carry a limb', () => {
    assert.throws(
      () =>
        referentBindingResult({
          outcome: 'denied',
          continuity: 'mismatch',
          reason_code: 'X',
          missing: ['coverage'],
        }),
      (err: unknown) => err instanceof CapabilityBindingError && err.code === 'MISSING_NOT_ALLOWED',
    )
  })

  test('the v0 projection collapses denied into not_established, and only that way', () => {
    assert.equal(projectBoundaryOutcomeToCandidateV0('authorized', 'admitted'), 'admitted')
    assert.equal(projectBoundaryOutcomeToCandidateV0('authorized', 'valid'), 'valid')
    assert.equal(projectBoundaryOutcomeToCandidateV0('denied', 'admitted'), 'not_established')
    assert.equal(projectBoundaryOutcomeToCandidateV0('not_established', 'valid'), 'not_established')
  })

  test('the module itself never reports an established mismatch as not_established', () => {
    for (const c of [...vectors.capability_binding_cases, ...ic.cases]) {
      if (c.expected.continuity !== 'mismatch') continue
      assert.equal(c.expected.outcome, 'denied', `${c.id}: CAND-07 v2 says a mismatch is a denial`)
      assert.equal(c.expected.missing, undefined, c.id)
    }
  })
})
