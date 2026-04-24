// Copyright 2024-2026 Tymofii Pidlisnyi. Apache-2.0 license.
// Generate deterministic rotation-attestation fixtures v1
// Run: npx tsx scripts/generate-rotation-attestation-fixtures.ts

import crypto from 'node:crypto'
import { writeFileSync, mkdirSync } from 'node:fs'
import { join } from 'node:path'

import { sign, publicKeyFromPrivate } from '../src/crypto/keys.js'
import { canonicalize } from '../src/core/canonical.js'
import { createDID, hexToMultibase } from '../src/core/did.js'
import type { RotatableDIDDocument, RotatableVerificationMethod, DIDRotationEntry } from '../src/types/passport.js'

// Deterministic seeds — DO NOT CHANGE (published SHAs depend on these)
const SEED_OLD_KEY = 'a1' + '0'.repeat(62)
const SEED_NEW_KEY = 'a2' + '0'.repeat(62)
const SEED_ATTESTOR = 'a3' + '0'.repeat(62)

const OLD_PUB = publicKeyFromPrivate(SEED_OLD_KEY)
const NEW_PUB = publicKeyFromPrivate(SEED_NEW_KEY)
const ATTESTOR_PUB = publicKeyFromPrivate(SEED_ATTESTOR)

const FIXED_ANNOUNCED_AT = '2026-04-24T17:00:00.000Z'
const FIXED_ACTIVATION_TIME = '2026-04-24T17:00:00.000Z'
const FIXED_CREATED = '2026-04-24T17:00:00.000Z'
const FIXED_MIGRATED_AT = '2026-04-24T17:00:00.000Z'

interface MigrationAttestation {
  attestorKey: string
  attestorSignature: string
  migrationType: 'key_class_upgrade'
  fromClass: 'self_asserted' | 'infrastructure_attested' | 'provider_attested' | 'hardware_attested'
  toClass: 'self_asserted' | 'infrastructure_attested' | 'provider_attested' | 'hardware_attested'
  migratedAt: string
}

interface ExtendedRotationEntry extends DIDRotationEntry {
  crossSignature?: string
  migrationAttestation?: MigrationAttestation
}

function canonicalRotationPayload(previousKey: string, newKey: string, mode: 'planned' | 'emergency', activationTime: string): string {
  return canonicalize({ previousKey, newKey, mode, activationTime })
}

function canonicalMigrationPayload(previousKey: string, newKey: string, migrationType: string, fromClass: string, toClass: string, migratedAt: string): string {
  return canonicalize({ previousKey, newKey, migrationType, fromClass, toClass, migratedAt })
}

function buildDocument(rotationEntry: ExtendedRotationEntry): RotatableDIDDocument {
  const did = createDID(OLD_PUB)
  const oldKeyId = `${did}#key-1`
  const newKeyId = `${did}#key-2`
  const oldVm: RotatableVerificationMethod = { id: oldKeyId, type: 'Ed25519VerificationKey2020', controller: did, publicKeyMultibase: hexToMultibase(OLD_PUB), retiredAt: FIXED_ANNOUNCED_AT }
  const newVm: RotatableVerificationMethod = { id: newKeyId, type: 'Ed25519VerificationKey2020', controller: did, publicKeyMultibase: hexToMultibase(NEW_PUB) }
  return {
    '@context': ['https://www.w3.org/ns/did/v1', 'https://w3id.org/security/suites/ed25519-2020/v1'],
    id: did, controller: did, verificationMethod: [oldVm, newVm],
    authentication: [newKeyId], assertionMethod: [newKeyId], capabilityDelegation: [newKeyId],
    rotationLog: [rotationEntry], created: FIXED_CREATED, updated: FIXED_ANNOUNCED_AT,
  }
}

function baseEntry(): ExtendedRotationEntry {
  const payload = canonicalRotationPayload(OLD_PUB, NEW_PUB, 'emergency', FIXED_ACTIVATION_TIME)
  return {
    previousKey: OLD_PUB, newKey: NEW_PUB, mode: 'emergency',
    announcedAt: FIXED_ANNOUNCED_AT, activationTime: FIXED_ACTIVATION_TIME,
    state: 'activated', rotationSignature: sign(payload, SEED_OLD_KEY),
    completedAt: FIXED_ANNOUNCED_AT,
  }
}

function migrationAttestation(): MigrationAttestation {
  const payload = canonicalMigrationPayload(OLD_PUB, NEW_PUB, 'key_class_upgrade', 'self_asserted', 'hardware_attested', FIXED_MIGRATED_AT)
  return {
    attestorKey: ATTESTOR_PUB, attestorSignature: sign(payload, SEED_ATTESTOR),
    migrationType: 'key_class_upgrade', fromClass: 'self_asserted', toClass: 'hardware_attested',
    migratedAt: FIXED_MIGRATED_AT,
  }
}

function fixtureHappyPath(): RotatableDIDDocument { return buildDocument(baseEntry()) }

function fixtureCrossSigned(): RotatableDIDDocument {
  const e = baseEntry()
  const payload = canonicalRotationPayload(OLD_PUB, NEW_PUB, 'emergency', FIXED_ACTIVATION_TIME)
  e.crossSignature = sign(payload, SEED_NEW_KEY)
  return buildDocument(e)
}

function fixtureMigrationAttested(): RotatableDIDDocument {
  const e = baseEntry()
  e.migrationAttestation = migrationAttestation()
  return buildDocument(e)
}

function fixtureCompound(): RotatableDIDDocument {
  const e = baseEntry()
  const payload = canonicalRotationPayload(OLD_PUB, NEW_PUB, 'emergency', FIXED_ACTIVATION_TIME)
  e.crossSignature = sign(payload, SEED_NEW_KEY)
  e.migrationAttestation = migrationAttestation()
  return buildDocument(e)
}

function fixtureNegative(): RotatableDIDDocument {
  const e: ExtendedRotationEntry = {
    previousKey: OLD_PUB, newKey: NEW_PUB, mode: 'emergency',
    announcedAt: FIXED_ANNOUNCED_AT, activationTime: FIXED_ACTIVATION_TIME,
    state: 'activated', rotationSignature: '', completedAt: FIXED_ANNOUNCED_AT,
  }
  return buildDocument(e)
}

const OUTPUT_DIR = '/Users/tima/aeoess_web/fixtures/rotation-attestation'
mkdirSync(OUTPUT_DIR, { recursive: true })
mkdirSync(join(OUTPUT_DIR, 'keys'), { recursive: true })

function writeFixture(name: string, doc: RotatableDIDDocument): { name: string; canonicalSha256: string } {
  const canonical = canonicalize(doc)
  writeFileSync(join(OUTPUT_DIR, `${name}.json`), JSON.stringify(doc, null, 2) + '\n')
  const sha = crypto.createHash('sha256').update(canonical, 'utf8').digest('hex')
  return { name, canonicalSha256: `sha256:${sha}` }
}

const vectors = [
  writeFixture('happy-path', fixtureHappyPath()),
  writeFixture('cross-signed', fixtureCrossSigned()),
  writeFixture('migration-attested', fixtureMigrationAttested()),
  writeFixture('happy-path-compound', fixtureCompound()),
  writeFixture('negative-no-attestation', fixtureNegative()),
]

writeFileSync(
  join(OUTPUT_DIR, 'keys', 'attestor-v1.pub.json'),
  JSON.stringify({
    kid: 'aeoess-fixture-attestor-v1',
    kty: 'OKP', crv: 'Ed25519',
    publicKeyHex: ATTESTOR_PUB,
    description: 'Deterministic Ed25519 public key used to sign migration attestations in v1 fixtures. Fixtures are reproducible without depending on gateway.aeoess.com.',
  }, null, 2) + '\n'
)

const schema = {
  $schema: 'https://json-schema.org/draft/2020-12/schema',
  $id: 'https://aeoess.com/fixtures/rotation-attestation/schema-v1.json',
  title: 'Rotation-Attested DID Document (APS continuity-layer claim)',
  type: 'object',
  required: ['@context', 'id', 'controller', 'verificationMethod', 'rotationLog', 'created', 'updated'],
  properties: {
    '@context': { type: 'array', items: { type: 'string' } },
    id: { type: 'string', pattern: '^did:aps:' },
    controller: { type: 'string' },
    verificationMethod: { type: 'array', minItems: 1, items: { $ref: '#/$defs/VerificationMethod' } },
    authentication: { type: 'array', items: { type: 'string' } },
    assertionMethod: { type: 'array', items: { type: 'string' } },
    capabilityDelegation: { type: 'array', items: { type: 'string' } },
    rotationLog: { type: 'array', items: { $ref: '#/$defs/RotationEntry' } },
    created: { type: 'string', format: 'date-time' },
    updated: { type: 'string', format: 'date-time' },
  },
  $defs: {
    VerificationMethod: {
      type: 'object',
      required: ['id', 'type', 'controller', 'publicKeyMultibase'],
      properties: {
        id: { type: 'string' }, type: { const: 'Ed25519VerificationKey2020' },
        controller: { type: 'string' }, publicKeyMultibase: { type: 'string' },
        retiredAt: { type: 'string', format: 'date-time' },
      },
    },
    RotationEntry: {
      type: 'object',
      required: ['previousKey', 'newKey', 'mode', 'announcedAt', 'activationTime', 'state', 'rotationSignature'],
      properties: {
        previousKey: { type: 'string', pattern: '^[0-9a-f]{64}$' },
        newKey: { type: 'string', pattern: '^[0-9a-f]{64}$' },
        mode: { enum: ['planned', 'emergency'] },
        announcedAt: { type: 'string', format: 'date-time' },
        activationTime: { type: 'string', format: 'date-time' },
        state: { enum: ['announced', 'activated', 'cancelled'] },
        rotationSignature: { type: 'string', description: 'Ed25519 signature by old key over JCS canonicalization of {previousKey, newKey, mode, activationTime}. Empty string indicates missing continuity evidence; verifier MUST return INVALID_CLAIM_SCOPE.' },
        crossSignature: { type: 'string', description: 'Optional Ed25519 signature by NEW key over the same canonical rotation payload.' },
        migrationAttestation: { $ref: '#/$defs/MigrationAttestation' },
        completedAt: { type: 'string', format: 'date-time' },
      },
    },
    MigrationAttestation: {
      type: 'object',
      required: ['attestorKey', 'attestorSignature', 'migrationType', 'fromClass', 'toClass', 'migratedAt'],
      properties: {
        attestorKey: { type: 'string', pattern: '^[0-9a-f]{64}$' },
        attestorSignature: { type: 'string', description: 'Ed25519 signature by attestor over JCS of {previousKey, newKey, migrationType, fromClass, toClass, migratedAt}.' },
        migrationType: { enum: ['key_class_upgrade'], description: 'v1 = {key_class_upgrade}. v2 adds {did_method_migration, pq_migration}.' },
        fromClass: { enum: ['self_asserted', 'infrastructure_attested', 'provider_attested', 'hardware_attested'] },
        toClass: { enum: ['self_asserted', 'infrastructure_attested', 'provider_attested', 'hardware_attested'] },
        migratedAt: { type: 'string', format: 'date-time' },
      },
    },
  },
}
writeFileSync(join(OUTPUT_DIR, 'schema-v1.json'), JSON.stringify(schema, null, 2) + '\n')

const testVectors = {
  specVersion: 'rotation-attestation-v1',
  canonicalizationRule: 'RFC 8785 JCS applied before any signature or hash operation in this set',
  fixtures: vectors.reduce((acc, v) => {
    acc[v.name] = {
      url: `https://aeoess.com/fixtures/rotation-attestation/${v.name}.json`,
      canonicalSha256: v.canonicalSha256,
      expectedResult: v.name.startsWith('negative') ? 'fail-closed' : 'pass',
    }
    return acc
  }, {} as Record<string, { url: string; canonicalSha256: string; expectedResult: string }>),
  errorCodes: {
    'negative-no-attestation': {
      code: 'INVALID_CLAIM_SCOPE',
      reason: 'Continuity-layer claim present in rotation log but rotationSignature is empty. Verifier cannot attest continuity without rotation evidence; MUST fail closed before any other layer is evaluated.',
    },
  },
  attestorKey: {
    kid: 'aeoess-fixture-attestor-v1',
    publicKeyHex: ATTESTOR_PUB,
    publicKeyManifest: 'https://aeoess.com/fixtures/rotation-attestation/keys/attestor-v1.pub.json',
  },
  generatedAt: FIXED_ANNOUNCED_AT,
}
writeFileSync(join(OUTPUT_DIR, 'test-vectors.json'), JSON.stringify(testVectors, null, 2) + '\n')

console.log('Generated fixtures:')
vectors.forEach(v => console.log(`  ${v.name.padEnd(28)} ${v.canonicalSha256}`))
console.log(`\nAttestor pubkey: ${ATTESTOR_PUB}`)
console.log(`Output: ${OUTPUT_DIR}`)
