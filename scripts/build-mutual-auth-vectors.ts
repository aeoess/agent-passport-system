// Copyright 2024-2026 Tymofii Pidlisnyi. Apache-2.0 license. See LICENSE.
// Generator for mutual-auth conformance vectors.
// Run: npx tsx scripts/build-mutual-auth-vectors.ts

import { createHash } from 'node:crypto'
import { writeFileSync, mkdirSync } from 'node:fs'
import { canonicalizeJCS } from '../src/core/canonical-jcs.js'
import {
  buildCertificate, buildBundle,
  certificateId,
} from '../src/index.js'

const OUT = 'src/conformance/mutual-auth-vectors'
mkdirSync(OUT, { recursive: true })

// Stable fixed inputs so vectors are reproducible.
const ROOT_PK = '00'.repeat(32)
const AGENT_PK = '01'.repeat(32)
const IS_PK = '02'.repeat(32)
const T0 = 1_745_000_000_000

function sha256(bytes: Uint8Array | string): string {
  return 'sha256:' + createHash('sha256').update(bytes as any).digest('hex')
}
function canonBytes(value: unknown): Uint8Array {
  return new TextEncoder().encode(canonicalizeJCS(value))
}
function write(name: string, vector: unknown): void {
  const path = `${OUT}/${name}`
  writeFileSync(path, JSON.stringify(vector, null, 2) + '\n')
  console.log('wrote', path)
}

// vec01: minimum-field certificate canonical form
{
  const unsigned = buildCertificate(
    {
      role: 'agent',
      subject_id: 'agent:minimal',
      subject_pubkey_hex: AGENT_PK,
      issuer_id: 'root',
      issuer_role: 'trust_anchor',
      binding: 'agent:minimal',
      not_before: T0 - 3600_000,
      not_after: T0 + 86400_000,
      supported_versions: ['1.0'],
    },
    ROOT_PK,
  )
  const canonical = canonBytes(unsigned)
  write('vec01-certificate-canonical.json', {
    name: 'certificate-minimal',
    spec_section: '3.1',
    primitive: 'buildCertificate',
    input: {
      role: 'agent', subject_id: 'agent:minimal',
      subject_pubkey_hex: AGENT_PK, issuer_id: 'root',
      issuer_role: 'trust_anchor', binding: 'agent:minimal',
      not_before: T0 - 3600_000, not_after: T0 + 86400_000,
      supported_versions: ['1.0'], issuer_pubkey_hex: ROOT_PK,
    },
    expected: {
      canonical_bytes_b64: Buffer.from(canonical).toString('base64'),
      canonical_sha256: sha256(canonical),
    },
  })
}

// vec02: all optional fields
{
  const unsigned = buildCertificate(
    {
      role: 'agent',
      subject_id: 'agent:full',
      subject_pubkey_hex: AGENT_PK,
      issuer_id: 'root',
      issuer_role: 'trust_anchor',
      binding: 'agent:full',
      not_before: T0 - 3600_000,
      not_after: T0 + 86400_000,
      supported_versions: ['1.2', '1.1', '1.0'],
      attestation_grade: 3,
      capabilities: ['mcp:read', 'mcp:write', 'a2a:task:execute'],
    },
    ROOT_PK,
  )
  const canonical = canonBytes(unsigned)
  write('vec02-certificate-all-fields.json', {
    name: 'certificate-all-fields',
    spec_section: '3.1',
    primitive: 'buildCertificate',
    input: {
      role: 'agent', subject_id: 'agent:full',
      subject_pubkey_hex: AGENT_PK, issuer_id: 'root',
      issuer_role: 'trust_anchor', binding: 'agent:full',
      not_before: T0 - 3600_000, not_after: T0 + 86400_000,
      supported_versions: ['1.2', '1.1', '1.0'],
      attestation_grade: 3,
      capabilities: ['mcp:read', 'mcp:write', 'a2a:task:execute'],
      issuer_pubkey_hex: ROOT_PK,
    },
    expected: {
      canonical_bytes_b64: Buffer.from(canonical).toString('base64'),
      canonical_sha256: sha256(canonical),
    },
  })
}

// vec03: trust anchor bundle canonical form
{
  const unsigned = buildBundle(
    {
      bundle_id: 'test-bundle-001',
      anchors: [
        {
          anchor_id: 'root',
          display_name: 'Root',
          role: 'trust_anchor',
          pubkey_hex: ROOT_PK,
          not_before: T0 - 86400_000,
          not_after: T0 + 31_536_000_000,
        },
      ],
      issued_at: T0,
      refresh_after: T0 + 7 * 86400_000,
    },
    ROOT_PK,
  )
  const canonical = canonBytes(unsigned)
  write('vec03-bundle-canonical.json', {
    name: 'bundle-canonical',
    spec_section: '4.2',
    primitive: 'buildBundle',
    expected: {
      canonical_bytes_b64: Buffer.from(canonical).toString('base64'),
      canonical_sha256: sha256(canonical),
    },
  })
}

// vec04: attest canonical (unsigned form)
{
  const cert = buildCertificate(
    {
      role: 'information_system',
      subject_id: 'mcp://api.example.com',
      subject_pubkey_hex: IS_PK,
      issuer_id: 'root',
      issuer_role: 'trust_anchor',
      binding: 'mcp://api.example.com',
      not_before: T0 - 3600_000,
      not_after: T0 + 86400_000,
      supported_versions: ['1.0'],
    },
    ROOT_PK,
  )
  // We need a pre-signed cert shape for the attest, but we don't
  // want to depend on signature determinism. Use a placeholder signature.
  const PLACEHOLDER_SIG = 'A'.repeat(86) + '=='
  const signedCertShape = { ...cert, signature_b64: PLACEHOLDER_SIG }

  const unsigned = {
    spec_version: '1.0' as const,
    role: 'information_system' as const,
    chosen_version: '1.0',
    own_nonce_b64: 'IMAU7m1TYk5qY',
    peer_nonce_b64: 'ALICE-NONCE=',
    certificate: signedCertShape,
    timestamp: T0,
  }
  const canonical = canonBytes(unsigned)
  write('vec04-attest-canonical.json', {
    name: 'attest-canonical',
    spec_section: '5.2',
    primitive: 'buildAttest',
    note: 'certificate.signature_b64 uses a fixed placeholder so this vector is signature-library-independent',
    expected: {
      canonical_bytes_b64: Buffer.from(canonical).toString('base64'),
      canonical_sha256: sha256(canonical),
      certificate_id: certificateId(signedCertShape),
    },
  })
}

// vec05: session derivation ID
{
  // Construct deterministic attests (with placeholder signatures) to
  // check session_id derivation.
  const agentCert = {
    ...buildCertificate(
      {
        role: 'agent' as const, subject_id: 'agent:a', subject_pubkey_hex: AGENT_PK,
        issuer_id: 'root', issuer_role: 'trust_anchor' as const,
        binding: 'agent:a',
        not_before: T0 - 3600_000, not_after: T0 + 86400_000,
        supported_versions: ['1.0'], attestation_grade: 2 as const,
      },
      ROOT_PK,
    ),
    signature_b64: 'A'.repeat(86) + '==',
  }
  const isCert = {
    ...buildCertificate(
      {
        role: 'information_system' as const, subject_id: 'mcp://x',
        subject_pubkey_hex: IS_PK, issuer_id: 'root',
        issuer_role: 'trust_anchor' as const, binding: 'mcp://x',
        not_before: T0 - 3600_000, not_after: T0 + 86400_000,
        supported_versions: ['1.0'],
      },
      ROOT_PK,
    ),
    signature_b64: 'B'.repeat(86) + '==',
  }

  const sessionMaterial = canonicalizeJCS({
    spec_version: '1.0',
    chosen_version: '1.0',
    agent_cert_id: certificateId(agentCert),
    is_cert_id: certificateId(isCert),
    agent_nonce_b64: 'AGENT-N==',
    is_nonce_b64: 'IS-N====',
  })
  const session_id = 'sha256:' + createHash('sha256').update(sessionMaterial).digest('hex')

  write('vec05-session-derivation.json', {
    name: 'session-derivation',
    spec_section: '5.5',
    primitive: 'deriveSession',
    input: {
      chosen_version: '1.0',
      agent_cert_id: certificateId(agentCert),
      is_cert_id: certificateId(isCert),
      agent_nonce_b64: 'AGENT-N==',
      is_nonce_b64: 'IS-N====',
    },
    expected: {
      session_id,
    },
  })
}

console.log('\nAll vectors generated.')
