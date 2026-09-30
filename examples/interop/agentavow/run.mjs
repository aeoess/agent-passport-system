// APS consumer profile for AgentAvow tool-manifest-digest-v0 vectors.
// Reads the vector file unchanged and evaluates each case with APS SDK primitives
// (canonicalizeJCS, strict Ed25519 verify). Each of the five axes is computed
// independently and compared to the fixture's expectation. APS-side claims that
// the fixture does not carry are reported separately as not_evaluated.
//
// usage: node run.mjs <path to tool-manifest-digest-v0-vectors.json>
import { readFileSync } from 'node:fs'
import { canonicalizeJCS, verify } from 'agent-passport-system'

const file = process.argv[2]
if (!file) { console.error('usage: node run.mjs <vectors.json>'); process.exit(2) }
const suite = JSON.parse(readFileSync(file, 'utf8'))

const b64u = (s) => Buffer.from(s.replace(/-/g, '+').replace(/_/g, '/'), 'base64')
const jwk = suite.issuer.jwk
const pubHex = b64u(jwk.x).toString('hex')
const AXES = ['signature_valid', 'canonical_bytes', 'subject_binds', 'digest_binds', 'fresh']

function evaluate(jws, gate) {
  const [h, p, s] = jws.split('.')
  const header = JSON.parse(b64u(h).toString('utf8'))
  const payloadStr = b64u(p).toString('utf8')
  const payload = JSON.parse(payloadStr)
  const t = Date.parse(gate.evaluation_time)
  const r = {
    // the key is pinned by kid, the header alg must be EdDSA, and the signature is over
    // ASCII(BASE64URL(header) "." BASE64URL(payload))
    signature_valid: header.kid === jwk.kid && header.alg === 'EdDSA' &&
      verify(`${h}.${p}`, b64u(s).toString('hex'), pubHex),
    canonical_bytes: canonicalizeJCS(payload) === payloadStr,
    subject_binds: payload?.subject?.id === gate.subject_id,
    digest_binds: payload?.scan?.toolManifestDigest === gate.observed_manifest_digest,
    fresh: Date.parse(payload.issuedAt) <= t && t < Date.parse(payload.expiresAt),
  }
  r.rely = AXES.every((a) => r[a] === true)
  return r
}

let failures = 0
console.log(`${suite.suite} via agent-passport-system canonicalizeJCS + verify`)
for (const v of suite.vectors) {
  const jws = v.jws === 'reference' ? suite.attestation.jws : v.jws
  const got = evaluate(jws, v.gate)
  for (const a of [...AXES, 'rely']) {
    const ok = got[a] === v.expect[a]
    if (!ok) failures++
    console.log(`  ${ok ? 'ok  ' : 'FAIL'}  ${v.name}: ${a} expected ${v.expect[a]} got ${got[a]}`)
  }
}
console.log('APS-side mappings, not carried by this fixture, reported separately:')
console.log('  not_evaluated  tool_to_subject: APS names the tool an action goes through (requestedToolName).')
console.log('                 The attestation subject is a repository/server id and scan.toolDigests is keyed')
console.log('                 by file path, so no tool name is bound to the subject here.')
console.log('  false_analog   toolManifestDigest as an APS metadata pin: capabilityMetadataDigest is SHA-256(domain || 0x00 || JCS(one tool')
console.log('                 metadata object)). toolManifestDigest is folded over per-file digests. Different')
console.log('                 preimage and domain, so neither digest stands in for the other.')
console.log(failures === 0 ? 'all fixture expectations matched' : `${failures} expectation(s) did not match`)
process.exit(failures === 0 ? 0 : 1)
