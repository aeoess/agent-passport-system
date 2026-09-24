// Copyright (c) 2026 Tymofii Pidlisnyi
// SPDX-License-Identifier: Apache-2.0
//
// PROPOSED, OPT-IN. The two digests a capability pin is taken over.
// See ./types.ts for the specification position: draft-pidlisnyi-aps-03 defines neither of
// these digests and states no pin rule. Concept source: aeoess/agent-authority-lifecycle,
// invariant candidate CAND-07 v2.

import { createHash } from 'node:crypto'

import { canonicalizeJCS } from '../../core/canonical-jcs.js'
import { CapabilityBindingError } from './types.js'

/** `sha256:` over the raw implementation bytes.
 *
 *  Byte-identical to what `createToolRegistryEntry` and `verifyToolIntegrity` already
 *  compute for `implementationHash`, and exported here so a caller can obtain the observed
 *  digest without minting a registry entry. The content may be source, a binary, or an
 *  endpoint descriptor: this function hashes exactly the bytes it is given and interprets
 *  nothing. */
export function capabilityImplementationDigest(implementation: string | Buffer): string {
  return `sha256:${createHash('sha256').update(implementation).digest('hex')}`
}

/** `sha256:` over DOMAIN || 0x00 || JCS(metadata).
 *
 *  DISTINCT FROM THE IMPLEMENTATION DIGEST, WHICH IS THE WHOLE POINT. A tool can keep its
 *  name and its implementation bytes while its declared description, schema or permissions
 *  change, gaining a destructive permission without any change to the grant. An
 *  implementation digest cannot see that; this one can.
 *
 *  The domain-separated preimage follows the style draft-03 section 4.1 uses for its own
 *  digests, verbatim:
 *
 *    payload_ref = lowercase-hex(SHA-256("APS-ACTION-PAYLOAD-V1" || 0x00 || JCS(payload)))
 *
 *  draft-03 does not define a tool-metadata digest, so `domain` is REQUIRED and has no
 *  default: a default here would mint protocol vocabulary this module has no standing to
 *  mint. `CAPABILITY_METADATA_DOMAIN_CBD_V0` is the one label already in use by a published
 *  candidate fixture family, offered as a value to pass rather than as a default.
 *
 *  The canonical bytes are RFC 8785 JCS, which preserves `null` members. The SDK's legacy
 *  `canonicalize` strips them, so the two are NOT interchangeable for this preimage. */
export function capabilityMetadataDigest(metadata: unknown, domain: string): string {
  if (typeof domain !== 'string' || domain.length === 0) {
    throw new CapabilityBindingError(
      'METADATA_DIGEST_DOMAIN_REQUIRED',
      'domain must be a non-empty string: this module mints no default metadata digest domain',
    )
  }
  const preimage = Buffer.concat([
    Buffer.from(domain, 'utf8'),
    Buffer.from([0x00]),
    Buffer.from(canonicalizeJCS(metadata), 'utf8'),
  ])
  return `sha256:${createHash('sha256').update(preimage).digest('hex')}`
}

/** The metadata-digest domain the `aps-capability-binding-drift-v0` candidate fixture
 *  family declares. Offered so a caller reproducing that family passes the same label, not
 *  as a protocol constant and not as a default. PROPOSED. */
export const CAPABILITY_METADATA_DOMAIN_CBD_V0 = 'APS-CBD-TOOL-METADATA-V0'
