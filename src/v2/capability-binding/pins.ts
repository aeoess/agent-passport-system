// Copyright (c) 2026 Tymofii Pidlisnyi
// SPDX-License-Identifier: Apache-2.0
//
// PROPOSED, OPT-IN. The `scope_grant_v0` pin encoding: reading a pin out of a grant's
// scope, and writing one into it.
//
// WHY THIS ENCODING. draft-03 section 3.2 already defines a segmented scope grammar,
// verbatim: "Scope grants use ASCII colon-separated segments. \"*\" covers all grants; a
// wildcard is otherwise permitted only as the terminal segment \":*\"." Expressing a pin as
// further segments under the tool grant keeps it inside a grammar that exists, rather than
// requiring an eighth authority facet, which draft-03 section 3.2 forbids by closing the
// vector at seven and making a missing facet invalid.
//
// THE SIDE EFFECT, STATED. Under this encoding a pin is subject to draft-03's ordinary
// parent-covers-child rule, so a child delegation carrying a DIFFERENT pin fails as scope
// widening rather than as a binding failure, and a child that drops the pin narrows
// legitimately into an unpinned grant. That is a consequence of the encoding, not a
// decision the concept document asked for. Concept source:
// aeoess/agent-authority-lifecycle, invariant candidate CAND-07 v2.

import { CapabilityBindingError, type CapabilityPin } from './types.js'

/** The tool grant itself, `tool:<name>`. */
export function toolScopeGrant(toolName: string): string {
  assertSegment('toolName', toolName)
  return `tool:${toolName}`
}

/** The implementation-pin prefix, `tool:<name>:impl:`. */
export function implementationPinPrefix(toolName: string): string {
  return `${toolScopeGrant(toolName)}:impl:`
}

/** The declared-metadata-pin prefix, `tool:<name>:meta:`. */
export function metadataPinPrefix(toolName: string): string {
  return `${toolScopeGrant(toolName)}:meta:`
}

function assertSegment(label: string, value: string): void {
  if (typeof value !== 'string' || value.length === 0) {
    throw new CapabilityBindingError('SEGMENT_INVALID', `${label} must be a non-empty string`)
  }
}

/** Read the pin a grant's scope carries for one tool.
 *
 *  Returns `null` when the grant does not name the tool at all, which is a DIFFERENT
 *  ANSWER from a grant that names it and pins nothing. The second comes back as a
 *  `CapabilityPin` with both digest arrays empty. `evaluateCapabilityBinding` gives the two
 *  different reason codes, `TOOL_NOT_IN_GRANT_SCOPE` and `NO_CAPABILITY_PIN_IN_GRANT`, and
 *  collapsing them loses the distinction CAND-07 v2's unpinned limb is about.
 *
 *  Pins are returned in the order the grants appear, de-duplicated, and are NOT validated
 *  as digests: an unparseable pin value is a pin that will not match, which is a verdict,
 *  not an error. */
export function parseCapabilityPinFromScopeGrants(
  grants: readonly string[],
  toolName: string,
): CapabilityPin | null {
  if (!Array.isArray(grants)) {
    throw new CapabilityBindingError('GRANTS_INVALID', 'grants must be an array of strings')
  }
  const toolGrant = toolScopeGrant(toolName)
  if (!grants.includes(toolGrant)) return null
  const implPrefix = `${toolGrant}:impl:`
  const metaPrefix = `${toolGrant}:meta:`
  return Object.freeze({
    tool_name: toolName,
    implementation_digests: pinsUnder(grants, implPrefix),
    metadata_digests: pinsUnder(grants, metaPrefix),
    encoding: 'scope_grant_v0' as const,
  })
}

function pinsUnder(grants: readonly string[], prefix: string): readonly string[] {
  const seen = new Set<string>()
  for (const grant of grants) {
    if (typeof grant !== 'string') continue
    if (!grant.startsWith(prefix)) continue
    const value = grant.slice(prefix.length)
    if (value.length > 0) seen.add(value)
  }
  return Object.freeze([...seen])
}

/** Write a pin as scope grants, the inverse of `parseCapabilityPinFromScopeGrants`.
 *
 *  Returns the tool grant followed by one grant per pinned digest, sorted by UTF-8 bytes so
 *  a caller appending them to an existing grant array can keep the array canonical, which
 *  draft-03 section 3.2 requires of scope arrays. Refuses a pin whose `encoding` is not
 *  `scope_grant_v0`, because writing a `bound_record_v0` pin into a scope would be a
 *  silently different artifact. */
export function capabilityPinScopeGrants(pin: CapabilityPin): readonly string[] {
  if (pin === null || typeof pin !== 'object') {
    throw new CapabilityBindingError('PIN_INVALID', 'pin must be a CapabilityPin object')
  }
  if (pin.encoding !== 'scope_grant_v0') {
    throw new CapabilityBindingError(
      'PIN_ENCODING_UNSUPPORTED',
      `capabilityPinScopeGrants writes scope_grant_v0 only, not ${String(pin.encoding)}`,
    )
  }
  const toolGrant = toolScopeGrant(pin.tool_name)
  const out = [toolGrant]
  for (const digest of pin.implementation_digests ?? []) {
    assertSegment('implementation digest', digest)
    out.push(`${toolGrant}:impl:${digest}`)
  }
  for (const digest of pin.metadata_digests ?? []) {
    assertSegment('metadata digest', digest)
    out.push(`${toolGrant}:meta:${digest}`)
  }
  return Object.freeze(
    [...new Set(out)].sort((a, b) => (Buffer.from(a, 'utf8') < Buffer.from(b, 'utf8') ? -1 : 1)),
  )
}

/** Whether a pin pins nothing. CAND-07 v2's unpinned limb turns on exactly this. */
export function capabilityPinIsEmpty(pin: CapabilityPin): boolean {
  return pin.implementation_digests.length === 0 && pin.metadata_digests.length === 0
}
