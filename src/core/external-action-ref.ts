// Copyright (c) 2026 Tymofii Pidlisnyi
// SPDX-License-Identifier: Apache-2.0
// ══════════════════════════════════════════════════════════════════
// External action_ref (action-ref-v1-jcs-sha256): Cross-Ecosystem Correlation Key
// ══════════════════════════════════════════════════════════════════
// This is the cross-ecosystem correlation key. It is NOT the APS-native
// action_ref.
//
// The APS-native action_ref (computeActionRef, draft-pidlisnyi-aps-01 §4.1)
// and this external key are distinct primitives with intentionally different
// preimages. Use computeActionRef for APS receipts and request equivalence.
// Use this helper only to correlate an APS action with the external
// action-ref-v1 form computed by independent ecosystem implementations
// (see docs/specs/action-ref-v1.md and conformance/action-ref-v1/).
//
// Differences from the APS-native §4.1 form:
//   - snake_case preimage keys {action_type, agent_id, scope, timestamp}
//   - scope is a single string, not the APS multi-scope array
//   - the input domain below, which the APS-native form does not share
//   - timestamp is an RFC 3339 date-time in UTC at exactly millisecond
//     precision (three fractional-second digits and a literal Z), hashed as
//     the byte sequence supplied and never normalized. Second 60 is accepted
//     at 23:59 on the last day of any month in the proleptic Gregorian
//     calendar. No leap-second table is consulted, although RFC 3339 section
//     5.7 allows second 60 only where a leap second occurs. Every other
//     second-60 value is invalid, and
//     the year-month-day must otherwise name a day that exists under that
//     calendar. A non-conforming value (wrong shape, non-string, a
//     calendar-invalid date, or an out-of-place second-60 value) is
//     rejected, never coerced, truncated, extended or renormalized.
//
// INPUT DOMAIN. The argentum-core specification this profile tracks
// (docs/spec/action-ref.md, the "Domain" paragraph) pins one closed input
// domain for the profile and requires a verifier to return
// OUT_OF_PROFILE_DOMAIN and stop BEFORE any digest when a preimage falls
// outside it. This helper enforces those checks except for the timestamp
// differences documented in docs/specs/action-ref-v1.md. There is no
// "canonicalize it some other way" fallback.
//
// PINNED REFERENCE REVISION. Everything this file claims about the profile
// was read from giskard09/argentum-core at commit
// 6ceecf5442fb9a573fdc87a0559755437a7f379f
// (docs/spec/action-ref.md, with the 2026-07-29, 2026-08-15 and 2026-08-16
// entries, and the reference validator
// plugins/agt_evidence_anchor/action_ref.py::_validate_domain). That one
// revision is the only reference revision cited anywhere in this profile's
// code, docs and vectors. Where this implementation's timestamp acceptance
// differs from that validator's, the differences are stated as facts in
// docs/specs/action-ref-v1.md, "Differences from the reference validator".
//
// Enforced here, in computeExternalActionRefV1 and
// parseExternalActionRefV1Preimage only:
//   - agent_id, action_type, scope are ASCII only, every code point <= 0x7F.
//     This closes the NFC/NFD normalization ambiguity by construction (the
//     two forms diverge only on non-ASCII code points, so neither can reach
//     the preimage) and subsumes the surrogate-pair case.
//   - scope is non-empty. The `""` "not applicable" exception was removed
//     from the specification on 2026-08-15 to match the published I-D
//     draft-etcheverry-action-ref-02 §6 ("free-form non-empty string").
//   - a duplicate preimage key is OUT_OF_PROFILE_DOMAIN, detected while the
//     bytes still carry the evidence; see parseExternalActionRefV1Preimage.
// The general canonicalization in canonical-jcs.ts is deliberately untouched
// by all of this: the domain belongs to this profile, not to JCS.
// ══════════════════════════════════════════════════════════════════

import { canonicalHashJCS } from './canonical-jcs.js'

// Canonical external timestamp shape: RFC 3339 UTC, exactly three
// fractional-second digits, mandatory Z, second 00-60 in the grammar.
// Calendar validity (day-in-month) and the second-60 rule (accepted at
// 23:59 on any month's last day, with no leap-second table) are
// checked separately below, since a regex cannot encode "30 is invalid in
// February" or "this 23:59:60 is not on the last day".
const EXTERNAL_TS =
  /^([0-9]{4})-(0[1-9]|1[0-2])-(0[1-9]|[12][0-9]|3[01])T([01][0-9]|2[0-3]):([0-5][0-9]):([0-5][0-9]|60)\.[0-9]{3}Z$/

/** Input to computeExternalActionRefV1. */
export interface ExternalActionRefV1Input {
  /** External action type, e.g. "payment.send". */
  actionType: string
  /** Agent identifier as the external ecosystem expects it. */
  agentId: string
  /** A single scope string. This differs from the APS-native action_ref,
   *  whose scopeRequired is a multi-scope array. */
  scope: string
  /** Millisecond RFC 3339 UTC instant (YYYY-MM-DDTHH:MM:SS.mmmZ). A canonical
   *  string is hashed as-is; a Date is rendered to the canonical form via
   *  toISOString. Any other string shape is rejected rather than coerced, so
   *  acceptance matches the aps-broker verifier. */
  timestamp: string | Date
}

/** True if `year` is a leap year under the proleptic Gregorian calendar
 *  (divisible by 4 and not by 100, or divisible by 400; year 0000 is a
 *  leap year). */
function isLeapYear(year: number): boolean {
  return (year % 4 === 0 && year % 100 !== 0) || year % 400 === 0
}

/** Days in `month` (1-12) of `year` under the proleptic Gregorian calendar. */
function daysInMonth(year: number, month: number): number {
  const lengths = [31, isLeapYear(year) ? 29 : 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31]
  return lengths[month - 1]
}

// Never validate a timestamp string with Date: Date cannot represent a
// leap-second (:60) value, so it would reject the month-end second-60 values
// this helper has always accepted.
//
// Every rejection below is a domain rejection and carries
// OUT_OF_PROFILE_DOMAIN: the timestamp grammar and calendar rules ARE part of
// the profile's input domain, not a separate well-formedness layer, so a
// caller matching on the marker catches them alongside the ASCII, empty-scope
// and duplicate-key refusals.
function validateTimestampString(ts: string): string {
  const match = EXTERNAL_TS.exec(ts)
  if (!match) {
    throw new Error(
      `computeExternalActionRefV1: OUT_OF_PROFILE_DOMAIN: timestamp must be RFC 3339 UTC with three fractional digits and a Z suffix (YYYY-MM-DDTHH:MM:SS.mmmZ), got ${JSON.stringify(ts)}`,
    )
  }
  const year = Number(match[1])
  const month = Number(match[2])
  const day = Number(match[3])
  const hour = Number(match[4])
  const minute = Number(match[5])
  const second = Number(match[6])
  const maxDay = daysInMonth(year, month)
  if (day > maxDay) {
    throw new Error(
      `computeExternalActionRefV1: OUT_OF_PROFILE_DOMAIN: timestamp names a day that does not exist in that month, got ${JSON.stringify(ts)}`,
    )
  }
  if (second === 60 && !(hour === 23 && minute === 59 && day === maxDay)) {
    throw new Error(
      `computeExternalActionRefV1: OUT_OF_PROFILE_DOMAIN: timestamp has second 60 outside 23:59 on the last day of its month, got ${JSON.stringify(ts)}`,
    )
  }
  return ts
}

function externalTimestamp(ts: string | Date): string {
  if (ts instanceof Date) {
    if (Number.isNaN(ts.getTime())) {
      throw new Error(
        'computeExternalActionRefV1: OUT_OF_PROFILE_DOMAIN: invalid Date timestamp',
      )
    }
    // A Date outside years 0000-9999 renders via toISOString with an
    // expanded year (e.g. "+010000-01-01T00:00:00.000Z"), which the string
    // check below rejects rather than hashes -- as an OUT_OF_PROFILE_DOMAIN
    // grammar failure, since an expanded year is not the profile's shape.
    return validateTimestampString(ts.toISOString())
  }
  if (typeof ts !== 'string') {
    throw new Error(
      'computeExternalActionRefV1: OUT_OF_PROFILE_DOMAIN: timestamp must be a string or a Date',
    )
  }
  return validateTimestampString(ts)
}

/** Reject a non-ASCII field value with OUT_OF_PROFILE_DOMAIN.
 *
 *  Iterates UTF-16 code units, not code points: every unit of a non-ASCII
 *  code point is itself above 0x7F, so a surrogate pair (paired or lone) is
 *  rejected on its first unit and no case can slip through a code-point
 *  reinterpretation. `field` is the camelCase input property; `preimageKey`
 *  is the snake_case name it occupies in the hashed preimage, so the message
 *  names the field in both vocabularies a caller may be reading.
 */
function assertAsciiDomain(field: string, preimageKey: string, value: string): void {
  for (let i = 0; i < value.length; i++) {
    const unit = value.charCodeAt(i)
    if (unit > 0x7f) {
      throw new Error(
        `computeExternalActionRefV1: OUT_OF_PROFILE_DOMAIN: ${field} (preimage ${preimageKey}) must be ASCII only, every code point <= 0x7F; found U+${unit.toString(16).toUpperCase().padStart(4, '0')} at index ${i}`,
      )
    }
  }
}

/**
 * Compute the external cross-ecosystem correlation key
 * (action-ref-v1-jcs-sha256): lowercase-hex SHA-256 of the RFC 8785 JCS
 * canonicalization of {action_type, agent_id, scope, timestamp}.
 *
 * Rejects a preimage outside the profile's input domain (see the file header)
 * with OUT_OF_PROFILE_DOMAIN, before any digest is computed: a non-string
 * field, a non-ASCII agentId, actionType or scope, an empty scope, and any
 * timestamp that fails the grammar or the calendar rules (including a Date
 * that is invalid or renders outside years 0000-9999).
 *
 * EVERY rejection carries OUT_OF_PROFILE_DOMAIN. The marker is the single
 * check a caller needs to tell "this input is not in the profile" from any
 * other error, so no domain failure is left for prose matching.
 *
 * This is NOT the APS-native action_ref. See the file header for the preimage
 * differences. Use computeActionRef for APS-native receipts and equivalence.
 *
 * Returns: lowercase hex SHA-256 digest.
 */
export function computeExternalActionRefV1(input: ExternalActionRefV1Input): string {
  if (typeof input.actionType !== 'string') {
    throw new Error(
      'computeExternalActionRefV1: OUT_OF_PROFILE_DOMAIN: actionType must be a string',
    )
  }
  if (typeof input.agentId !== 'string') {
    throw new Error(
      'computeExternalActionRefV1: OUT_OF_PROFILE_DOMAIN: agentId must be a string',
    )
  }
  if (typeof input.scope !== 'string') {
    throw new Error(
      'computeExternalActionRefV1: OUT_OF_PROFILE_DOMAIN: scope must be a string',
    )
  }
  // Domain order follows the reference validator's _validate_domain: ASCII
  // over the three string fields first, then the scope non-empty rule, then
  // the timestamp grammar (inside externalTimestamp, below).
  assertAsciiDomain('agentId', 'agent_id', input.agentId)
  assertAsciiDomain('actionType', 'action_type', input.actionType)
  assertAsciiDomain('scope', 'scope', input.scope)
  if (input.scope === '') {
    throw new Error(
      'computeExternalActionRefV1: OUT_OF_PROFILE_DOMAIN: scope (preimage scope) must be a non-empty string; the "" not-applicable exception was removed from the profile on 2026-08-15',
    )
  }
  return canonicalHashJCS({
    action_type: input.actionType,
    agent_id: input.agentId,
    scope: input.scope,
    timestamp: externalTimestamp(input.timestamp),
  })
}

// ── Serialized entry point ─────────────────────────────────────────
// Duplicate preimage keys are OUT_OF_PROFILE_DOMAIN per the spec's Domain
// paragraph, and that fact only exists in the byte stream: by the time JSON
// has become a JavaScript object the second "agent_id" has overwritten the
// first and the evidence is gone, so no check inside
// computeExternalActionRefV1, which receives an already-parsed input, could
// ever see it. Hence a parsing entry point.
//
// The scan below is deliberately self-contained: no dependency, and no reuse
// of the stricter I-JSON parser in src/v2/receipt-core/jcs.ts, whose bounds
// and error taxonomy belong to the receipt-core profile rather than to this
// cross-ecosystem helper.

const JSON_WS = new Set([' ', '\t', '\n', '\r'])

/** Top-level member names of a well-formed JSON object text, in document
 *  order, rejecting a name that repeats after JSON string decoding (so "a"
 *  and "a" are the same name).
 *
 *  Only ever called on text JSON.parse has already accepted, so it scans
 *  rather than validates: the structural errors it can still raise are
 *  defensive, not reachable through parseExternalActionRefV1Preimage.
 */
function scanTopLevelKeys(json: string): string[] {
  let i = 0
  const skipWhitespace = (): void => {
    while (i < json.length && JSON_WS.has(json[i])) i++
  }
  // Decodes the string token starting at json[i] === '"' and leaves i just
  // past its closing quote. JSON.parse does the unescaping, so an escaped
  // \u0061 decodes to "a" and the duplicate comparison below is over decoded
  // names, not over the raw member-name bytes.
  const readString = (): string => {
    const start = i
    i++
    while (i < json.length) {
      const ch = json[i]
      if (ch === '\\') {
        i += 2
        continue
      }
      i++
      if (ch === '"') return JSON.parse(json.slice(start, i)) as string
    }
    throw new Error(
      'parseExternalActionRefV1Preimage: OUT_OF_PROFILE_DOMAIN: unterminated JSON string',
    )
  }
  // Advances i past one complete value without interpreting it.
  const skipValue = (): void => {
    skipWhitespace()
    const ch = json[i]
    if (ch === '"') {
      readString()
      return
    }
    if (ch === '{' || ch === '[') {
      let depth = 0
      while (i < json.length) {
        const c = json[i]
        if (c === '"') {
          readString()
          continue
        }
        if (c === '{' || c === '[') depth++
        else if (c === '}' || c === ']') depth--
        i++
        if (depth === 0) return
      }
      throw new Error(
        'parseExternalActionRefV1Preimage: OUT_OF_PROFILE_DOMAIN: unterminated JSON structure',
      )
    }
    // A number, true, false or null runs to the next structural character.
    while (i < json.length && json[i] !== ',' && json[i] !== '}' && !JSON_WS.has(json[i])) i++
  }

  skipWhitespace()
  if (json[i] !== '{') {
    throw new Error(
      'parseExternalActionRefV1Preimage: OUT_OF_PROFILE_DOMAIN: expected a JSON object',
    )
  }
  i++
  const names: string[] = []
  const seen = new Set<string>()
  skipWhitespace()
  if (json[i] === '}') return names
  for (;;) {
    skipWhitespace()
    if (json[i] !== '"') {
      throw new Error(
        'parseExternalActionRefV1Preimage: OUT_OF_PROFILE_DOMAIN: expected a member name',
      )
    }
    const name = readString()
    if (seen.has(name)) {
      throw new Error(
        `parseExternalActionRefV1Preimage: OUT_OF_PROFILE_DOMAIN: duplicate preimage key ${JSON.stringify(name)}; names are compared after JSON string decoding, so "a" and "\\u0061" are the same key`,
      )
    }
    seen.add(name)
    names.push(name)
    skipWhitespace()
    if (json[i] !== ':') {
      throw new Error(
        'parseExternalActionRefV1Preimage: OUT_OF_PROFILE_DOMAIN: expected a colon after a member name',
      )
    }
    i++
    skipValue()
    skipWhitespace()
    const separator = json[i]
    i++
    if (separator === '}') return names
    if (separator !== ',') {
      throw new Error(
        'parseExternalActionRefV1Preimage: OUT_OF_PROFILE_DOMAIN: expected a comma or the end of the object',
      )
    }
  }
}

/**
 * Parse one serialized snake_case preimage object into the camelCase input of
 * computeExternalActionRefV1.
 *
 * Enforces what only the bytes can answer: the top level must be a JSON
 * object (not an array, string, number, boolean or null), and no top-level
 * key may repeat. A repeated key is OUT_OF_PROFILE_DOMAIN per the spec's
 * Domain paragraph and is rejected here, before any digest exists. Names are
 * compared after JSON string decoding, so a plain `"a"` and an escaped
 * `"\u0061"` are the same key and collide.
 *
 * It does not type-check or domain-check the four values: those are
 * computeExternalActionRefV1's own checks and run unchanged when the result
 * is passed to it. A missing key therefore surfaces there, as the field's
 * "must be a string" rejection -- also marked OUT_OF_PROFILE_DOMAIN, so the
 * composition parse-then-compute marks every rejection either way.
 *
 * EVERY rejection here carries OUT_OF_PROFILE_DOMAIN, including a non-object
 * top level, malformed JSON and a non-string argument.
 */
export function parseExternalActionRefV1Preimage(json: string): ExternalActionRefV1Input {
  if (typeof json !== 'string') {
    throw new Error(
      'parseExternalActionRefV1Preimage: OUT_OF_PROFILE_DOMAIN: expected a JSON string',
    )
  }
  let parsed: unknown
  try {
    parsed = JSON.parse(json)
  } catch (error) {
    throw new Error(
      `parseExternalActionRefV1Preimage: OUT_OF_PROFILE_DOMAIN: invalid JSON: ${error instanceof Error ? error.message : String(error)}`,
    )
  }
  if (parsed === null || typeof parsed !== 'object' || Array.isArray(parsed)) {
    throw new Error(
      `parseExternalActionRefV1Preimage: OUT_OF_PROFILE_DOMAIN: the preimage must be a JSON object, got ${Array.isArray(parsed) ? 'an array' : parsed === null ? 'null' : `a ${typeof parsed}`}`,
    )
  }
  scanTopLevelKeys(json)
  const record = parsed as Record<string, unknown>
  return {
    actionType: record.action_type as string,
    agentId: record.agent_id as string,
    scope: record.scope as string,
    timestamp: record.timestamp as string,
  }
}
