// Human Values Floor — Attestation, Compliance, and Negotiation
// Layer 2 of the Agent Social Contract
//
// Design philosophy:
//   The Floor produces FACTS, not opinions.
//   "This principle is technically enforced" = fact.
//   "This agent is 94.3% compliant" = opinion disguised as fact.
//   We produce the former. Consumers interpret the latter.

import { v4 as uuidv4 } from 'uuid'
import { readFileSync } from 'node:fs'
import { sign, verify } from '../crypto/keys.js'
import { canonicalize } from './canonical.js'
import { scopeAuthorizes } from './delegation.js'
import { ENFORCEMENT_ESCALATION_ORDER } from '../types/passport.js'
import type {
  ValuesFloor, FloorPrinciple, FloorAttestation,
  ComplianceCheck, ComplianceReport, SharedGround,
  AgentPassport, ActionReceipt, SignedPassport,
  EnforcementMode
} from '../types/passport.js'

// ══════════════════════════════════════
// FLOOR LOADING
// ══════════════════════════════════════

/**
 * Parse the Values Floor from a JSON object.
 * 
 * v2 design: JSON, not YAML. The floor is a protocol artifact,
 * not a config file. JSON is unambiguous, universally parseable,
 * and requires zero dependencies. Every language on earth can
 * read JSON. Not every language can read YAML the same way.
 * 
 * We still support YAML for human authoring (loadFloorFromYaml),
 * but the canonical representation is JSON.
 */
export function loadFloor(input: string): ValuesFloor {
  // Try JSON first (canonical format)
  try {
    const parsed = JSON.parse(input)
    if (parsed.floor && Array.isArray(parsed.floor)) {
      return parsed as ValuesFloor
    }
  } catch {
    // Not JSON — try YAML
  }

  return parseYamlFloor(input)
}

export function loadFloorFromFile(filePath: string): ValuesFloor {
  const content = readFileSync(filePath, 'utf-8')
  return loadFloor(content)
}

/**
 * Minimal YAML parser for the floor manifest.
 * Handles our specific structure only. For complex YAML, convert to JSON first.
 */
function parseYamlFloor(yamlContent: string): ValuesFloor {
  const lines = yamlContent.split('\n')
  const floor: ValuesFloor = {
    version: '',
    schema: '',
    lastUpdated: '',
    governanceUri: '',
    floor: []
  }

  let currentPrinciple: Partial<FloorPrinciple> | null = null
  let inFloor = false
  let inEnforcement = false
  let inSection = false  // true once we enter 'floor:' or 'extensions:'

  for (const line of lines) {
    const trimmed = line.trim()
    if (trimmed.startsWith('#') || trimmed === '') continue

    // Top-level fields — only before entering a section
    if (!inSection) {
      if (trimmed.startsWith('version:')) { floor.version = extractVal(trimmed); continue }
      if (trimmed.startsWith('schema:')) { floor.schema = extractVal(trimmed); continue }
      if (trimmed.startsWith('last_updated:')) { floor.lastUpdated = extractVal(trimmed); continue }
      if (trimmed.startsWith('governance_uri:')) { floor.governanceUri = extractVal(trimmed); continue }
    }

    if (trimmed === 'floor:') { inFloor = true; inSection = true; continue }
    if (inFloor && (trimmed.startsWith('extensions:') || trimmed.startsWith('integration:'))) {
      inFloor = false; continue
    }

    if (inFloor) {
      if (trimmed.startsWith('- id:')) {
        if (currentPrinciple?.id) floor.floor.push(currentPrinciple as FloorPrinciple)
        currentPrinciple = {
          id: extractVal(trimmed.slice(2)),
          enforcement: { technical: false, mechanism: '' } as FloorPrinciple['enforcement'],
          weight: 'mandatory'
        }
        inEnforcement = false
      }
      if (currentPrinciple) {
        if (trimmed.startsWith('name:')) currentPrinciple.name = extractVal(trimmed)
        if (trimmed.startsWith('weight:')) currentPrinciple.weight = extractVal(trimmed) as FloorPrinciple['weight']
        if (trimmed.startsWith('principle:') && !trimmed.endsWith('>')) {
          currentPrinciple.principle = extractVal(trimmed)
        }
        if (trimmed === 'enforcement:') { inEnforcement = true; continue }
        if (inEnforcement) {
          if (trimmed.startsWith('mode:')) {
            const mode = extractVal(trimmed)
            if (mode === 'inline' || mode === 'audit' || mode === 'warn') {
              currentPrinciple.enforcement!.mode = mode
            }
          }
          if (trimmed.startsWith('technical:')) currentPrinciple.enforcement!.technical = trimmed.includes('true')
          if (trimmed.startsWith('mechanism:')) currentPrinciple.enforcement!.mechanism = extractVal(trimmed)
          if (trimmed.startsWith('protocol_ref:')) currentPrinciple.enforcement!.protocolRef = extractVal(trimmed)
        }
      }
    }
  }
  if (currentPrinciple?.id) floor.floor.push(currentPrinciple as FloorPrinciple)

  // Post-process: resolve enforcement modes for backward compat
  // Old YAML with technical: true/false gets mapped to mode: inline/audit
  for (const p of floor.floor) {
    if (!p.enforcement.mode) {
      p.enforcement.mode = resolveEnforcementMode(p.enforcement)
    }
  }

  return floor
}

function extractVal(line: string): string {
  const i = line.indexOf(':')
  if (i === -1) return ''
  let v = line.slice(i + 1).trim()
  if ((v.startsWith('"') && v.endsWith('"')) || (v.startsWith("'") && v.endsWith("'"))) {
    v = v.slice(1, -1)
  }
  return v
}

// ══════════════════════════════════════
// ENFORCEMENT MODE RESOLUTION
// ══════════════════════════════════════

/**
 * Resolve the effective enforcement mode for a principle.
 * 
 * Handles backward compatibility:
 *   - mode present → use it
 *   - mode absent, technical: true → 'inline'
 *   - mode absent, technical: false → 'audit'
 *   - nothing → 'audit' (safe default: log but don't block)
 */
export function resolveEnforcementMode(
  enforcement: FloorPrinciple['enforcement']
): EnforcementMode {
  if (enforcement.mode) return enforcement.mode
  if (enforcement.technical === true) return 'inline'
  if (enforcement.technical === false) return 'audit'
  return 'audit'
}

/**
 * Compute the effective enforcement mode across floor + extensions.
 * 
 * Strictness ordering: inline > warn > audit
 * Extensions can only escalate (audit→warn→inline), never de-escalate.
 * The strictest mode wins.
 * 
 * This is the core narrowing rule: if the floor says 'audit' and
 * an extension says 'inline', the effective mode is 'inline'.
 * If the floor says 'inline', nothing can weaken it.
 */
export function effectiveEnforcementMode(
  floorMode: EnforcementMode,
  ...extensionModes: EnforcementMode[]
): EnforcementMode {
  const all = [floorMode, ...extensionModes]
  return all.reduce((strictest, current) =>
    ENFORCEMENT_ESCALATION_ORDER[current] > ENFORCEMENT_ESCALATION_ORDER[strictest]
      ? current
      : strictest
  )
}

// ══════════════════════════════════════
// FLOOR ATTESTATION
// ══════════════════════════════════════

/**
 * An attestation is minimal: agent signs {floorVersion, extensions, timestamp}.
 * That's it. No performative commitment text.
 * 
 * The attestation says: "I recognize this floor version."
 * The receipts say: "Here's what I actually did."
 * The compliance check compares the two.
 * 
 * Truth is in the receipts, not in the attestation.
 */
export function attestFloor(
  agentId: string,
  publicKey: string,
  floorVersion: string,
  extensions: string[],
  privateKey: string,
  expiresInDays: number = 365
): FloorAttestation {
  const now = new Date()
  const expiry = new Date(now)
  expiry.setDate(expiry.getDate() + expiresInDays)

  const attestation: Omit<FloorAttestation, 'signature'> = {
    attestationId: 'att_' + uuidv4().slice(0, 12),
    agentId,
    publicKey,
    floorVersion,
    extensions,
    attestedAt: now.toISOString(),
    expiresAt: expiry.toISOString(),
    // Minimal commitment: what floor, what extensions, nothing more
    commitment: `floor:${floorVersion}|ext:${extensions.sort().join(',') || 'none'}|ts:${now.toISOString()}`
  }

  const canonical = canonicalize(attestation)
  const signature = sign(canonical, privateKey)

  return { ...attestation, signature }
}

export function verifyAttestation(
  attestation: FloorAttestation
): { valid: boolean; errors: string[] } {
  const errors: string[] = []

  const { signature, ...unsigned } = attestation
  const canonical = canonicalize(unsigned)
  if (!verify(canonical, signature, attestation.publicKey)) {
    errors.push('Invalid attestation signature')
  }

  if (new Date(attestation.expiresAt) < new Date()) {
    errors.push('Attestation expired')
  }

  if (!attestation.floorVersion) errors.push('No floor version specified')

  return { valid: errors.length === 0, errors }
}

// ══════════════════════════════════════
// COMPLIANCE — FACTS, NOT SCORES
// ══════════════════════════════════════

/**
 * Evaluate compliance by producing FACTS about each principle.
 * 
 * Previous version: returned overallCompliance: 0.943 (opinion).
 * This version: returns each principle's status as a verifiable fact,
 * PLUS a summary that separates what's proven from what's claimed.
 * 
 * The compliance report is evidence. What you do with evidence
 * is your decision — not the protocol's.
 */
export function evaluateCompliance(
  agentId: string,
  receipts: ActionReceipt[],
  floor: ValuesFloor,
  delegations: Map<string, { scope: string[]; revoked: boolean }>,
  verifierPrivateKey: string
): ComplianceReport {
  const agentReceipts = receipts.filter(r => r.agentId === agentId)
  const checks: ComplianceCheck[] = floor.floor.map(p =>
    evaluatePrinciple(p, agentReceipts, delegations)
  )

  const enforced = checks.filter(c => c.status === 'enforced').length
  const attested = checks.filter(c => c.status === 'attested').length
  const violations = checks.filter(c => c.status === 'violation').length
  const total = checks.length

  // We still compute a score because consumers need a number.
  // But we document what it means: fraction of principles with
  // no violations, weighted by enforcement type.
  // enforced = 1.0 (cryptographic proof), attested = 0.8 (claim without proof),
  // unverifiable = 0.5 (no data), violation = 0.0 (counter-evidence)
  const score = checks.reduce((sum, c) => {
    if (c.status === 'enforced') return sum + 1.0
    if (c.status === 'attested') return sum + 0.8
    if (c.status === 'unverifiable') return sum + 0.5
    return sum
  }, 0) / total

  const timestamps = agentReceipts.map(r => r.timestamp).sort()
  const report: Omit<ComplianceReport, 'signature'> = {
    reportId: 'comp_' + uuidv4().slice(0, 12),
    agentId,
    floorVersion: floor.version,
    period: {
      from: timestamps[0] || new Date().toISOString(),
      to: timestamps[timestamps.length - 1] || new Date().toISOString()
    },
    receiptsAnalyzed: agentReceipts.length,
    checks,
    overallCompliance: Math.round(score * 1000) / 1000,
    generatedAt: new Date().toISOString()
  }

  const canonical = canonicalize(report)
  const signature = sign(canonical, verifierPrivateKey)
  return { ...report, signature }
}

function evaluatePrinciple(
  principle: FloorPrinciple,
  receipts: ActionReceipt[],
  delegations: Map<string, { scope: string[]; revoked: boolean }>
): ComplianceCheck {
  const mode = resolveEnforcementMode(principle.enforcement)
  const base = { principleId: principle.id, principleName: principle.name, enforcementMode: mode }

  switch (principle.id) {
    case 'F-001': { // Traceability
      if (receipts.length === 0) return { ...base, status: 'unverifiable', detail: 'No receipts to analyze' }
      const traced = receipts.filter(r => r.delegationChain?.length > 0)
      return traced.length === receipts.length
        ? { ...base, status: 'enforced', detail: `All ${receipts.length} receipts have delegation chains`, evidence: receipts[0]?.receiptId }
        : { ...base, status: 'violation', detail: `${receipts.length - traced.length} receipts missing delegation chain` }
    }

    case 'F-002': { // Honest Identity
      const ids = new Set(receipts.map(r => r.agentId))
      return ids.size <= 1
        ? { ...base, status: 'enforced', detail: 'Consistent agent identity across all receipts' }
        : { ...base, status: 'violation', detail: `Multiple agent IDs: ${[...ids].join(', ')}` }
    }

    case 'F-003': { // Scoped Authority
      const bad = receipts.filter(r => {
        const d = delegations.get(r.delegationId)
        return d && !scopeAuthorizes(d.scope, r.action.scopeUsed)
      })
      return bad.length === 0
        ? { ...base, status: 'enforced', detail: 'All actions within delegated scope' }
        : { ...base, status: 'violation', detail: `${bad.length} out-of-scope actions`, evidence: bad[0].receiptId }
    }

    case 'F-004': { // Revocability
      const revoked = receipts.filter(r => delegations.get(r.delegationId)?.revoked)
      return revoked.length === 0
        ? { ...base, status: 'enforced', detail: 'No actions under revoked delegations' }
        : { ...base, status: 'violation', detail: `${revoked.length} actions under revoked delegations`, evidence: revoked[0].receiptId }
    }

    case 'F-005': { // Auditability
      if (receipts.length === 0) return { ...base, status: 'unverifiable', detail: 'No receipts to audit' }
      const signed = receipts.filter(r => r.signature?.length > 0)
      return signed.length === receipts.length
        ? { ...base, status: 'enforced', detail: `All ${receipts.length} receipts cryptographically signed` }
        : { ...base, status: 'violation', detail: 'Unsigned receipts found' }
    }

    case 'F-006': // Non-Deception
      return { ...base, status: 'attested', detail: 'Requires reasoning-level verification' }

    case 'F-007': // Proportionality
      return { ...base, status: 'attested', detail: 'Requires reputation context' }

    default:
      return { ...base, status: 'unverifiable', detail: `Unknown principle ${principle.id}` }
  }
}

// ══════════════════════════════════════
// COMMON GROUND NEGOTIATION
// ══════════════════════════════════════

/**
 * Determine shared ethical ground between two agents.
 * Simple: same major floor version + intersection of extensions.
 */
export function negotiateCommonGround(
  passportA: AgentPassport,
  attestationA: FloorAttestation,
  passportB: AgentPassport,
  attestationB: FloorAttestation
): SharedGround {
  const reasons: string[] = []

  if (new Date(attestationA.expiresAt) < new Date()) {
    reasons.push(`Agent ${passportA.agentId} attestation expired`)
  }
  if (new Date(attestationB.expiresAt) < new Date()) {
    reasons.push(`Agent ${passportB.agentId} attestation expired`)
  }

  const majorA = attestationA.floorVersion.split('.')[0]
  const majorB = attestationB.floorVersion.split('.')[0]
  const compatible = majorA === majorB

  if (!compatible) {
    reasons.push(`Incompatible floor versions: ${attestationA.floorVersion} vs ${attestationB.floorVersion}`)
  }

  const extA = new Set(attestationA.extensions)
  const shared = attestationB.extensions.filter(e => extA.has(e))

  return {
    floorVersion: compatible ? attestationA.floorVersion : null,
    sharedExtensions: shared,
    agentA: passportA.publicKey,
    agentB: passportB.publicKey,
    negotiatedAt: new Date().toISOString(),
    compatible: reasons.length === 0 && compatible,
    incompatibilityReasons: reasons
  }
}
