// Copyright (c) 2026 Tymofii Pidlisnyi
// SPDX-License-Identifier: Apache-2.0
// ══════════════════════════════════════════════════════════════════
// Human oversight as evidence (W2-B5): co-sign, break-glass, descriptor
// ══════════════════════════════════════════════════════════════════
// Records human oversight on a general (NON-bilateral) signed receipt as
// evidence, and lets a verifier derive a mechanical-fact descriptor over
// it. Three additive, optional, versioned slots: co_signer,
// approval_reference, break_glass. A receipt that omits all three is
// byte-identical to its pre-slot form.
//
// EXTENDS, does not duplicate:
//   - For the BILATERAL case (two interacting agents co-sign one outcome)
//     use src/core/bilateral-receipt.ts. This module does NOT rebuild it.
//   - Reuses the destructure-then-canonicalize co-sign discipline of
//     verifyBilateralReceipt (bilateral-receipt.ts:101-102): signatures
//     are sibling fields; signed bytes are canonical(body minus the
//     co_signer slot), so a human and an agent both cover identical bytes.
//   - Reuses canonicalize (src/core/canonical.ts), sign/verify
//     (src/crypto/keys.ts), the EvidenceCommitment hash-binding pattern,
//     the four-valued Belnap ConstraintStatus (src/types/gateway.ts),
//     and the ApprovalSignature shape (src/types/approval.ts).
//
// Slots and verification only. Slack/ServiceNow integrations and any
// approval-workflow machinery are gateway operations and out of scope.
// break_glass is a FORMAT recorded as evidence, not machinery: nothing
// here notifies, escalates, or executes an override.
//
// ──────────────────────────── PROOF BOX ────────────────────────────
// Proves: a co-signed or break_glass receipt proves a named human
//   signature over the receipt body and the recorded approval reference.
//   Each co_signer entry that verifies proves the named DID signed the
//   exact canonical body the other signers signed.
// Does NOT prove: that the human understood what they approved; that the
//   approval workflow OUTSIDE the protocol (ticket, sign-off, on-call
//   page) occurred; that an independent signer is uncompromised; that a
//   break_glass override was warranted. A break_glass declaration records
//   that an override was claimed, not that it was justified or reviewed.
//   Independence is derived from the key and DID graph; it does not by
//   itself prevent collusion.
// Dogfood: buildOversightScopeOfClaim() returns a ScopeOfClaim
//   (src/v2/accountability/types/base.ts) mirroring this box for callers
//   that emit an accountability receipt over the oversight check.
// ════════════════════════════════════════════════════════════════════

import { canonicalize } from '../../core/canonical.js'
import { sign, verify } from '../../crypto/keys.js'
import type { ConstraintStatus } from '../../types/gateway.js'
import type { ScopeOfClaim } from '../accountability/types/base.js'
import type {
  CoSignerEntry,
  CoSignerRole,
  HumanOversightSlots,
  BreakGlass,
  ApprovalReference,
  CoSignerKeyResolution,
  SharesRoot,
} from './types.js'
import type {
  HumanOversightDescriptor,
  CoSignatureFact,
  ApprovalReferenceFact,
  ApprovalScheme,
  BreakGlassFact,
} from './descriptor.js'
import { computeIndependence, isSignerIndependent } from './descriptor.js'

export * from './types.js'
export * from './descriptor.js'

// ══════════════════════════════════════════════════════════════════
// Canonical co-sign body: destructure the co_signer slot, canonicalize
// ══════════════════════════════════════════════════════════════════

/**
 * The bytes a co-signer signs: canonical(receipt minus the co_signer
 * slot and minus the version marker). Every co-signer signs the SAME
 * string, exactly the discipline in bilateral-receipt.ts:101-102. The
 * approval_reference and break_glass slots ARE part of the signed body
 * (a human signs over the approval they reference and the override they
 * declare); only co_signer and the version marker are removed so the
 * signatures do not sign over each other.
 */
export function canonicalCoSignBody(receipt: Record<string, unknown>): string {
  const { co_signer, human_oversight_version, ...body } = receipt as Record<
    string,
    unknown
  > & Partial<HumanOversightSlots>
  void co_signer
  void human_oversight_version
  return canonicalize(body)
}

/**
 * Produce a co_signer entry by signing the canonical co-sign body of a
 * receipt. The receipt passed in MUST already carry whatever
 * approval_reference / break_glass slots are to be covered; pass the
 * receipt WITHOUT a co_signer slot (or with the prior entries; they are
 * stripped before signing so order does not matter).
 */
export function signAsCoSigner(opts: {
  receipt: Record<string, unknown>
  role: CoSignerRole
  keyClass: string
  privateKey: string
  publicKey: string
  did?: string
  signedAt?: string
}): CoSignerEntry {
  const canonical = canonicalCoSignBody(opts.receipt)
  return {
    publicKey: opts.publicKey,
    role: opts.role,
    keyClass: opts.keyClass,
    did: opts.did,
    signedAt: opts.signedAt ?? new Date().toISOString(),
    signature: sign(canonical, opts.privateKey),
  }
}

/**
 * Attach a co-signer entry to a receipt's co_signer slot, stamping the
 * versioned marker. Additive and pure: returns a new object. A receipt
 * with an empty/absent co_signer slot is byte-identical to its pre-slot
 * form for canonicalization purposes; only adding an entry changes it.
 */
export function attachCoSigner(
  receipt: Record<string, unknown>,
  entry: CoSignerEntry
): Record<string, unknown> & HumanOversightSlots {
  const existing = (receipt as Partial<HumanOversightSlots>).co_signer ?? []
  return {
    ...receipt,
    co_signer: [...existing, entry],
    human_oversight_version: '1.0',
  }
}

// ══════════════════════════════════════════════════════════════════
// Break-glass validation (FORMAT, not machinery)
// ══════════════════════════════════════════════════════════════════

const BREAK_GLASS_REQUIRED_KEYS: (keyof BreakGlass)[] = [
  'reason',
  'approved_by',
  'expires_at',
  'post_review_required',
]

/**
 * Validate a break_glass declaration as a format. Returns the mechanical
 * facts a verifier records: well formed, in force, class allowed, and the
 * rejection reasons. `forbiddenClasses` is the relying party's list of
 * action classes that may NOT be overridden by break-glass; a declaration
 * whose action_class is in that list is rejected.
 *
 * This does not run a workflow. It does not notify or escalate. It reads
 * the declaration and reports whether it is acceptable.
 */
export function validateBreakGlass(
  bg: BreakGlass,
  opts?: { forbiddenClasses?: string[]; now?: Date }
): BreakGlassFact {
  const rejections: string[] = []
  const now = (opts?.now ?? new Date()).getTime()

  let wellFormed = true
  for (const k of BREAK_GLASS_REQUIRED_KEYS) {
    if (bg[k] === undefined || bg[k] === null) {
      wellFormed = false
      rejections.push(`break_glass missing required field: ${k}`)
    }
  }
  if (typeof bg.reason === 'string' && bg.reason.trim() === '') {
    wellFormed = false
    rejections.push('break_glass reason is empty')
  }
  if (typeof bg.post_review_required !== 'boolean') {
    wellFormed = false
    rejections.push('break_glass post_review_required must be boolean')
  }

  let inForce = true
  const expMs = new Date(bg.expires_at).getTime()
  if (Number.isNaN(expMs)) {
    inForce = false
    wellFormed = false
    rejections.push('break_glass expires_at is not a valid ISO 8601 instant')
  } else if (expMs < now) {
    inForce = false
    rejections.push('break_glass declaration has expired')
  }

  const forbidden = opts?.forbiddenClasses ?? []
  let classAllowed = true
  if (bg.action_class !== undefined && forbidden.includes(bg.action_class)) {
    classAllowed = false
    rejections.push(
      `break_glass over forbidden class: ${bg.action_class}`
    )
  }

  return {
    present: true,
    wellFormed,
    inForce,
    classAllowed,
    postReviewRequired: bg.post_review_required === true,
    rejections,
  }
}

// ══════════════════════════════════════════════════════════════════
// Approval reference classification
// ══════════════════════════════════════════════════════════════════

/** Classify which existing request-id scheme an approval reference uses.
 *  'approval-<hex>' (commerce) or 'approval_<uuid12>' (charter). No third
 *  scheme is recognized; an unrecognized id is reported as such, not
 *  coined. */
export function classifyApprovalScheme(requestId: string): ApprovalScheme {
  if (/^approval-[0-9a-f]+$/.test(requestId)) return 'commerce_hex'
  if (/^approval_[0-9a-f-]{12}$/.test(requestId)) return 'charter_uuid'
  return 'unrecognized'
}

function describeApprovalReference(
  ref: ApprovalReference | undefined
): ApprovalReferenceFact {
  if (!ref) {
    return {
      present: false,
      scheme: 'unrecognized',
      commitmentPresent: false,
    }
  }
  return {
    present: true,
    requestId: ref.requestId,
    scheme: classifyApprovalScheme(ref.requestId),
    commitmentPresent: ref.commitment !== undefined,
  }
}

// ══════════════════════════════════════════════════════════════════
// Co-signature verification → per-signer Belnap facts
// ══════════════════════════════════════════════════════════════════

/**
 * Verify each co_signer entry over the canonical co-sign body and return
 * a Belnap-valued fact per signer. A key resolution may be supplied per
 * entry (by index) to verify against a DID-resolved key instead of the
 * entry's self-declared publicKey; absent that, the entry's own publicKey
 * is used. When no key is available, the status is 'unknown' (Belnap),
 * never silently 'pass'.
 */
export function verifyCoSignatures(
  receipt: Record<string, unknown>,
  resolutions?: (CoSignerKeyResolution | undefined)[]
): CoSignatureFact[] {
  const slots = receipt as Partial<HumanOversightSlots>
  const entries = slots.co_signer ?? []
  const canonical = canonicalCoSignBody(receipt)

  return entries.map((entry, i): CoSignatureFact => {
    const res = resolutions?.[i]
    const key = res?.publicKey ?? entry.publicKey
    let status: ConstraintStatus
    if (!entry.signature) {
      status = 'not_applicable'
    } else if (!key) {
      status = 'unknown'
    } else {
      status = verify(canonical, entry.signature, key) ? 'pass' : 'fail'
    }
    return {
      publicKey: entry.publicKey,
      role: entry.role,
      keyClass: entry.keyClass,
      did: res?.did ?? entry.did,
      status,
    }
  })
}

// ══════════════════════════════════════════════════════════════════
// Descriptor assembly (verifier OUTPUT)
// ══════════════════════════════════════════════════════════════════

/**
 * Derive the full human-oversight descriptor from a receipt's slots. This
 * is the verifier OUTPUT: a SET of mechanical facts. The single advisory
 * scalar on top is a relying-party-policy output, computed here, never
 * read from the receipt.
 */
export function deriveOversightDescriptor(
  receipt: Record<string, unknown>,
  opts?: {
    resolutions?: (CoSignerKeyResolution | undefined)[]
    sharesRoot?: SharesRoot
    forbiddenBreakGlassClasses?: string[]
    now?: Date
  }
): HumanOversightDescriptor {
  const slots = receipt as Partial<HumanOversightSlots>
  const entries = slots.co_signer ?? []

  const coSignatures = verifyCoSignatures(receipt, opts?.resolutions)
  const { edges, allIndependent } = computeIndependence(
    entries,
    opts?.sharesRoot
  )

  // A human signature is present only when an entry with role 'human'
  // verified ('pass'). Presence of a 'human' entry that did not verify
  // is NOT human oversight.
  const humanSignaturePresent = coSignatures.some(
    (f) => f.role === 'human' && f.status === 'pass'
  )

  const approvalReference = describeApprovalReference(slots.approval_reference)

  const breakGlass: BreakGlassFact = slots.break_glass
    ? validateBreakGlass(slots.break_glass, {
        forbiddenClasses: opts?.forbiddenBreakGlassClasses,
        now: opts?.now,
      })
    : {
        present: false,
        wellFormed: false,
        inForce: false,
        classAllowed: true,
        postReviewRequired: false,
        rejections: [],
      }

  // ── advisory scalar (relying-party-policy output) ──
  // True only when: a human signature verified, that human signer is
  // independent of every other recorded signer in the key and DID graph,
  // and any break_glass declaration is not rejected. Computed here; never
  // an issuer-set field.
  let advisory = false
  if (humanSignaturePresent) {
    const verifiedHumanEntries = entries.filter((e, i) => {
      const f = coSignatures[i]
      return e.role === 'human' && f && f.status === 'pass'
    })
    const someHumanIndependent = verifiedHumanEntries.some((e) =>
      isSignerIndependent(e, entries, opts?.sharesRoot)
    )
    const breakGlassOk = !breakGlass.present || breakGlass.rejections.length === 0
    advisory = someHumanIndependent && breakGlassOk
  }

  return {
    coSignatures,
    humanSignaturePresent,
    independence: edges,
    allSignersIndependent: allIndependent,
    approvalReference,
    breakGlass,
    advisory_independent_human_oversight: advisory,
  }
}

// ══════════════════════════════════════════════════════════════════
// Dogfood: ScopeOfClaim for an oversight check
// ══════════════════════════════════════════════════════════════════

/**
 * Return a ScopeOfClaim mirroring this module's PROOF BOX, for callers
 * that emit an accountability receipt over the oversight check. The
 * capture_mode and self_attested fields reflect the descriptor: when a
 * verified human signature is independent of the agent, the oversight is
 * not self-attested; otherwise it is.
 */
export function buildOversightScopeOfClaim(
  descriptor?: HumanOversightDescriptor
): ScopeOfClaim {
  const independentHuman =
    descriptor?.advisory_independent_human_oversight ?? false
  return {
    asserts:
      'A named human signature was recorded over this receipt body and ' +
      'the approval reference it carries; each verified co-signature ' +
      'covers the identical canonical body.',
    does_not_assert: [
      'that the human understood what they approved',
      'that an approval workflow outside the protocol occurred',
      'that an independent signer is uncompromised',
      'that a break_glass override was warranted or reviewed',
      'that recording independence prevents collusion',
    ],
    capture_mode: independentHuman ? 'gateway_observed' : 'self_attested',
    completeness: 'partial',
    self_attested: !independentHuman,
  }
}
