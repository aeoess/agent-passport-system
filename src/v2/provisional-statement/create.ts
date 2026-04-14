// Copyright 2024-2026 Tymofii Pidlisnyi. Apache-2.0 license. See LICENSE.
// ══════════════════════════════════════════════════════════════════
// Provisional Statement — createProvisional, withdrawProvisional, isBinding
// ══════════════════════════════════════════════════════════════════

import crypto from 'node:crypto'
import { sign, verify } from '../../crypto/keys.js'
import { canonicalize } from '../../core/canonical.js'
import { createHybridTimestamp } from '../../core/time.js'
import type { HybridTimestamp } from '../../types/time.js'
import type {
  ProvisionalStatement,
  AgentDID,
  PrincipalDID,
  Ed25519Signature,
} from './types.js'

/** Canonical payload an author signs to attest a provisional statement.
 *  Verifiers reconstruct this exact payload to check author_signature. */
export function statementSigningPayload(s: {
  id: string
  version: '1.0'
  author: AgentDID
  author_principal: PrincipalDID
  content: string
  created_at: HybridTimestamp
  dead_man_expires_at?: HybridTimestamp
}): string {
  return canonicalize({
    id: s.id,
    version: s.version,
    author: s.author,
    author_principal: s.author_principal,
    content: s.content,
    created_at: s.created_at,
    ...(s.dead_man_expires_at ? { dead_man_expires_at: s.dead_man_expires_at } : {}),
  })
}

export interface CreateProvisionalParams {
  author: AgentDID
  author_principal: PrincipalDID
  content: string
  /** Ed25519 private key (hex) controlling the author DID. */
  authorPrivateKey: string
  /** Gateway id used to stamp the hybrid timestamp. */
  gatewayId: string
  /** Optional dead-man expiry. Construct via createHybridTimestamp or pass through. */
  dead_man_expires_at?: HybridTimestamp
  /** Override id for test determinism. */
  id?: string
}

export function createProvisional(params: CreateProvisionalParams): ProvisionalStatement {
  const id = params.id ?? crypto.randomBytes(16).toString('hex')
  const created_at = createHybridTimestamp(params.gatewayId)

  const base = {
    id,
    version: '1.0' as const,
    author: params.author,
    author_principal: params.author_principal,
    content: params.content,
    created_at,
    ...(params.dead_man_expires_at ? { dead_man_expires_at: params.dead_man_expires_at } : {}),
  }

  const author_signature = sign(statementSigningPayload(base), params.authorPrivateKey)

  return {
    ...base,
    status: 'provisional',
    author_signature,
  }
}

/** Returns true only for promoted statements with a verifying promotion.
 *  Provisional and withdrawn statements are never binding. This check
 *  does not re-verify the PromotionEvent signature — use verifyPromotion
 *  for the full cryptographic check. */
export function isBinding(statement: ProvisionalStatement): boolean {
  return statement.status === 'promoted' && !!statement.promotion
}

/** Verify the author's signature over the statement's signed fields.
 *  Returns false if the content or any signed field was tampered with
 *  after signing. */
export function verifyAuthorSignature(statement: ProvisionalStatement): boolean {
  const payload = statementSigningPayload(statement)
  return verify(payload, statement.author_signature, statement.author)
}

/** Withdraw a provisional statement. The caller must supply a signature
 *  from the author over the withdrawal payload. Already-promoted
 *  statements cannot be withdrawn. */
export function withdrawProvisional(
  statement: ProvisionalStatement,
  author_sig: Ed25519Signature,
): ProvisionalStatement {
  if (statement.status === 'promoted') {
    throw new Error('Cannot withdraw a promoted statement')
  }
  if (statement.status === 'withdrawn') {
    return statement
  }
  const payload = canonicalize({ action: 'withdraw', statement_id: statement.id })
  if (!verify(payload, author_sig, statement.author)) {
    throw new Error('Invalid withdrawal signature')
  }
  return { ...statement, status: 'withdrawn' }
}

/** Compute the withdrawal payload an author must sign. */
export function withdrawalPayload(statement_id: string): string {
  return canonicalize({ action: 'withdraw', statement_id })
}
