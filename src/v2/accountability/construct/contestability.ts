// Copyright 2024-2026 Tymofii Pidlisnyi. Apache-2.0 license. See LICENSE.
// ══════════════════════════════════════════════════════════════════
// ContestabilityReceipt — construction
// ══════════════════════════════════════════════════════════════════
// At filing time: receipt_id and outer signature are computed over the
// receipt with NO controller_response present. This locks the
// contestants claim independently of any later controller response.
//
// attachControllerResponse re-issues the receipt by adding an
// independently-signed controller_response. The outer (contestant)
// signature is unchanged; the response_signature is computed over
// JCS(receipt with controller_response present and response_signature
// emptied), so anyone with both DIDs can verify the two assertions
// separately.
// ══════════════════════════════════════════════════════════════════

import { createHash } from 'node:crypto'
import { canonicalizeJCS } from '../../../core/canonical-jcs.js'
import { sign, publicKeyFromPrivate } from '../../../crypto/keys.js'
import type {
  ContestabilityReceipt,
  ContestabilityControllerResponse,
} from '../types/contestability.js'

export type CreateContestabilityReceiptInput = Omit<
  ContestabilityReceipt,
  | 'receipt_id'
  | 'signature'
  | 'signer_did'
  | 'timestamp'
  | 'claim_type'
  | 'controller_response'
> & {
  /** Optional override; defaults to new Date().toISOString(). */
  timestamp?: string
}

export function createContestabilityReceipt(
  input: CreateContestabilityReceiptInput,
  contestantPrivateKey: string,
): ContestabilityReceipt {
  if (
    (input.contestant.did === undefined || input.contestant.did === '') &&
    (input.contestant.pseudonym_hash === undefined || input.contestant.pseudonym_hash === '')
  ) {
    throw new Error(
      'createContestabilityReceipt: contestant must have at least one of did or pseudonym_hash',
    )
  }

  const signer_did = publicKeyFromPrivate(contestantPrivateKey)
  const timestamp = input.timestamp ?? new Date().toISOString()

  const draft: ContestabilityReceipt = {
    claim_type: 'aps:contestability:v1',
    receipt_id: '',
    timestamp,
    signer_did,
    scope_of_claim: input.scope_of_claim,
    contestant: input.contestant,
    action_id: input.action_id,
    grounds: input.grounds,
    requested_remedy: input.requested_remedy,
    signature: '',
  }

  const receipt_id = createHash('sha256')
    .update(canonicalizeJCS(draft), 'utf8')
    .digest('hex')

  const signed: ContestabilityReceipt = { ...draft, receipt_id }
  const signature = sign(canonicalizeJCS(signed), contestantPrivateKey)

  return { ...signed, signature }
}

export type ControllerResponseInput = Omit<
  ContestabilityControllerResponse,
  'response_signature'
>

export function attachControllerResponse(
  receipt: ContestabilityReceipt,
  response: ControllerResponseInput,
  controllerPrivateKey: string,
): ContestabilityReceipt {
  // Build the receipt as it will exist post-attach but with the
  // response_signature placeholder, then sign that canonical form.
  const responseDraft: ContestabilityControllerResponse = {
    ...response,
    response_signature: '',
  }
  const receiptDraft: ContestabilityReceipt = {
    ...receipt,
    controller_response: responseDraft,
  }
  const response_signature = sign(canonicalizeJCS(receiptDraft), controllerPrivateKey)

  return {
    ...receipt,
    controller_response: { ...response, response_signature },
  }
}
