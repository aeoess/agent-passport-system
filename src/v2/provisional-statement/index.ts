// Copyright (c) 2026 Tymofii Pidlisnyi
// SPDX-License-Identifier: Apache-2.0
// Provisional Statement — public surface

export type {
  ProvisionalStatement,
  PromotionEvent,
  PromotionPolicy,
  PromotionKind,
  ProvisionalStatus,
  PromotionVerifyResult,
  AgentDID,
  PrincipalDID,
  Ed25519Signature,
  Duration,
} from './types.js'

export {
  createProvisional,
  isBinding,
  verifyAuthorSignature,
  withdrawProvisional,
  withdrawalPayload,
  statementSigningPayload,
} from './create.js'
export type { CreateProvisionalParams } from './create.js'

export { promoteStatement, processDeadMan, promotionSigningPayload } from './promote.js'

export { verifyPromotion } from './verify.js'
