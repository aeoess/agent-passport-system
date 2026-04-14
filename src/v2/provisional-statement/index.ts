// Copyright 2024-2026 Tymofii Pidlisnyi. Apache-2.0 license. See LICENSE.
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
