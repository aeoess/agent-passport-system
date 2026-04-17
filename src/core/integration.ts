// Copyright 2024-2026 Tymofii Pidlisnyi. Apache-2.0 license. See LICENSE.
/**
 * DEPRECATED — Layer integration bridges have moved to the AEOESS Gateway.
 *
 * The commerce↔intent, commerce↔attribution, commerce↔delegation, and
 * coordination↔agora bridges compose multiple protocol primitives into a
 * product runtime. They live at @aeoess/gateway
 * (src/sdk-migrated/core/integration.ts).
 *
 * Individual primitives (createActionIntent, evaluateIntent, commercePreflight,
 * verifyDelegation, createAgoraMessage, appendToFeed) remain exported from the
 * SDK and can be composed directly.
 *
 * See MIGRATION.md#data-lifecycle.
 */

const MOVED = 'Layer integration bridges moved to @aeoess/gateway. See MIGRATION.md#data-lifecycle'

export type CommerceIntentResult = never
export type DelegationValidationResult = never
export type CoordinationEventType = never

export function commerceWithIntent(..._args: unknown[]): never { throw new Error(MOVED) }
export function commerceReceiptToActionReceipt(..._args: unknown[]): never { throw new Error(MOVED) }
export function validateCommerceDelegation(..._args: unknown[]): never { throw new Error(MOVED) }
export function coordinationToAgora(..._args: unknown[]): never { throw new Error(MOVED) }
export function postTaskCreated(..._args: unknown[]): never { throw new Error(MOVED) }
export function postReviewCompleted(..._args: unknown[]): never { throw new Error(MOVED) }
export function postTaskCompleted(..._args: unknown[]): never { throw new Error(MOVED) }
