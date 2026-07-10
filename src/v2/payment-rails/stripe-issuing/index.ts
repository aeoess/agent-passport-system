// Copyright (c) 2026 Tymofii Pidlisnyi
// SPDX-License-Identifier: Apache-2.0
// ══════════════════════════════════════════════════════════════════
// Stripe Issuing — public SDK barrel
// ══════════════════════════════════════════════════════════════════
// The protocol primitives live in `./primitives.js`. The orchestration
// class `StripeIssuingRail` and its factory `createStripeIssuingRail`
// have moved to the private gateway repo at
// `aeoess-gateway/src/payment-rails/stripe-issuing/index.ts`. The SDK
// transferred to the Linux Foundation on AAIF acceptance carries only
// the protocol-defining surface; live HTTP, credential handling, and
// the in-memory card↔delegation registry are gateway product.
//
// Existing import paths through this file continue to work for the
// primitive surface. Callers that previously imported the class
// must now consume it from the gateway package.
// ══════════════════════════════════════════════════════════════════

export {
  DEFAULT_API_BASE,
  DEFAULT_REQUIRED_SCOPE,
  DEFAULT_TOLERANCE_SEC,
  RAIL_NAME,
  defaultMapDelegationToSpendingControls,
  delegationToView,
  encodeForm,
  verifyStripeSignature,
} from './primitives.js'

export type {
  Authorization,
  AuthorizationDecision,
  AuthorizationEvent,
  CardholderRef,
  DelegationLookup,
  FetchLike,
  MerchantData,
  SpendingControls,
  SpendingControlsMapper,
  SpendingLimit,
  SpendingLimitInterval,
  StripeIssuingConfig,
  VirtualCard,
} from './types.js'
