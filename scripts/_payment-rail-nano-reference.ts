// Copyright 2026 Tymofii Pidlisnyi. Apache-2.0 license. See LICENSE.
// Reference adapter shim for verify-payment-rail-conformance.mjs.
// Wires the bundled Nano reference rail with the default governance
// hooks and exposes them in the shape the verifier expects.
//
// Run via:
//   npx tsx scripts/verify-payment-rail-conformance.mjs \
//     scripts/_payment-rail-nano-reference.ts

import {
  createDefaultGovernanceHooks,
  createNanoRail,
} from '../src/v2/payment-rails/index.js'

export const rail = createNanoRail({
  receivingAddress:
    'nano_3test1f1xt7r3y6a7z9k1c0nv8d4yhfk93rcd6b1pmce8wkqf6kpunkfxnwd',
  fetchHistory: async () => [],
  fetchBlockInfo: async () => ({ confirmed: 'true', amount: '0' }),
})

export const hooks = createDefaultGovernanceHooks()
