// Copyright (c) 2026 Tymofii Pidlisnyi
// SPDX-License-Identifier: Apache-2.0
//
// PROPOSED, OPT-IN authority state markers, write fencing and revocation withdrawal.
// Nothing here is required by draft-pidlisnyi-aps-03 and nothing here changes any existing
// exported behaviour. Concept source: aeoess/agent-authority-lifecycle, invariant candidates
// CAND-08 and CAND-02.

export * from './types.js'
export * from './marker.js'
export * from './retained.js'
export * from './fencing.js'
export * from './withdrawal.js'
export * from './report.js'
