// Copyright (c) 2026 Tymofii Pidlisnyi
// SPDX-License-Identifier: Apache-2.0
//
// PROPOSED module, but these two functions are NOT new and NOT proposed. They are the
// hierarchical purpose helpers that have shipped in `src/core/data-lifecycle.ts` since
// before this module existed, re-exported here so that both reference SDKs agree on where
// purpose membership lives.
//
// WHY THE RE-EXPORT. The Python SDK had no port of either function. Adding them there under
// a `data_lifecycle` module, to hold two functions, would have put the same primitive at two
// unrelated paths in the two languages, which becomes a cross-language test annoyance the
// first time a vector references it. Both SDKs now expose them from the bounds module, and
// the TypeScript original stays exported from its old path too, so nothing that imports it
// today changes.
//
// PURPOSE MEMBERSHIP IS NOT PURPOSE EXHAUSTION, and the distinction is the reason this file
// carries a comment at all. `isPurposePermitted` answers whether a requested purpose falls
// inside a set of allowed purposes. It answers `true` for the second compressor purchase
// exactly as it does for the first. Membership can therefore never decide exhaustion, and a
// boundary that checks only membership is the defective implementation the purpose-bound
// case corpus exists to catch. `evaluateBound` is the exhaustion question.

export { isPurposePermitted, purposeCategory } from '../../core/data-lifecycle.js'
