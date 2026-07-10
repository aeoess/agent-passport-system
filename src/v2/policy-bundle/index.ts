// Copyright (c) 2026 Tymofii Pidlisnyi
// SPDX-License-Identifier: Apache-2.0
/**
 * Signed, content-addressed policy-bundle primitive. Public surface.
 *
 * Format and verifier only. No registry, no resolver service, no lockfile
 * service, no transparency-log backend. Those are gateway product and live
 * outside this SDK.
 *
 * See ./bundle.ts for the proof box: what a valid bundle proves and what it
 * does NOT prove.
 */

export {
  createPolicyBundle,
  verifyPolicyBundle,
  manifestHash,
  defaultPolicyBundleScope,
  serializePolicyBundle,
  parsePolicyBundle,
  bundleTarBytes,
} from './bundle.js'

export type {
  CreatePolicyBundleInput,
  PolicyBundleFileInput,
  VerifyPolicyBundleOptions,
} from './bundle.js'

export { packTar, unpackTar } from './tar.js'
export type { TarEntry } from './tar.js'

export type {
  PolicyBundleManifest,
  PolicyBundleEnvelope,
  PolicyBundleVerification,
  PolicyBundleFileEntry,
  PolicyBundleGovernance,
  ManifestHash,
} from './types.js'
