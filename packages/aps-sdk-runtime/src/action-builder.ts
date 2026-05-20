/**
 * `buildAction` — ergonomic helper to construct an `ActionInput` for
 * `check(handle, action)`.
 *
 * Handles the boring parts: generates a random 128-bit nonce, calls
 * `hashResourcePath` on the resource segments, and defaults
 * `version=1`, `resourceType=0`.
 */

import { randomBytes } from 'node:crypto';
import { authorityInfo, hashResourcePath } from '..';

export interface BuildActionOpts {
  handle: any; // ExternalObject<AuthorityHandle> — opaque
  toolDescriptorHashHex: string;
  localToolId: number;
  operationId: number;
  riskClass: number;
  resourcePath: string[];
  costUnits: number;
  sequenceId: bigint;
  /** Optional override for testing; otherwise a 16-byte random hex string. */
  nonceHex?: string;
  /** Optional override; defaults to `0`. */
  resourceType?: number;
  /** Optional override; defaults to `1` (current ActionInput version). */
  version?: number;
}

export function buildAction(opts: BuildActionOpts) {
  const info = authorityInfo(opts.handle);
  const resourcePathHashes = hashResourcePath(opts.resourcePath);
  return {
    version: opts.version ?? 1,
    passportIdHashHex: info.passportIdHashHex,
    toolDescriptorHashHex: opts.toolDescriptorHashHex,
    localToolId: opts.localToolId,
    operationId: opts.operationId,
    resourceType: opts.resourceType ?? 0,
    riskClass: opts.riskClass,
    resourcePathDepth: opts.resourcePath.length,
    costUnits: opts.costUnits,
    sequenceId: opts.sequenceId,
    nonceHex: opts.nonceHex ?? randomBytes(16).toString('hex'),
    resourcePathHashes,
  };
}
