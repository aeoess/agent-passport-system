/**
 * @aeoess/aps-sdk-runtime — public API (Prototype 1 scaffold).
 *
 * Public surface matches spec Section 12 Stream B. All function bodies
 * throw until the N-API binding (Stream A) reaches a callable interface.
 */

import type {
  ActionDescriptor,
  Decision,
  PassportId,
  RuntimePassport,
  Session,
} from "./types.js";

export * from "./types.js";
export {
  ActionDescriptorBuilder,
  actionDescriptor,
} from "./action-builder.js";
export {
  startRegistrySync,
  currentSnapshot,
  type RegistrySyncOptions,
  type RegistrySnapshot,
} from "./registry-sync.js";
export {
  startTimeAnchor,
  currentAnchor,
  type TimeAnchorOptions,
  type TimeAnchor,
} from "./time-anchor.js";

function todo(): never {
  throw new Error("not implemented (Prototype 1 scaffold)");
}

/**
 * Load a RuntimePassport and open a verifier session against it.
 * Spec Section 12 Stream B.
 */
export async function loadPassport(
  _passport: RuntimePassport,
): Promise<Session> {
  return todo();
}

/**
 * Evaluate an ActionDescriptor against the current session, returning
 * a signed Decision. Spec Section 12 Stream B.
 */
export async function check(_action: ActionDescriptor): Promise<Decision> {
  return todo();
}

/**
 * Recover a previously-opened session by passport id (e.g. after a
 * process restart while the passport remains valid). Spec Section 12
 * Stream B.
 */
export async function recoverSession(
  _passportId: PassportId,
): Promise<Session> {
  return todo();
}
