/**
 * Tool registry HTTPS poll client — Prototype 1 scaffold.
 *
 * The real client will poll the canonical registry endpoint, verify
 * the Merkle root against the published epoch, and surface a fresh
 * tool-descriptor view to the verifier. Stub only at this stage.
 */

function todo(): never {
  throw new Error("not implemented (Prototype 1 scaffold)");
}

export interface RegistrySyncOptions {
  readonly endpoint: string;
  readonly pollIntervalMs: number;
}

export interface RegistrySnapshot {
  readonly epoch: number;
  readonly merkleRoot: string;
  readonly fetchedAt: string;
}

export async function startRegistrySync(
  _options: RegistrySyncOptions,
): Promise<RegistrySnapshot> {
  return todo();
}

export async function currentSnapshot(): Promise<RegistrySnapshot> {
  return todo();
}
