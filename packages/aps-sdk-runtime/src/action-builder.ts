/**
 * ActionDescriptor builder — Prototype 1 scaffold.
 *
 * Shape only. Every method returns todo(); the real implementation
 * arrives when the N-API binding is callable.
 */

import type { ActionDescriptor, HexHash, RiskClass } from "./types.js";

function todo(): never {
  throw new Error("not implemented (Prototype 1 scaffold)");
}

export class ActionDescriptorBuilder {
  withTool(_toolDescriptorHash: HexHash): this {
    return todo();
  }

  withOperation(_opId: string): this {
    return todo();
  }

  withResource(_path: string): this {
    return todo();
  }

  withRiskClass(_cls: RiskClass): this {
    return todo();
  }

  build(): ActionDescriptor {
    return todo();
  }
}

export function actionDescriptor(): ActionDescriptorBuilder {
  return new ActionDescriptorBuilder();
}
