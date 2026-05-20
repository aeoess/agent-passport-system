/**
 * @aeoess/aps-sdk-runtime — type round-trip stub.
 *
 * Compile-time shape check. A real round-trip lands once the N-API
 * binding can canonicalize and re-parse a RuntimePassport.
 */

import { test } from "node:test";
import assert from "node:assert/strict";

import type {
  ActionDescriptor,
  Decision,
  RuntimePassport,
  Session,
} from "../src/index.js";

test("RuntimePassport / ActionDescriptor / Decision / Session shapes accept required fields", () => {
  const passport: RuntimePassport = {
    id: "urn:aps:passport:scaffold",
    publicKey: "00".repeat(32),
    scopes: [
      {
        tool: "fs.read",
        operations: ["read"],
        maxRiskClass: "low",
      },
    ],
    delegationChain: [],
    issuedAt: "2026-05-19T00:00:00Z",
    expiresAt: "2026-05-20T00:00:00Z",
    signature: "00".repeat(64),
  };

  const action: ActionDescriptor = {
    toolDescriptorHash: "00".repeat(32),
    operationId: "read",
    resourcePath: "/tmp/example",
    riskClass: "low",
    timestamp: "2026-05-19T00:00:01Z",
  };

  const session: Session = {
    id: "sess-scaffold",
    passportId: passport.id,
    openedAt: "2026-05-19T00:00:00Z",
    timeAnchor: "2026-05-19T00:00:00Z",
    registryEpoch: 0,
  };

  const decision: Decision = {
    outcome: "permit",
    reason: { code: "scaffold", message: "stub" },
    receiptHash: "00".repeat(32),
    evaluatedAt: "2026-05-19T00:00:02Z",
    sessionId: session.id,
  };

  assert.equal(passport.id, "urn:aps:passport:scaffold");
  assert.equal(action.operationId, "read");
  assert.equal(session.registryEpoch, 0);
  assert.equal(decision.outcome, "permit");
});
