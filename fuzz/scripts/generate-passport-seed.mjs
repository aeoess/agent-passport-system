// One-off generator for the verify-passport fuzz corpus seed: a real,
// cryptographically valid signed passport, produced through the actual
// createPassport() pipeline (not hand-fabricated), so the fuzzer's
// mutation engine starts from a genuinely working example.
import { createPassport } from "../../src/core/passport.ts";
import { writeFileSync } from "node:fs";

const { signedPassport } = createPassport({
  agentId: "fuzz-seed-001",
  agentName: "Fuzz Seed Agent",
  ownerAlias: "fuzz",
  mission: "seed corpus generation",
  capabilities: ["code_execution"],
  runtime: { platform: "fuzz", models: ["m"], toolsCount: 1, memoryType: "m" },
});

const json = JSON.stringify(signedPassport, null, 2);
writeFileSync("fuzz/corpus/verify-passport/valid-signed-passport.json", json);
console.log("wrote fuzz/corpus/verify-passport/valid-signed-passport.json");
