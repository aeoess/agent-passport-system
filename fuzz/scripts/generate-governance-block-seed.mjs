// One-off generator for the governance-block-html fuzz corpus: real,
// cryptographically valid governance blocks rendered through the actual
// generateGovernanceBlock/renderGovernanceHTML/renderGovernanceMeta
// pipeline (not hand-fabricated JSON), so the fuzzer starts from
// genuinely working script-tag and meta-tag examples.
import {
  generateKeyPair,
  generateGovernanceBlock,
  renderGovernanceHTML,
  renderGovernanceMeta,
} from "../../src/index.ts";
import { writeFileSync } from "node:fs";

const keys = generateKeyPair();
const ARTICLE = "AI agents are transforming the economy.";

const block = generateGovernanceBlock({
  content: ARTICLE,
  publicKey: keys.publicKey,
  privateKey: keys.privateKey,
  terms: {
    inference: "permitted",
    training: "compensation_required",
    redistribution: "prohibited",
    derivative: "attribution_required",
    caching: "permitted",
    version: "1.0",
  },
});

const scriptHtml = renderGovernanceHTML(block);
writeFileSync(
  "fuzz/corpus/governance-block-html/valid-script-tag.html",
  `<html><head>${scriptHtml}</head><body>${ARTICLE}</body></html>`,
);

const metaTag = renderGovernanceMeta(block);
writeFileSync(
  "fuzz/corpus/governance-block-html/valid-meta-tag.html",
  `<html><head>${metaTag}</head><body>${ARTICLE}</body></html>`,
);

writeFileSync(
  "fuzz/corpus/governance-block-html/no-governance.html",
  "<html><body>No governance here</body></html>",
);

console.log("wrote 3 governance-block-html corpus seeds");
