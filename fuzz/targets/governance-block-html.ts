// Fuzz target: parseGovernanceBlockFromHTML (src/core/governance-block.ts).
// Read the full function first: both its script-tag and meta-tag branches
// wrap their JSON.parse in try/catch and return null on failure, and its
// two regexes are bounded (non-greedy up to a literal closing tag, and a
// simple negated-character-class run), so the function's own contract is
// "never throws, worst case returns null." Any uncaught throw here is a
// genuine finding, and a hang is caught by Jazzer's per-input timeout.
import { parseGovernanceBlockFromHTML } from "../../src/core/governance-block.js";

export function fuzz(data: Buffer): void {
  const html = data.toString("utf8");
  parseGovernanceBlockFromHTML(html);
}
