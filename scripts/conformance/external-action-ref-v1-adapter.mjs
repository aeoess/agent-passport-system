// Adapter for the Composable Evidence Criteria lab's action-ref-conformance
// Action (mode verify-impl), profile action-ref-v1-jcs-sha256.
//
// Exercises the external action-ref v1 helper only: computeExternalActionRefV1
// from this checkout's build. It is distinct from the APS-native action
// reference (computeActionRef, draft-pidlisnyi-aps section 4.1) and says
// nothing about overall APS conformance.
//
// Reads one preimage JSON object on stdin and prints the hex digest. Invalid
// input throws, so the process exits non-zero and the runner records a reject.
import { computeExternalActionRefV1 } from '../../dist/src/index.js'

let raw = ''
process.stdin.setEncoding('utf8')
for await (const chunk of process.stdin) raw += chunk
const p = JSON.parse(raw)
const digest = computeExternalActionRefV1({
  actionType: p.action_type,
  agentId: p.agent_id,
  scope: p.scope,
  timestamp: p.timestamp,
})
process.stdout.write(digest + '\n')
