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
//
// The bytes go through parseExternalActionRefV1Preimage, not JSON.parse: a
// duplicate preimage key is OUT_OF_PROFILE_DOMAIN per the profile's Domain
// paragraph, and JSON.parse would silently keep the last occurrence and
// destroy the evidence before the helper could see it.
import {
  computeExternalActionRefV1,
  parseExternalActionRefV1Preimage,
} from '../../dist/src/index.js'

let raw = ''
process.stdin.setEncoding('utf8')
for await (const chunk of process.stdin) raw += chunk
const digest = computeExternalActionRefV1(parseExternalActionRefV1Preimage(raw))
process.stdout.write(digest + '\n')
