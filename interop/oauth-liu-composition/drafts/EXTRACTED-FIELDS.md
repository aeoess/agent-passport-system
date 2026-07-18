# Extracted fields from the Liu OAuth draft family

Source texts fetched 2026-07-18 from www.ietf.org/archive/id/ into this directory.
Line references are into the fetched .txt files. Field names below are used verbatim
by the input fixtures in ../vectors/. Where a draft gives a JSON example, the fixture
adapts it; where it gives none, the fixture constructs a minimal instance from the
field definitions and the mapping table says so.

## draft-liu-oauth-chain-delegation-00.txt

Figure 1 (lines 199-219) gives a complete delegation_chain example. Fields per hop:

- `delegation_chain` (array of hop records), line 200
- `delegator_id` (line 202), `delegatee_id` (line 203): wit:// agent identifiers
- `delegation_timestamp` (line 204): unix epoch seconds
- `root_evidence_ref` (line 205): string reference to the root evidence record
- `delegated_policy` (line 206): object with `type` ("rego"), `content` (rego source
  whose allow rules test `input.action == "..."`), `entry_point` ("allow")
- `operation_summary` (line 211): human-readable summary
- `delegator_signature` (line 212), `as_signature` (line 213): JWS compact strings

Section 4.3 (line 224): four lifecycle phases; narrowing semantics are that each hop
delegates a policy scope. Section 10.8 (line 2032): revocation semantics. Root and
intermediate hop revocation invalidate downstream tokens; detection mechanisms
include short-lived tokens, RFC 7662 introspection, and back-channel revocation
notifications (lines 2073-2090). The draft names back-channel notification but does
not itself cite RFC 8417; the SET tie in vector v3 comes from the APS observation
record's status_source vocabulary, which accepts a SET jti reference.

## draft-liu-oauth-authorization-evidence-01.txt

Type identifier `authorization_evidence` (Section 3.1, line 232), carried inside
`authorization_details` (RFC 9396). Enriched response example (Section 3.3, lines
254-272):

- `authorization_details[].type` = "authorization_evidence"
- `evidence.id`: urn:uuid
- `evidence.user_confirmation.displayed_content`, `.user_action`, `.timestamp`
  (unix epoch seconds)
- `evidence.as_signature`: JWS compact string
- `evidence.audit_trail.semantic_expansion_level`, `.proposal_ref`

## draft-liu-oauth-rego-policy-00.txt

`policy_ref` claim structure (Section 3.2.2, lines 143-156 area, Figure 3):

- `policy_ref.id` REQUIRED, `policy_ref.version` OPTIONAL,
- `policy_ref.hash` OPTIONAL ("algorithm-base64value", sha256 mandatory to support),
- `policy_ref.endpoint` OPTIONAL (privacy note in Section 10 recommends abstract ids).

Section 9.7 Behavioral Audit (line 1497): Resource Servers SHOULD log each policy
evaluation event including: the policy identifier (policy_ref.id), a hash or summary
of the evaluated input, the allow/deny result, and the evaluation timestamp. This
four-part tuple is the decision context carried by vectors v1 and v2 as:
`policy_ref`, `input_hash`, `result`, `evaluation_timestamp`. The composite object
name and those last three field spellings are constructed for the fixture (the draft
prescribes the tuple's content, not JSON field names); the mapping table marks them
constructed.
