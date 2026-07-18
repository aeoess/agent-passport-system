# Liu draft family to APS record mapping

Mechanical field map for the three vectors. Draft line references are into the
fetched .txt files in drafts/. "Their field" spellings are verbatim from the drafts
except the three marked constructed, whose content Section 9.7 prescribes without
JSON spellings. APS slots are existing exported shapes only; no record shape or
signing profile was modified.

How column vocabulary: digest means the sha256 of the strict JCS form of their
object lands in the APS slot; copied means the value is carried verbatim; derived
means the APS value is computed from their values; referenced means their id string
is embedded in an APS string slot.

## draft-liu-oauth-chain-delegation-00 (vectors v1, v2, v3)

| Their ref | Their field | APS slot | How |
|---|---|---|---|
| Fig. 1, line 200 | delegation_chain (whole array) | ReceiptV1.evidence_refs[] artifact_type liu-oauth-chain-delegation-00/delegation_chain | digest |
| Fig. 1, line 200 | delegation_chain (whole array) | ReceiptV1.delegation_ref | derived (liu-chain:sha256:digest string) |
| Fig. 1, line 200 | delegation_chain (whole array) | DecisionRefInputV1.authority_state_ref via buildDecisionRefV1 authority_state | digest |
| Fig. 1, line 203 | delegatee_id (final hop) | ReceiptV1.subject_agent | copied |
| Fig. 1, line 203 | delegatee_id (final hop) | ActionReferenceInputV2.agent_id | copied |
| Fig. 1, lines 206-210 | delegated_policy.content (rego allow clauses) | narrowed subset in result.narrowed_subset and CoreDecisionOutputV1.constraints (permit) | derived (input.action equality clauses parsed per the draft's own clause form) |
| Fig. 1, lines 206-210 | delegated_policy.content (final hop) | rego_decision_context.policy_ref.hash | derived (sha256- base64, the rego draft's format) |
| Fig. 1, lines 202, 203 | delegator_id, delegatee_id (revoked hop) | RevocationObservation.authority_ref | derived (liu-chain-hop:delegator->delegatee) |
| Sec. 10.8, lines 2073-2090 | back-channel revocation notification | RevocationObservation.status_source {kind: set, jti} | referenced (the SET jti string; the RFC 8417 tie is the APS status_source vocabulary, the Liu draft names back-channel notification without citing 8417) |
| Sec. 10.8 | revocation takes effect on observation | RevocationObservation.observed_at, maximum_staleness_ms, decision | derived (the relying party's freshness contract and the deny that followed) |
| Fig. 1, lines 206-210 | delegated_policy scope (final hop) | RevocationObservation.affected_scope | derived (space-joined narrowed action set) |
| Fig. 1, lines 204, 205, 211-213 | delegation_timestamp, root_evidence_ref, operation_summary, delegator_signature, as_signature | covered by the chain digest only | digest (inside the whole-array digest; not individually mapped) |

## draft-liu-oauth-authorization-evidence-01 (vectors v1, v2)

| Their ref | Their field | APS slot | How |
|---|---|---|---|
| Sec. 3.3, lines 254-272 | authorization_details (whole enriched array) | ReceiptV1.evidence_refs[] artifact_type liu-oauth-authorization-evidence-01/authorization_details | digest |
| Sec. 3.3 | evidence.id, user_confirmation.*, as_signature, audit_trail.* | covered by the authorization_details digest | digest (inside the whole-object digest; not individually mapped) |

## draft-liu-oauth-rego-policy-00 (vectors v1, v2)

| Their ref | Their field | APS slot | How |
|---|---|---|---|
| Sec. 3.2.2, Fig. 3 | policy_ref (id, version, hash) | DecisionRefInputV1.policy_ref via buildDecisionRefV1 policy_input | digest |
| Sec. 3.2.2, Fig. 3 | policy_ref.id | ReceiptV1.result.policy_id | copied |
| Sec. 9.7, line 1497 | policy identifier (policy_ref.id) | decision_context component of decision_ref | digest (as part of the 9.7 tuple object) |
| Sec. 9.7 | hash of the evaluated input | fixture field input_hash (constructed spelling) in the decision_context component | derived (sha256: digest of the evaluated input) |
| Sec. 9.7 | allow/deny result | fixture field result (constructed spelling) in decision_context; CoreDecisionOutputV1.verdict; ReceiptV1.result.decision | copied / derived (allow to permit, deny to deny) |
| Sec. 9.7 | evaluation timestamp | fixture field evaluation_timestamp (constructed spelling) in decision_context | copied |

## Consulted but unmapped

| Their ref | Their field | Why unmapped |
|---|---|---|
| rego-policy-00 Sec. 3.2.2 | policy_ref.endpoint | the draft's own privacy section recommends abstract identifiers; the vectors carry id, version, hash only |
| rego-policy-00 error vocabulary | error, error_description, rego_profile | error negotiation is a request-time flow; the vectors record decisions, not the negotiation |
| chain-delegation-00 Sec. 4.3 phase 2 | interaction_required | user-interaction phase precedes the decision the receipt records; the evidence object already carries the user confirmation |
| authorization-evidence-01 Sec. 3.2 | client request form (minimal type-only object) | the vectors carry the enriched response, which is the evidence-bearing form |

## Gap notes

No new field or profile was needed for any of the three vectors. Two observations
that are conventions rather than gaps: the evidence tie-back uses digest-only
evidence_refs (artifact_type plus sha256), so a relying party needs the input
artifact out of band to re-derive the digest, which is the intended evidence_refs
model; and the 9.7 tuple has prescribed content but no prescribed JSON spellings,
so the three constructed spellings (input_hash, result, evaluation_timestamp) are
fixture conventions, marked above.
