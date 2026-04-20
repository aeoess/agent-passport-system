# Cognitive Attestation

TypeScript primitive for **signed declarations of feature-level model
computation**. Part of APS v2.1.0.

- **Paper:** "Cognitive Attestation" — Zenodo DOI
  [10.5281/zenodo.19646276](https://doi.org/10.5281/zenodo.19646276)
- **Normative schema:** `papers/paper-4/poc/schema/cognitive_attestation.schema.json`
- **Python reference:** `papers/paper-4/poc/src/envelope.py`

## What this module ships

| Capability | Function |
|---|---|
| Envelope construction | `buildAttestation` |
| RFC 8785 JCS canonicalization (signatures elided) | `canonicalizeAttestation` |
| Ed25519 signing (multi-signer) | `signAttestation` |
| Content-addressable digest (for cross-primitive refs) | `cognitiveAttestationDigest` |
| Shape validation against the normative schema | `validateAttestationShape` |
| Stage 1 cryptographic — single signer | `verifySignature` |
| Stage 1 cryptographic — required role coverage | `verifyRequiredSignerRoles` |
| Stage 2 registry — model + dictionary version known | `verifyAgainstRegistry` (interface) |
| Stage 3 replay — SAE re-execution | `verifyByReplay` (stub, inject backend) |
| Typed dispute primitives | `ThresholdDispute`, `ExclusionDispute`, `DecompositionAdequacyDispute`, `FacetedReinterpretationDispute` |

## What this module does NOT ship (product intelligence — gateway only)

- Dispute resolution, adjudication, or scheduling
- Transparency-log publishing of attestations
- Cross-tenant correlation or drift detection
- Bulk compliance-report generation
- Rate limiting or audit-trail analytics

Those belong in the private `@aeoess/gateway` module.

## Minimal example

```ts
import {
  buildAttestation,
  signAttestation,
  verifySignature,
  verifyRequiredSignerRoles,
} from 'agent-passport-system'
import { generateKeyPair } from 'agent-passport-system'
import { createHash } from 'node:crypto'

// You bring your own Ed25519 keys (32-byte seed + 32-byte public).
// The example below derives them from hex via any standard path.
const sha = (s: string) => createHash('sha256').update(s).digest('hex')

const att = buildAttestation({
  model_id: 'meta-llama/Llama-3.1-8B-Instruct',
  model_version_hash: sha('fake-weights'),
  tokenizer_version_hash: sha('fake-tokenizer'),
  inference_provider: null,
  hardware_family: 'apple-silicon/m-series/m3-max',
  precision: 'fp32',
  inference_engine: 'pytorch@2.4',
  deterministic_mode: true,
  dictionary_id: 'neuronpedia/llama3-8b/l19-res-32k',
  dictionary_version_hash: sha('fake-sae'),
  training_corpus_hash: null,
  layer_index: 19,
  attachment_point: 'residual_stream',
  sae_type: 'topk',
  absolute_sequence_hash: sha('fake-tokens'),
  prior_state_hash: null,
  start_token_index: 0,
  end_token_index: 47,
  token_count: 47,
  feature_activations: [
    {
      feature_id: 20946,
      feature_label: 'vulnerability/attack/security-adjacent',
      activation_statistic: 'max',
      activation_value: 3.8,
      tokens_active: 3,
    },
  ],
  aggregation_policy: {
    top_k: 32,
    threshold: null,
    attestation_epsilon: 0.5,
    feature_allowlist_hash: null,
    completeness_claim: 'top_k_only',
    tiebreaker_rule: 'lowest_feature_id',
    required_signer_roles: ['agent'],
  },
})

// privKey/pubKey are 32-byte Uint8Arrays (Ed25519 seed + pub).
const signed = signAttestation(att, privKey, 'did:aps:test-agent', 'agent')

console.log(verifySignature(signed, pubKey, 'did:aps:test-agent'))    // true
console.log(verifyRequiredSignerRoles(signed).ok)                     // true
```

## Wire compatibility with the Python reference

Both implementations produce byte-identical JCS canonical bytes over the
same envelope — signatures sign/verify across the two sides of the
language boundary. Deviations from the Python smoke test (missing
`attestation_epsilon` and `required_signer_roles` in `aggregation_policy`)
are fixed here; the TS types make them compile-time-required, and the
normative schema file is the source of truth.
