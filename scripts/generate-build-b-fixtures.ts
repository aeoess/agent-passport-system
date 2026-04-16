// Copyright 2024-2026 Tymofii Pidlisnyi. Apache-2.0 license. See LICENSE.
// Generate cross-language fixtures for Build B. Run with:
//   npx tsx scripts/generate-build-b-fixtures.ts
//
// Writes 10 JSON fixtures to /Users/tima/aeoess_web/specs/fixtures/build-b/.
// Each fixture contains { kind, description, input, expected }. Python
// and TS cross-verify tests load these and assert byte-identical
// canonical output.

import { mkdirSync, writeFileSync } from 'node:fs'
import { join } from 'node:path'
import {
  DEFAULT_WEIGHT_PROFILE,
  computeComputeAxisWeights,
  computeDataAxisWeights,
  hashWeightProfile,
} from '../src/index.js'

const OUT_DIR = '/Users/tima/aeoess_web/specs/fixtures/build-b'
mkdirSync(OUT_DIR, { recursive: true })

function write(name: string, body: unknown): void {
  const path = join(OUT_DIR, `${name}.json`)
  writeFileSync(path, JSON.stringify(body, null, 2) + '\n')
  console.log(`wrote ${path}`)
}

// ─── Scenario 1: single primary source ────────────────────────
{
  const sources = [
    { source_did: 'did:data:single', access_receipt_hash: 'a'.repeat(64), role: 'primary_source' as const, timestamp: '2026-04-16T12:00:00.000Z', content_length: 1000 },
  ]
  const action_timestamp = '2026-04-16T12:00:00.000Z'
  write('01-d-single-primary', {
    kind: 'd_axis',
    description: 'Single primary source, same-day, reference length — expect weight 1.000000',
    input: { sources, action_timestamp },
    expected: {
      weights: computeDataAxisWeights(sources, { action_timestamp }),
    },
  })
}

// ─── Scenario 2: two equal sources ─────────────────────────────
{
  const sources = [
    { source_did: 'did:data:a', access_receipt_hash: 'a'.repeat(64), role: 'primary_source' as const, timestamp: '2026-04-16T00:00:00.000Z', content_length: 500 },
    { source_did: 'did:data:b', access_receipt_hash: 'b'.repeat(64), role: 'primary_source' as const, timestamp: '2026-04-16T00:00:00.000Z', content_length: 500 },
  ]
  const action_timestamp = '2026-04-16T12:00:00.000Z'
  write('02-d-two-equal', {
    kind: 'd_axis',
    description: 'Two structurally identical sources → 0.500000 each',
    input: { sources, action_timestamp },
    expected: { weights: computeDataAxisWeights(sources, { action_timestamp }) },
  })
}

// ─── Scenario 3: three mixed roles ─────────────────────────────
{
  const sources = [
    { source_did: 'did:data:primary', access_receipt_hash: 'a'.repeat(64), role: 'primary_source' as const, timestamp: '2026-04-16T00:00:00.000Z', content_length: 1000 },
    { source_did: 'did:data:supporting', access_receipt_hash: 'b'.repeat(64), role: 'supporting_evidence' as const, timestamp: '2026-04-16T00:00:00.000Z', content_length: 1000 },
    { source_did: 'did:data:context', access_receipt_hash: 'c'.repeat(64), role: 'context_only' as const, timestamp: '2026-04-16T00:00:00.000Z', content_length: 1000 },
  ]
  const action_timestamp = '2026-04-16T12:00:00.000Z'
  write('03-d-three-mixed-roles', {
    kind: 'd_axis',
    description: 'Three sources with distinct roles, otherwise identical — role weights drive the split',
    input: { sources, action_timestamp },
    expected: { weights: computeDataAxisWeights(sources, { action_timestamp }) },
  })
}

// ─── Scenario 4: recency floor ─────────────────────────────────
{
  const sources = [
    { source_did: 'did:data:fresh', access_receipt_hash: 'a'.repeat(64), role: 'primary_source' as const, timestamp: '2026-04-16T00:00:00.000Z', content_length: 1000 },
    { source_did: 'did:data:ancient', access_receipt_hash: 'b'.repeat(64), role: 'primary_source' as const, timestamp: '2010-01-01T00:00:00.000Z', content_length: 1000 },
  ]
  const action_timestamp = '2026-04-16T12:00:00.000Z'
  write('04-d-recency-floor', {
    kind: 'd_axis',
    description: 'Fresh source vs ancient source floored at min_recency=0.2 — fresh gets ~5× weight',
    input: { sources, action_timestamp },
    expected: { weights: computeDataAxisWeights(sources, { action_timestamp }) },
  })
}

// ─── Scenario 5: length saturation ─────────────────────────────
{
  const sources = [
    { source_did: 'did:data:short', access_receipt_hash: 'a'.repeat(64), role: 'primary_source' as const, timestamp: '2026-04-16T00:00:00.000Z', content_length: 10 },
    { source_did: 'did:data:huge', access_receipt_hash: 'b'.repeat(64), role: 'primary_source' as const, timestamp: '2026-04-16T00:00:00.000Z', content_length: 100_000 },
  ]
  const action_timestamp = '2026-04-16T12:00:00.000Z'
  write('05-d-length-saturation', {
    kind: 'd_axis',
    description: 'Sub-linear length weight: 10-token vs 100k-token source; huge does NOT get 99%',
    input: { sources, action_timestamp },
    expected: { weights: computeDataAxisWeights(sources, { action_timestamp }) },
  })
}

// ─── Scenario 6: single provider ───────────────────────────────
{
  const providers = [
    { provider_did: 'did:compute:only', hardware_attestation_hash: '1'.repeat(64), prompt_tokens: 1500, completion_tokens: 500 },
  ]
  write('06-c-single-provider', {
    kind: 'c_axis',
    description: 'Single provider → 1.000000',
    input: { providers },
    expected: { weights: computeComputeAxisWeights(providers) },
  })
}

// ─── Scenario 7: two equal providers ───────────────────────────
{
  const providers = [
    { provider_did: 'did:compute:a', hardware_attestation_hash: '1'.repeat(64), prompt_tokens: 1000, completion_tokens: 500 },
    { provider_did: 'did:compute:b', hardware_attestation_hash: '2'.repeat(64), prompt_tokens: 1000, completion_tokens: 500 },
  ]
  write('07-c-two-equal-split', {
    kind: 'c_axis',
    description: 'Two providers with identical token counts → 0.500000 each',
    input: { providers },
    expected: { weights: computeComputeAxisWeights(providers) },
  })
}

// ─── Scenario 8: prompt-vs-completion 3× multiplier ────────────
{
  const providers = [
    { provider_did: 'did:compute:prompt-only', hardware_attestation_hash: '1'.repeat(64), prompt_tokens: 300, completion_tokens: 0 },
    { provider_did: 'did:compute:completion-only', hardware_attestation_hash: '2'.repeat(64), prompt_tokens: 0, completion_tokens: 100 },
  ]
  write('08-c-completion-multiplier', {
    kind: 'c_axis',
    description: 'Provider A: 300 prompt. Provider B: 100 completion. With COMPLETION_MULTIPLIER=3.0, both contribute 300 — 0.500000 each',
    input: { providers },
    expected: { weights: computeComputeAxisWeights(providers) },
  })
}

// ─── Scenario 9: many providers with varied tokens ─────────────
{
  const providers = [
    { provider_did: 'did:compute:anthropic', hardware_attestation_hash: '1'.repeat(64), prompt_tokens: 2000, completion_tokens: 1500 },
    { provider_did: 'did:compute:openai', hardware_attestation_hash: '2'.repeat(64), prompt_tokens: 1500, completion_tokens: 800 },
    { provider_did: 'did:compute:google', hardware_attestation_hash: '3'.repeat(64), prompt_tokens: 800, completion_tokens: 400 },
    { provider_did: 'did:compute:xai', hardware_attestation_hash: '4'.repeat(64), prompt_tokens: 500, completion_tokens: 200 },
    { provider_did: 'did:compute:meta', hardware_attestation_hash: '5'.repeat(64), prompt_tokens: 300, completion_tokens: 100 },
  ]
  write('09-c-multi-provider', {
    kind: 'c_axis',
    description: 'Five providers with varied workloads — sums to 1.0, larger providers dominate',
    input: { providers },
    expected: { weights: computeComputeAxisWeights(providers) },
  })
}

// ─── Scenario 10: profile hash anchor ──────────────────────────
{
  write('10-profile-hash-default', {
    kind: 'profile_hash',
    description: 'Hash of DEFAULT_WEIGHT_PROFILE — must be byte-identical across TS and Python',
    input: { profile: DEFAULT_WEIGHT_PROFILE },
    expected: { hash: hashWeightProfile(DEFAULT_WEIGHT_PROFILE) },
  })
}

console.log('\nDone.')
