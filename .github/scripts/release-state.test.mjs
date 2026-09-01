import assert from 'node:assert/strict';
import test from 'node:test';

import {
  artifactDigests,
  classifyRegistryResponse,
  ProvenanceUnavailableError,
} from './release-registry.mjs';
import { classifyGitHubReleaseResponse } from './github-release-state.mjs';
import { validatePublishManifest } from './release-manifest.mjs';
import { validateImmutableVersionTagRuleset } from './tag-ruleset-state.mjs';

const version = '5.0.1';
const bytes = Buffer.from('one packed artifact');
const localDigests = artifactDigests(bytes);
const registryDocument = {
  name: 'agent-passport-system',
  version,
  dist: {
    shasum: localDigests.shasum,
    integrity: localDigests.integrity,
    attestations: {
      url: `https://registry.npmjs.org/-/npm/v1/attestations/agent-passport-system@${version}`,
      provenance: { predicateType: 'https://slsa.dev/provenance/v1' },
    },
  },
};

test('only HTTP 404 establishes registry absence', () => {
  assert.deepEqual(
    classifyRegistryResponse(
      { status: 404 },
      { version, localDigests },
    ),
    { state: 'absent', provenance: 'absent', ...localDigests },
  );
  assert.throws(
    () => classifyRegistryResponse(
      { status: 503, document: { error: 'E404 not found' } },
      { version, localDigests },
    ),
    /HTTP 503; absence is not established/,
  );
});

test('HTTP 404 fails after publication is required', () => {
  assert.throws(
    () => classifyRegistryResponse(
      { status: 404 },
      { version, localDigests, requirePresent: true },
    ),
    /HTTP 404.*after publication/,
  );
});

test('an existing version must match both registry digests', () => {
  assert.deepEqual(
    classifyRegistryResponse(
      { status: 200, document: registryDocument },
      { version, localDigests, requireProvenance: true },
    ),
    { state: 'identical', provenance: 'present', ...localDigests },
  );

  assert.throws(
    () => classifyRegistryResponse(
      {
        status: 200,
        document: {
          ...registryDocument,
          dist: { ...registryDocument.dist, shasum: '0'.repeat(40) },
        },
      },
      { version, localDigests },
    ),
    /published bytes differ/,
  );
});

test('required npm provenance is distinct from matching registry bytes', () => {
  const withoutProvenance = {
    ...registryDocument,
    dist: {
      shasum: registryDocument.dist.shasum,
      integrity: registryDocument.dist.integrity,
    },
  };
  assert.throws(
    () => classifyRegistryResponse(
      { status: 200, document: withoutProvenance },
      { version, localDigests, requireProvenance: true },
    ),
    ProvenanceUnavailableError,
  );
});

const publishManifest = {
  name: 'agent-passport-system',
  version,
  repository: {
    url: 'git+https://github.com/aeoess/agent-passport-system.git',
  },
  scripts: {
    build: 'tsc',
    test: 'node --test',
  },
};

test('publish manifest admits package scripts but no privileged redirection', () => {
  assert.deepEqual(validatePublishManifest(publishManifest, version), {
    name: 'agent-passport-system',
    version,
  });
  assert.throws(
    () => validatePublishManifest({
      ...publishManifest,
      publishConfig: { registry: 'https://attacker.invalid/' },
    }, version),
    /publishConfig is forbidden/,
  );
});

test('GitHub release control flow distinguishes 404 from ambiguity', () => {
  assert.equal(classifyGitHubReleaseResponse({ status: 404 }, 'v5.0.1'), 'absent');
  assert.equal(
    classifyGitHubReleaseResponse(
      {
        status: 200,
        document: {
          tag_name: 'v5.0.1',
          name: 'v5.0.1',
          draft: false,
          prerelease: false,
          immutable: true,
          published_at: '2026-09-01T00:00:00Z',
          author: { login: 'github-actions[bot]', id: 41898282, type: 'Bot' },
          assets: [
            { name: 'agent-passport-system-5.0.1.tgz', state: 'uploaded' },
            { name: 'agent-passport-system-5.0.1.intoto.jsonl', state: 'uploaded' },
            { name: 'agent-passport-system-5.0.1.sbom.spdx.json', state: 'uploaded' },
          ],
        },
      },
      'v5.0.1',
    ),
    'immutable',
  );
  assert.throws(
    () => classifyGitHubReleaseResponse(
      { status: 502, document: { message: 'Not Found' } },
      'v5.0.1',
    ),
    /HTTP 502; absence is not established/,
  );
  assert.throws(
    () => classifyGitHubReleaseResponse(
      {
        status: 200,
        document: {
          tag_name: 'v5.0.1',
          name: 'v5.0.1',
          draft: false,
          prerelease: false,
          immutable: false,
          published_at: '2026-09-01T00:00:00Z',
          author: { login: 'github-actions[bot]', id: 41898282, type: 'Bot' },
          assets: [],
        },
      },
      'v5.0.1',
    ),
    /exists but is not immutable/,
  );
  assert.throws(
    () => classifyGitHubReleaseResponse(
      {
        status: 200,
        document: {
          tag_name: 'v5.0.1',
          name: 'v5.0.1',
          draft: false,
          prerelease: false,
          immutable: true,
          published_at: '2026-09-01T00:00:00Z',
          author: { login: 'attacker', id: 1, type: 'User' },
          assets: [],
        },
      },
      'v5.0.1',
    ),
    /was not created by the repository release workflow/,
  );
});

const immutableTagRuleset = {
  name: 'immutable-version-tags',
  target: 'tag',
  source: 'aeoess/agent-passport-system',
  enforcement: 'active',
  bypass_actors: [{
    actor_id: 171286556,
    actor_type: 'User',
    bypass_mode: 'always',
  }],
  conditions: {
    ref_name: {
      include: ['refs/tags/v*'],
      exclude: [],
    },
  },
  rules: [
    { type: 'creation' },
    { type: 'update', parameters: { update_allows_fetch_and_merge: false } },
    { type: 'deletion' },
    { type: 'non_fast_forward' },
  ],
};

test('version-tag ruleset binds immutable releases to the owner bypass', () => {
  assert.deepEqual(validateImmutableVersionTagRuleset(immutableTagRuleset), {
    state: 'active',
    bypassVisibility: 'visible',
  });
  assert.deepEqual(
    validateImmutableVersionTagRuleset({
      ...immutableTagRuleset,
      bypass_actors: undefined,
    }),
    { state: 'active', bypassVisibility: 'not-visible' },
  );
});

test('version-tag ruleset fails closed on missing restrictions or extra bypasses', () => {
  assert.throws(
    () => validateImmutableVersionTagRuleset({
      ...immutableTagRuleset,
      rules: immutableTagRuleset.rules.filter((rule) => rule.type !== 'update'),
    }),
    /missing update/,
  );
  assert.throws(
    () => validateImmutableVersionTagRuleset({
      ...immutableTagRuleset,
      conditions: { ref_name: { include: ['~ALL'], exclude: [] } },
    }),
    /must include only refs\/tags\/v\*/,
  );
  assert.throws(
    () => validateImmutableVersionTagRuleset({
      ...immutableTagRuleset,
      bypass_actors: [
        ...immutableTagRuleset.bypass_actors,
        { actor_id: 1, actor_type: 'User', bypass_mode: 'always' },
      ],
    }),
    /exactly one visible bypass actor/,
  );
});
