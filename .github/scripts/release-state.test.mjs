import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import {
  mkdtemp,
  open,
  readFile,
  rename,
  rm,
  symlink,
  writeFile,
} from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { promisify } from 'node:util';
import { execFile } from 'node:child_process';
import test from 'node:test';

import {
  artifactDigests,
  classifyRegistryResponse,
  loadArtifact,
  ProvenanceUnavailableError,
} from './release-registry.mjs';
import { classifyGitHubReleaseResponse } from './github-release-state.mjs';
import { loadManifest, validatePublishManifest } from './release-manifest.mjs';
import { readOpenedRegularFile } from './opened-regular-file.mjs';
import { validateImmutableVersionTagRuleset } from './tag-ruleset-state.mjs';

const execFileAsync = promisify(execFile);

async function withTempDirectory(run) {
  const directory = await mkdtemp(join(tmpdir(), 'aps-release-file-'));
  try {
    return await run(directory);
  } finally {
    await rm(directory, { recursive: true, force: true });
  }
}

function swappingOpen(replacement) {
  return async (path, flags) => {
    const handle = await open(path, flags);
    return {
      async stat() {
        const stat = await handle.stat();
        await rename(path, `${path}.validated`);
        await writeFile(path, replacement);
        return stat;
      },
      readFile: (...args) => handle.readFile(...args),
      close: () => handle.close(),
    };
  };
}

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

test('regular release files work end to end through their opened handles', async () => {
  await withTempDirectory(async (cwd) => {
    const tarball = `agent-passport-system-${version}.tgz`;
    const tarballBytes = Buffer.from('regular packed artifact');
    await writeFile(join(cwd, tarball), tarballBytes);
    assert.deepEqual(
      await loadArtifact(version, tarball, { cwd }),
      artifactDigests(tarballBytes),
    );

    const manifestName = 'package.json';
    await writeFile(join(cwd, manifestName), JSON.stringify(publishManifest));
    const manifest = await loadManifest(manifestName, { cwd });
    assert.deepEqual(validatePublishManifest(manifest, version), {
      name: 'agent-passport-system',
      version,
    });
  });
});

test('release helpers reject symlink inputs', async () => {
  await withTempDirectory(async (cwd) => {
    await writeFile(join(cwd, 'artifact-target'), 'target bytes');
    const tarball = `agent-passport-system-${version}.tgz`;
    await symlink('artifact-target', join(cwd, tarball));
    await assert.rejects(
      loadArtifact(version, tarball, { cwd }),
      /tarball must be a regular, non-symlink file/,
    );

    await writeFile(join(cwd, 'manifest-target'), JSON.stringify(publishManifest));
    await symlink('manifest-target', join(cwd, 'package.json'));
    await assert.rejects(
      loadManifest('package.json', { cwd }),
      /publish manifest must be a regular, non-symlink file/,
    );
  });
});

test('release helpers read the same opened objects they validated', async () => {
  await withTempDirectory(async (cwd) => {
    const tarball = `agent-passport-system-${version}.tgz`;
    const validatedBytes = Buffer.from('validated artifact bytes');
    const replacementBytes = Buffer.from('replacement pathname bytes');
    await writeFile(join(cwd, tarball), validatedBytes);
    assert.deepEqual(
      await loadArtifact(version, tarball, {
        cwd,
        openFile: swappingOpen(replacementBytes),
      }),
      artifactDigests(validatedBytes),
    );
    assert.deepEqual(await readFile(join(cwd, tarball)), replacementBytes);

    const replacementManifest = {
      ...publishManifest,
      publishConfig: { registry: 'https://attacker.invalid/' },
    };
    await writeFile(join(cwd, 'package.json'), JSON.stringify(publishManifest));
    const manifest = await loadManifest('package.json', {
      cwd,
      openFile: swappingOpen(JSON.stringify(replacementManifest)),
    });
    assert.deepEqual(validatePublishManifest(manifest, version), {
      name: 'agent-passport-system',
      version,
    });
    assert.deepEqual(
      JSON.parse(await readFile(join(cwd, 'package.json'), 'utf8')),
      replacementManifest,
    );
  });
});

test('release file reads fail closed when no-follow support is unavailable', async () => {
  await assert.rejects(
    readOpenedRegularFile('/unused', 'must be regular', {
      fsConstants: { O_RDONLY: 0, O_NONBLOCK: 4 },
      openFile: async () => assert.fail('open must not run without O_NOFOLLOW'),
    }),
    /O_NOFOLLOW is unavailable; refusing an unsafe pathname-based fallback/,
  );
});

test('FIFO inputs are rejected without blocking the privileged helper', {
  skip: process.platform === 'win32',
}, async () => {
  await withTempDirectory(async (cwd) => {
    const cases = [
      {
        name: `agent-passport-system-${version}.tgz`,
        moduleUrl: new URL('./release-registry.mjs', import.meta.url).href,
        source: `import { loadArtifact } from ${JSON.stringify(new URL('./release-registry.mjs', import.meta.url).href)}; await loadArtifact(${JSON.stringify(version)}, ${JSON.stringify(`agent-passport-system-${version}.tgz`)});`,
        error: /tarball must be a regular, non-symlink file/,
      },
      {
        name: 'package.json',
        moduleUrl: new URL('./release-manifest.mjs', import.meta.url).href,
        source: `import { loadManifest } from ${JSON.stringify(new URL('./release-manifest.mjs', import.meta.url).href)}; await loadManifest('package.json');`,
        error: /publish manifest must be a regular, non-symlink file/,
      },
    ];

    for (const fifoCase of cases) {
      await execFileAsync('mkfifo', [fifoCase.name], { cwd });
      await assert.rejects(
        execFileAsync(process.execPath, [
          '--input-type=module',
          '--eval',
          fifoCase.source,
        ], {
          cwd,
          timeout: 2_000,
          killSignal: 'SIGKILL',
        }),
        (error) => {
          assert.equal(error.killed, false, `${fifoCase.moduleUrl} blocked while opening a FIFO`);
          assert.match(error.stderr, fifoCase.error);
          return true;
        },
      );
    }
  });
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

test('the official immutable GitHub Release gates npm publication', () => {
  const workflow = readFileSync(
    new URL('../workflows/release.yml', import.meta.url),
    'utf8',
  );
  const attestIndex = workflow.indexOf('\n  attest:\n');
  const releaseIndex = workflow.indexOf('\n  release:\n');
  const publishIndex = workflow.indexOf('\n  publish:\n');
  assert.ok(attestIndex > 0 && attestIndex < releaseIndex && releaseIndex < publishIndex);

  const publishJob = workflow.slice(publishIndex);
  assert.match(publishJob, /    needs:\n(?:      - [a-z-]+\n)*      - release\n/);
  assert.match(publishJob, /Require the official immutable GitHub Release before npm publication/);
  assert.equal((workflow.match(/npm publish /g) ?? []).length, 1);
  assert.equal((workflow.slice(0, publishIndex).match(/npm publish /g) ?? []).length, 0);
});
