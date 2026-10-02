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
  RegistryNotVisibleError,
  resolveRegistryState,
} from './release-registry.mjs';
import { classifyGitHubReleaseResponse } from './github-release-state.mjs';
import { loadManifest, validatePublishManifest } from './release-manifest.mjs';
import { readOpenedRegularFile } from './opened-regular-file.mjs';
import {
  authorizeReleaseActor,
  AUTHORIZED_RELEASE_ACTOR_ID,
} from './release-actor-state.mjs';
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

function recordingRetry(responses) {
  const queue = [...responses];
  const fetched = [];
  const slept = [];
  const logged = [];
  return {
    fetched,
    slept,
    logged,
    options: {
      fetchDocument: async (requestedVersion) => {
        fetched.push(requestedVersion);
        if (queue.length === 0) throw new Error('fetched more often than the test allows');
        return queue.shift();
      },
      sleep: async (ms) => { slept.push(ms); },
      log: (line) => { logged.push(line); },
    },
  };
}

const withoutProvenanceDocument = {
  ...registryDocument,
  dist: {
    shasum: registryDocument.dist.shasum,
    integrity: registryDocument.dist.integrity,
  },
};

test('a version that is not visible yet is retried until it appears', async () => {
  const retry = recordingRetry([
    { status: 404 },
    { status: 404 },
    { status: 200, document: registryDocument },
  ]);

  assert.deepEqual(
    await resolveRegistryState(
      { version, localDigests, requirePresent: true, requireProvenance: true },
      retry.options,
    ),
    { state: 'identical', provenance: 'present', ...localDigests },
  );
  assert.equal(retry.fetched.length, 3);
  assert.deepEqual(retry.slept, [15_000, 15_000]);
  assert.match(retry.logged[0], /attempt 1\/12: registry returned HTTP 404 .* retrying in 15s/);
});

test('provenance that is not published yet is retried until it appears', async () => {
  const retry = recordingRetry([
    { status: 200, document: withoutProvenanceDocument },
    { status: 200, document: registryDocument },
  ]);

  assert.equal(
    (await resolveRegistryState(
      { version, localDigests, requirePresent: true, requireProvenance: true },
      retry.options,
    )).provenance,
    'present',
  );
  assert.deepEqual(retry.slept, [15_000]);
});

test('published bytes that differ fail on the first attempt', async () => {
  const retry = recordingRetry([
    {
      status: 200,
      document: {
        ...registryDocument,
        dist: { ...registryDocument.dist, shasum: '0'.repeat(40) },
      },
    },
  ]);

  await assert.rejects(
    () => resolveRegistryState(
      { version, localDigests, requirePresent: true, requireProvenance: true },
      retry.options,
    ),
    /published bytes differ/,
  );
  assert.equal(retry.fetched.length, 1);
  assert.deepEqual(retry.slept, []);
  assert.match(retry.logged[0], /not a visibility delay, not retrying/);
});

test('a version that never appears fails after the bounded attempts', async () => {
  const retry = recordingRetry(Array.from({ length: 12 }, () => ({ status: 404 })));

  await assert.rejects(
    () => resolveRegistryState(
      { version, localDigests, requirePresent: true },
      retry.options,
    ),
    RegistryNotVisibleError,
  );
  assert.equal(retry.fetched.length, 12);
  assert.deepEqual(retry.slept, Array(11).fill(15_000));
  assert.match(retry.logged.at(-1), /still not visible after 12 attempts/);
});

test('absence stays a first-attempt answer when presence is not required', async () => {
  const retry = recordingRetry([{ status: 404 }]);

  assert.equal(
    (await resolveRegistryState({ version, localDigests }, retry.options)).state,
    'absent',
  );
  assert.equal(retry.fetched.length, 1);
  assert.deepEqual(retry.slept, []);
});

const publishManifest = {
  name: 'agent-passport-system',
  version,
  repository: {
    url: 'git+https://github.com/agent-passport-system/agent-passport-system.git',
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
  source: 'agent-passport-system/agent-passport-system',
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

test('version-tag ruleset binds immutable releases to the authorized release actor bypass', () => {
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

test('version-tag ruleset accepts only the authorized release actor as the bypass principal', () => {
  assert.deepEqual(
    validateImmutableVersionTagRuleset({
      ...immutableTagRuleset,
      bypass_actors: [{ actor_id: 171286556, actor_type: 'User', bypass_mode: 'always' }],
    }),
    { state: 'active', bypassVisibility: 'visible' },
  );

  // Every rejected case uses an actor_type the rulesets API actually returns,
  // so this tracks real policy changes rather than a string the API never
  // emits. Moving the repository into the organization must not hand the
  // release bypass to organization admins, a team, an app or a repository role,
  // and the one allowed principal must still bypass always rather than only
  // through a pull request.
  const rejectedBypasses = [
    [{ actor_id: 1, actor_type: 'OrganizationAdmin', bypass_mode: 'always' }],
    [{ actor_id: 9876543, actor_type: 'Team', bypass_mode: 'always' }],
    [{ actor_id: 281797194, actor_type: 'User', bypass_mode: 'always' }],
    [{ actor_id: 5, actor_type: 'RepositoryRole', bypass_mode: 'always' }],
    [{ actor_id: 15368, actor_type: 'Integration', bypass_mode: 'always' }],
    [{ actor_id: 171286556, actor_type: 'User', bypass_mode: 'pull_request' }],
  ];
  for (const bypassActors of rejectedBypasses) {
    const [actor] = bypassActors;
    assert.throws(
      () => validateImmutableVersionTagRuleset({
        ...immutableTagRuleset,
        bypass_actors: bypassActors,
      }),
      /bypass must be the authorized release actor only/,
      `accepted ${actor.actor_type}:${actor.actor_id}:${actor.bypass_mode}`,
    );
  }

  // A second bypass actor alongside the correct one is refused by the
  // single-actor requirement, which reports a different failure.
  assert.throws(
    () => validateImmutableVersionTagRuleset({
      ...immutableTagRuleset,
      bypass_actors: [
        { actor_id: 171286556, actor_type: 'User', bypass_mode: 'always' },
        { actor_id: 1, actor_type: 'OrganizationAdmin', bypass_mode: 'always' },
      ],
    }),
    /exactly one visible bypass actor/,
  );
});

test('the release principal gate binds the authorized release actor id, not repository ownership', () => {
  const workflow = readFileSync(
    new URL('../workflows/release.yml', import.meta.url),
    'utf8',
  );
  assert.match(
    workflow,
    /if \[ "\$GITHUB_ACTOR_ID" != "171286556" \]; then\n +echo "::error::release tags must be pushed by the authorized release actor"\n +exit 1\n +fi\n/,
  );
  // Owning the repository is no longer the release credential, so no comparison
  // against the owner login may remain.
  assert.doesNotMatch(workflow, /GITHUB_REPOSITORY_OWNER/);
  assert.match(
    workflow,
    /pkg\.repository\?\.url !== 'git\+https:\/\/github\.com\/agent-passport-system\/agent-passport-system\.git'/,
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

const RELEASE_CONTEXT = {
  GH_TOKEN: 'test-token',
  GITHUB_ACTOR_ID: '171286556',
  GITHUB_REPOSITORY: 'agent-passport-system/agent-passport-system',
  GITHUB_RUN_ID: '36022044285',
  GITHUB_RUN_ATTEMPT: '1',
};

function runAttemptDocument(overrides = {}) {
  return {
    id: 36022044285,
    run_attempt: 1,
    repository: { full_name: 'agent-passport-system/agent-passport-system', id: 1161268529 },
    actor: { id: 171286556, login: 'aeoess' },
    triggering_actor: { id: 171286556, login: 'aeoess' },
    ...overrides,
  };
}

// The guard's only external input is one GitHub REST response, so the tests
// drive it through an injected fetch and never reach the network.
function stubAttemptApi(reply, calls = []) {
  return async (url, options) => {
    calls.push({ url, options });
    if (typeof reply === 'function') return reply(url, options);
    return reply;
  };
}

function jsonReply(document, status = 200) {
  return {
    status,
    async text() {
      return JSON.stringify(document);
    },
  };
}

test('the release guard accepts the authorized release actor on an original run and on a rerun', async () => {
  const calls = [];
  assert.deepEqual(
    await authorizeReleaseActor({
      env: RELEASE_CONTEXT,
      fetchImpl: stubAttemptApi(jsonReply(runAttemptDocument()), calls),
    }),
    {
      repository: 'agent-passport-system/agent-passport-system',
      runId: 36022044285,
      runAttempt: 1,
      triggeringActorId: AUTHORIZED_RELEASE_ACTOR_ID,
    },
  );
  assert.equal(calls.length, 1);
  assert.equal(
    calls[0].url,
    'https://api.github.com/repos/agent-passport-system/agent-passport-system'
    + '/actions/runs/36022044285/attempts/1',
  );
  assert.equal(calls[0].options.redirect, 'error');

  // A rerun keeps GITHUB_ACTOR_ID on the original actor and raises the attempt
  // number. Tima rerunning his own release still passes.
  const rerun = [];
  assert.deepEqual(
    await authorizeReleaseActor({
      env: { ...RELEASE_CONTEXT, GITHUB_RUN_ATTEMPT: '3' },
      fetchImpl: stubAttemptApi(jsonReply(runAttemptDocument({ run_attempt: 3 })), rerun),
    }),
    {
      repository: 'agent-passport-system/agent-passport-system',
      runId: 36022044285,
      runAttempt: 3,
      triggeringActorId: AUTHORIZED_RELEASE_ACTOR_ID,
    },
  );
  assert.match(rerun[0].url, /\/actions\/runs\/36022044285\/attempts\/3$/);
});

test('the release guard rejects another original actor before it looks anything up', async () => {
  for (const actorId of ['281797194', '1', '', undefined, '0171286556', '171286556 ']) {
    const calls = [];
    await assert.rejects(
      authorizeReleaseActor({
        env: { ...RELEASE_CONTEXT, GITHUB_ACTOR_ID: actorId },
        fetchImpl: stubAttemptApi(jsonReply(runAttemptDocument()), calls),
      }),
      /release tags must be pushed by the authorized release actor/,
      `accepted GITHUB_ACTOR_ID ${JSON.stringify(actorId)}`,
    );
    assert.equal(calls.length, 0, 'an unauthorized original actor must not reach the API');
  }
});

test('the release guard rejects an attempt requested by a different actor', async () => {
  // Rerunning a failed publish job can reuse an earlier attempt's successful
  // authorize job, so the actor who asked for this attempt is checked too.
  for (const triggeringActor of [
    { id: 281797194, login: 'agent-passport-system' },
    { id: 1, login: 'someone-else' },
  ]) {
    await assert.rejects(
      authorizeReleaseActor({
        env: RELEASE_CONTEXT,
        fetchImpl: stubAttemptApi(jsonReply(runAttemptDocument({ triggering_actor: triggeringActor }))),
      }),
      /this release attempt must be requested by the authorized release actor/,
      `accepted triggering actor ${triggeringActor.id}`,
    );
  }
});

test('the release guard fails closed on a run attempt document it cannot trust', async () => {
  const cases = [
    [{ triggering_actor: undefined }, /has no triggering actor id/],
    [{ triggering_actor: null }, /has no triggering actor id/],
    [{ triggering_actor: {} }, /has no triggering actor id/],
    [{ triggering_actor: { id: '171286556' } }, /has no triggering actor id/],
    [{ repository: { full_name: 'aeoess/agent-passport-system' } }, /does not name this repository/],
    [{ repository: undefined }, /does not name this repository/],
    [{ id: 36022044286 }, /does not name this run/],
    [{ id: '36022044285' }, /does not name this run/],
    [{ run_attempt: 2 }, /does not name this attempt/],
    [{ run_attempt: undefined }, /does not name this attempt/],
  ];
  for (const [overrides, expected] of cases) {
    await assert.rejects(
      authorizeReleaseActor({
        env: RELEASE_CONTEXT,
        fetchImpl: stubAttemptApi(jsonReply(runAttemptDocument(overrides))),
      }),
      expected,
      `accepted ${JSON.stringify(overrides)}`,
    );
  }

  for (const body of [null, [runAttemptDocument()], 'a string', 7]) {
    await assert.rejects(
      authorizeReleaseActor({
        env: RELEASE_CONTEXT,
        fetchImpl: stubAttemptApi(jsonReply(body)),
      }),
      /returned a non-object document/,
      `accepted body ${JSON.stringify(body)}`,
    );
  }

  await assert.rejects(
    authorizeReleaseActor({
      env: RELEASE_CONTEXT,
      fetchImpl: stubAttemptApi({ status: 200, async text() { return '{not json'; } }),
    }),
    /returned invalid JSON/,
  );
});

test('the release guard fails closed when the run attempt lookup does not succeed', async () => {
  for (const status of [401, 403, 404, 410, 500, 502]) {
    await assert.rejects(
      authorizeReleaseActor({
        env: RELEASE_CONTEXT,
        fetchImpl: stubAttemptApi(jsonReply(runAttemptDocument(), status)),
      }),
      new RegExp(`returned HTTP ${status}; the requesting release actor is not established`),
      `accepted HTTP ${status}`,
    );
  }

  await assert.rejects(
    authorizeReleaseActor({
      env: RELEASE_CONTEXT,
      fetchImpl: async () => { throw new TypeError('fetch failed'); },
    }),
    /release run attempt lookup failed \(TypeError: fetch failed\)/,
  );
  await assert.rejects(
    authorizeReleaseActor({
      env: RELEASE_CONTEXT,
      fetchImpl: async () => ({ status: 200, async text() { throw new Error('socket hang up'); } }),
    }),
    /release run attempt lookup failed \(Error: socket hang up\)/,
  );
  // No fallback to allowing the release when the response object itself is unusable.
  await assert.rejects(
    authorizeReleaseActor({ env: RELEASE_CONTEXT, fetchImpl: async () => undefined }),
    /returned HTTP undefined/,
  );
});

test('the release guard refuses an incomplete workflow context', async () => {
  const broken = [
    [{ GITHUB_REPOSITORY: 'agent-passport-system' }, /invalid GITHUB_REPOSITORY/],
    [{ GITHUB_REPOSITORY: undefined }, /invalid GITHUB_REPOSITORY/],
    [{ GITHUB_RUN_ID: '0' }, /invalid GITHUB_RUN_ID/],
    [{ GITHUB_RUN_ID: 'latest' }, /invalid GITHUB_RUN_ID/],
    [{ GITHUB_RUN_ID: undefined }, /invalid GITHUB_RUN_ID/],
    [{ GITHUB_RUN_ATTEMPT: '' }, /invalid GITHUB_RUN_ATTEMPT/],
    [{ GITHUB_RUN_ATTEMPT: '-1' }, /invalid GITHUB_RUN_ATTEMPT/],
    [{ GH_TOKEN: '' }, /GH_TOKEN is required/],
    [{ GH_TOKEN: undefined }, /GH_TOKEN is required/],
  ];
  for (const [overrides, expected] of broken) {
    const calls = [];
    await assert.rejects(
      authorizeReleaseActor({
        env: { ...RELEASE_CONTEXT, ...overrides },
        fetchImpl: stubAttemptApi(jsonReply(runAttemptDocument()), calls),
      }),
      expected,
      `accepted ${JSON.stringify(overrides)}`,
    );
    assert.equal(calls.length, 0, 'an incomplete context must not reach the API');
  }
});

// Wiring, not behavior: the four tests above prove what the guard decides, and
// this one proves the workflow actually calls it in every job that holds a
// privileged permission, from the tagged release controls rather than from a
// downloaded artifact. Placement can only be read out of the workflow text.
test('every privileged release job runs the shared actor guard from the tagged controls', () => {
  const file = readFileSync(
    new URL('../workflows/release.yml', import.meta.url),
    'utf8',
  );
  const jobsIndex = file.indexOf('\njobs:\n');
  assert.ok(jobsIndex > 0);
  const workflow = file.slice(jobsIndex);
  const jobNames = [...workflow.matchAll(/^  ([a-z][a-z-]*):$/gm)].map((match) => ({
    name: match[1],
    index: match.index,
  }));
  assert.deepEqual(
    jobNames.map((job) => job.name),
    ['authorize', 'test', 'build', 'package', 'probe', 'attest', 'release', 'publish'],
  );
  const jobBody = (name) => {
    const position = jobNames.findIndex((job) => job.name === name);
    const next = jobNames[position + 1];
    return workflow.slice(jobNames[position].index, next ? next.index : workflow.length);
  };

  const guardCommands = {
    authorize: 'node .github/scripts/release-actor-state.mjs',
    attest: 'node release-source/.github/scripts/release-actor-state.mjs',
    release: 'node release-source/.github/scripts/release-actor-state.mjs',
    publish: 'node release-source/.github/scripts/release-actor-state.mjs',
  };
  for (const [name, command] of Object.entries(guardCommands)) {
    const body = jobBody(name);
    assert.match(
      body,
      new RegExp(`      - name: Require the authorized release actor\\n`
        + `        env:\\n`
        + `          GH_TOKEN: \\$\\{\\{ secrets.GITHUB_TOKEN \\}\\}\\n`
        + `        run: ${command.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')}\\n`),
      `${name} does not run the shared actor guard`,
    );
    assert.match(body, /^    permissions:\n(?:      [a-z-]+: [a-z]+\n)*      actions: read\n/m,
      `${name} does not grant the actions read permission the lookup needs`);
  }

  // Unprivileged jobs stay unchanged: no guard, no extra token permission.
  for (const name of ['test', 'build', 'package', 'probe']) {
    assert.doesNotMatch(jobBody(name), /release-actor-state\.mjs/);
    assert.doesNotMatch(jobBody(name), /actions: read/);
  }

  // The guard is release-controls code. It must never be read from the packed
  // artifact or from any downloaded bundle.
  assert.equal((workflow.match(/release-actor-state\.mjs/g) ?? []).length, 4);
  assert.doesNotMatch(workflow, /release-bundle\/\.github|public-release\/\.github/);
});
