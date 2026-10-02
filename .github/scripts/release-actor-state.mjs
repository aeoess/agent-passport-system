#!/usr/bin/env node

import { resolve } from 'node:path';
import { pathToFileURL } from 'node:url';

// Repository ownership is not the release credential, so every privileged job
// checks the actor instead of the owner. Two actors matter. GITHUB_ACTOR_ID is
// the actor who started the run, and GitHub keeps it pointing at that original
// actor on a rerun. The run attempt's triggering_actor is whoever asked for
// this attempt. Checking only the first would let a rerun of a failed publish
// job reuse an earlier attempt's authorization, so both must be the authorized
// release actor. Fail closed on anything unexpected.
export const AUTHORIZED_RELEASE_ACTOR_ID = 171286556;

// The repository id survives a transfer between owners, so it is the one piece
// of repository identity that a rename or a move cannot change. Pinning it
// means a run against some other repository that happens to carry the expected
// full name cannot satisfy this guard. GITHUB_REPOSITORY_ID is a documented
// default workflow variable, and the document's repository.id must agree with
// it and with this pin.
export const SDK_REPOSITORY_ID = 1161268529;

const REPOSITORY_PATTERN = /^[A-Za-z0-9_.-]+\/[A-Za-z0-9_.-]+$/;
const BOUNDED_ERROR_LENGTH = 120;

function boundedCause(error) {
  const name = typeof error?.name === 'string' && error.name ? error.name : 'Error';
  const message = typeof error?.message === 'string' ? error.message : '';
  return message ? `${name}: ${message.slice(0, BOUNDED_ERROR_LENGTH)}` : name;
}

function readRunNumber(value, label) {
  if (typeof value !== 'string' || !/^[1-9][0-9]*$/.test(value)) {
    throw new Error(`invalid ${label}`);
  }
  const parsed = Number(value);
  if (!Number.isSafeInteger(parsed)) {
    throw new Error(`invalid ${label}`);
  }
  return parsed;
}

export function validateOriginalReleaseActor(actorId, {
  expectedActorId = AUTHORIZED_RELEASE_ACTOR_ID,
} = {}) {
  if (typeof actorId !== 'string'
    || !/^[1-9][0-9]*$/.test(actorId)
    || Number(actorId) !== expectedActorId) {
    throw new Error('release tags must be pushed by the authorized release actor');
  }
  return expectedActorId;
}

export function validateReleaseRunAttempt(context, response, {
  expectedActorId = AUTHORIZED_RELEASE_ACTOR_ID,
  expectedRepositoryId = SDK_REPOSITORY_ID,
} = {}) {
  const { repository, repositoryId, runId, runAttempt } = context;
  const { status, document } = response;

  if (status !== 200) {
    throw new Error(
      `release run attempt lookup returned HTTP ${status}; the requesting release actor is not established`,
    );
  }
  if (!document || typeof document !== 'object' || Array.isArray(document)) {
    throw new Error('release run attempt lookup returned a non-object document');
  }
  if (document.repository?.full_name !== repository) {
    throw new Error('release run attempt document does not name this repository');
  }

  const documentRepositoryId = document.repository?.id;
  if (!Number.isInteger(documentRepositoryId)) {
    throw new Error('release run attempt document has no repository id');
  }
  if (documentRepositoryId !== repositoryId) {
    throw new Error('release run attempt document does not name this repository id');
  }
  if (documentRepositoryId !== expectedRepositoryId) {
    throw new Error('release run attempt document does not name the pinned release repository id');
  }
  if (document.id !== runId) {
    throw new Error('release run attempt document does not name this run');
  }
  if (document.run_attempt !== runAttempt) {
    throw new Error('release run attempt document does not name this attempt');
  }

  const triggeringActorId = document.triggering_actor?.id;
  if (!Number.isInteger(triggeringActorId)) {
    throw new Error('release run attempt document has no triggering actor id');
  }
  if (triggeringActorId !== expectedActorId) {
    throw new Error('this release attempt must be requested by the authorized release actor');
  }

  return { repository, repositoryId, runId, runAttempt, triggeringActorId };
}

export async function authorizeReleaseActor({
  env = process.env,
  fetchImpl = fetch,
  expectedActorId = AUTHORIZED_RELEASE_ACTOR_ID,
  expectedRepositoryId = SDK_REPOSITORY_ID,
} = {}) {
  validateOriginalReleaseActor(env.GITHUB_ACTOR_ID, { expectedActorId });

  const repository = env.GITHUB_REPOSITORY;
  if (!REPOSITORY_PATTERN.test(repository ?? '')) {
    throw new Error('invalid GITHUB_REPOSITORY');
  }
  const repositoryId = readRunNumber(env.GITHUB_REPOSITORY_ID, 'GITHUB_REPOSITORY_ID');
  if (repositoryId !== expectedRepositoryId) {
    throw new Error('GITHUB_REPOSITORY_ID is not the pinned release repository id');
  }
  const runId = readRunNumber(env.GITHUB_RUN_ID, 'GITHUB_RUN_ID');
  const runAttempt = readRunNumber(env.GITHUB_RUN_ATTEMPT, 'GITHUB_RUN_ATTEMPT');
  const token = env.GH_TOKEN;
  if (!token) throw new Error('GH_TOKEN is required');

  const [owner, repo] = repository.split('/');
  const url = `https://api.github.com/repos/${encodeURIComponent(owner)}/${encodeURIComponent(repo)}`
    + `/actions/runs/${runId}/attempts/${runAttempt}`;

  let response;
  try {
    response = await fetchImpl(url, {
      headers: {
        accept: 'application/vnd.github+json',
        authorization: `Bearer ${token}`,
        'user-agent': 'agent-passport-system-release-guard',
        'x-github-api-version': '2022-11-28',
      },
      redirect: 'error',
      signal: AbortSignal.timeout(15_000),
    });
  } catch (error) {
    throw new Error(`release run attempt lookup failed (${boundedCause(error)})`);
  }

  let document;
  if (response?.status === 200) {
    let text;
    try {
      text = await response.text();
    } catch (error) {
      throw new Error(`release run attempt lookup failed (${boundedCause(error)})`);
    }
    try {
      document = JSON.parse(text);
    } catch {
      throw new Error('release run attempt lookup returned invalid JSON');
    }
  }

  return validateReleaseRunAttempt(
    { repository, repositoryId, runId, runAttempt },
    { status: response?.status, document },
    { expectedActorId, expectedRepositoryId },
  );
}

async function main() {
  const summary = await authorizeReleaseActor();
  console.log(
    `release principal: the run actor and the actor requesting attempt ${summary.runAttempt} of run `
    + `${summary.runId} in ${summary.repository} (repository id ${summary.repositoryId}) are both `
    + `the authorized release actor ${summary.triggeringActorId}`,
  );
}

const invokedPath = process.argv[1] ? pathToFileURL(resolve(process.argv[1])).href : '';
if (import.meta.url === invokedPath) {
  main().catch((error) => {
    console.error(`::error::${error.message}`);
    process.exitCode = 1;
  });
}
