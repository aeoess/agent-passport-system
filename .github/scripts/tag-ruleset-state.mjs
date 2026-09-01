#!/usr/bin/env node

import { resolve } from 'node:path';
import { pathToFileURL } from 'node:url';

const EXPECTED_NAME = 'immutable-version-tags';
const EXPECTED_REPOSITORY = 'aeoess/agent-passport-system';
const EXPECTED_OWNER_ID = 171286556;
const EXPECTED_REF_INCLUDE = 'refs/tags/v*';
const REQUIRED_RULES = new Set([
  'creation',
  'update',
  'deletion',
  'non_fast_forward',
]);

function sameMembers(actual, expected) {
  return actual.length === expected.length
    && actual.every((item) => expected.includes(item));
}

export function validateImmutableVersionTagRuleset(document, {
  expectedRepository = EXPECTED_REPOSITORY,
  expectedOwnerId = EXPECTED_OWNER_ID,
} = {}) {
  if (!document || typeof document !== 'object' || Array.isArray(document)) {
    throw new Error('immutable version-tag ruleset is not an object');
  }
  if (document.name !== EXPECTED_NAME) {
    throw new Error(`expected ruleset ${EXPECTED_NAME}`);
  }
  if (document.target !== 'tag' || document.enforcement !== 'active') {
    throw new Error('immutable version-tag ruleset must target tags with active enforcement');
  }
  if (document.source && document.source !== expectedRepository) {
    throw new Error(`immutable version-tag ruleset has unexpected source ${document.source}`);
  }

  const include = document.conditions?.ref_name?.include;
  const exclude = document.conditions?.ref_name?.exclude;
  if (!Array.isArray(include) || !sameMembers(include, [EXPECTED_REF_INCLUDE])) {
    throw new Error(`immutable version-tag ruleset must include only ${EXPECTED_REF_INCLUDE}`);
  }
  if (!Array.isArray(exclude) || exclude.length !== 0) {
    throw new Error('immutable version-tag ruleset must not exclude release tags');
  }

  const ruleTypes = document.rules?.map((rule) => rule?.type);
  if (!Array.isArray(ruleTypes)) {
    throw new Error('immutable version-tag ruleset has no rules array');
  }
  for (const required of REQUIRED_RULES) {
    if (!ruleTypes.includes(required)) {
      throw new Error(`immutable version-tag ruleset is missing ${required}`);
    }
  }

  const bypassActors = document.bypass_actors;
  if (bypassActors !== undefined) {
    if (!Array.isArray(bypassActors) || bypassActors.length !== 1) {
      throw new Error('immutable version-tag ruleset must have exactly one visible bypass actor');
    }
    const [actor] = bypassActors;
    if (actor?.actor_type !== 'User'
      || actor?.actor_id !== expectedOwnerId
      || actor?.bypass_mode !== 'always') {
      throw new Error('immutable version-tag ruleset bypass must be the repository owner only');
    }
  }

  return {
    state: 'active',
    bypassVisibility: bypassActors === undefined ? 'not-visible' : 'visible',
  };
}

function validateInputs(repository, token) {
  if (repository !== EXPECTED_REPOSITORY) {
    throw new Error(`unexpected GITHUB_REPOSITORY: ${repository ?? '<missing>'}`);
  }
  if (!token) throw new Error('GH_TOKEN is required');
}

async function fetchJson(path, token) {
  const response = await fetch(`https://api.github.com${path}`, {
    headers: {
      accept: 'application/vnd.github+json',
      authorization: `Bearer ${token}`,
      'user-agent': 'agent-passport-system-release-guard',
      'x-github-api-version': '2022-11-28',
    },
    redirect: 'error',
    signal: AbortSignal.timeout(15_000),
  });
  if (response.status !== 200) {
    throw new Error(`GitHub ruleset lookup returned HTTP ${response.status}`);
  }
  const text = await response.text();
  try {
    return JSON.parse(text);
  } catch (error) {
    throw new Error(`GitHub ruleset lookup returned invalid JSON: ${error.message}`);
  }
}

async function main() {
  const repository = process.env.GITHUB_REPOSITORY;
  const token = process.env.GH_TOKEN;
  validateInputs(repository, token);

  const summaries = await fetchJson(`/repos/${repository}/rulesets?includes_parents=true`, token);
  if (!Array.isArray(summaries)) {
    throw new Error('GitHub ruleset list is not an array');
  }
  const matches = summaries.filter((item) => item?.name === EXPECTED_NAME);
  if (matches.length !== 1 || !Number.isInteger(matches[0]?.id)) {
    throw new Error(`expected exactly one ${EXPECTED_NAME} ruleset, found ${matches.length}`);
  }

  const document = await fetchJson(`/repos/${repository}/rulesets/${matches[0].id}?includes_parents=true`, token);
  const result = validateImmutableVersionTagRuleset(document, { expectedRepository: repository });
  if (result.bypassVisibility === 'not-visible') {
    console.log(
      `::notice::${EXPECTED_NAME}: structural restrictions are active; GitHub hides bypass actors from the workflow token, so the principal gate must verify the owner-only bypass`,
    );
  } else {
    console.log(`${EXPECTED_NAME}: active with the repository owner as the sole bypass actor`);
  }
}

const invokedPath = process.argv[1] ? pathToFileURL(resolve(process.argv[1])).href : '';
if (import.meta.url === invokedPath) {
  main().catch((error) => {
    console.error(`::error::${error.message}`);
    process.exitCode = 1;
  });
}
