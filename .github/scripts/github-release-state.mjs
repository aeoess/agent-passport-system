#!/usr/bin/env node

import { appendFile } from 'node:fs/promises';
import { resolve } from 'node:path';
import { pathToFileURL } from 'node:url';

function expectedAssetNames(expectedTag) {
  const version = expectedTag.slice(1);
  return [
    `agent-passport-system-${version}.intoto.jsonl`,
    `agent-passport-system-${version}.sbom.spdx.json`,
    `agent-passport-system-${version}.tgz`,
  ];
}

export function classifyGitHubReleaseResponse({ status, document }, expectedTag) {
  if (status === 404) return 'absent';
  if (status !== 200) {
    throw new Error(`GitHub release lookup returned HTTP ${status}; absence is not established`);
  }
  if (!document || typeof document !== 'object' || Array.isArray(document)) {
    throw new Error('GitHub returned HTTP 200 with a non-object release document');
  }
  if (document.tag_name !== expectedTag) {
    throw new Error(`GitHub release identity mismatch: expected tag ${expectedTag}`);
  }
  if (document.draft === true) {
    throw new Error(`GitHub release ${expectedTag} is an interrupted mutable draft; manual inspection is required`);
  }
  if (document.immutable !== true) {
    throw new Error(`GitHub release ${expectedTag} exists but is not immutable`);
  }

  const assets = document.assets;
  if (!Array.isArray(assets)) {
    throw new Error(`GitHub release ${expectedTag} has no assets array`);
  }
  const assetNames = assets.map((asset) => asset?.name).sort();
  const expectedNames = expectedAssetNames(expectedTag);
  if (assetNames.length !== expectedNames.length
    || !assetNames.every((name, index) => name === expectedNames[index])) {
    throw new Error(`GitHub release ${expectedTag} does not contain exactly the expected assets`);
  }
  if (assets.some((asset) => asset?.state !== 'uploaded')) {
    throw new Error(`GitHub release ${expectedTag} has an incomplete asset upload`);
  }
  return 'immutable';
}

function validateInputs(repository, tag, token) {
  if (!/^[A-Za-z0-9_.-]+\/[A-Za-z0-9_.-]+$/.test(repository ?? '')) {
    throw new Error('invalid GITHUB_REPOSITORY');
  }
  if (!/^v[0-9]+\.[0-9]+\.[0-9]+(?:-[0-9A-Za-z.-]+)?$/.test(tag ?? '')) {
    throw new Error('invalid GITHUB_REF_NAME release tag');
  }
  if (!token) throw new Error('GH_TOKEN is required');
}

async function main() {
  const repository = process.env.GITHUB_REPOSITORY;
  const tag = process.env.GITHUB_REF_NAME;
  const token = process.env.GH_TOKEN;
  validateInputs(repository, tag, token);

  const [owner, repo] = repository.split('/');
  const url = `https://api.github.com/repos/${encodeURIComponent(owner)}/${encodeURIComponent(repo)}/releases/tags/${encodeURIComponent(tag)}`;
  const response = await fetch(url, {
    headers: {
      accept: 'application/vnd.github+json',
      authorization: `Bearer ${token}`,
      'user-agent': 'agent-passport-system-release-guard',
      'x-github-api-version': '2026-03-10',
    },
    redirect: 'error',
    signal: AbortSignal.timeout(15_000),
  });

  let document;
  if (response.status === 200) {
    const text = await response.text();
    try {
      document = JSON.parse(text);
    } catch (error) {
      throw new Error(`GitHub returned invalid JSON: ${error.message}`);
    }
  }

  const state = classifyGitHubReleaseResponse({ status: response.status, document }, tag);
  if (process.env.GITHUB_OUTPUT) {
    await appendFile(process.env.GITHUB_OUTPUT, `state=${state}\n`, { encoding: 'utf8' });
  }
  console.log(`GitHub release ${tag}: ${state}`);
}

const invokedPath = process.argv[1] ? pathToFileURL(resolve(process.argv[1])).href : '';
if (import.meta.url === invokedPath) {
  main().catch((error) => {
    console.error(`::error::${error.message}`);
    process.exitCode = 1;
  });
}
