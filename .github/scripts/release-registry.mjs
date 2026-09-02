#!/usr/bin/env node

import { createHash } from 'node:crypto';
import { appendFile } from 'node:fs/promises';
import { basename, dirname, isAbsolute, resolve } from 'node:path';
import { pathToFileURL } from 'node:url';

import { readOpenedRegularFile } from './opened-regular-file.mjs';

const PACKAGE_NAME = 'agent-passport-system';
const PROVENANCE_PREDICATE = 'https://slsa.dev/provenance/v1';

export class ProvenanceUnavailableError extends Error {}

export function artifactDigests(bytes) {
  return {
    shasum: createHash('sha1').update(bytes).digest('hex'),
    integrity: `sha512-${createHash('sha512').update(bytes).digest('base64')}`,
    sha256: createHash('sha256').update(bytes).digest('hex'),
  };
}

function hasExpectedProvenance(dist, version) {
  const attestations = dist?.attestations;
  if (attestations?.provenance?.predicateType !== PROVENANCE_PREDICATE) {
    return false;
  }

  const expectedUrl = `https://registry.npmjs.org/-/npm/v1/attestations/${PACKAGE_NAME}@${version}`;
  return attestations.url === expectedUrl;
}

export function classifyRegistryResponse({ status, document }, {
  version,
  localDigests,
  requirePresent = false,
  requireProvenance = false,
}) {
  if (status === 404) {
    if (requirePresent) {
      throw new Error(`registry returned HTTP 404 for ${PACKAGE_NAME}@${version} after publication`);
    }
    return { state: 'absent', provenance: 'absent', ...localDigests };
  }

  if (status !== 200) {
    throw new Error(`registry lookup returned HTTP ${status}; absence is not established`);
  }

  if (!document || typeof document !== 'object' || Array.isArray(document)) {
    throw new Error('registry returned HTTP 200 with a non-object JSON document');
  }
  if (document.name !== PACKAGE_NAME || document.version !== version) {
    throw new Error(`registry identity mismatch: expected ${PACKAGE_NAME}@${version}`);
  }

  const shasum = document.dist?.shasum;
  const integrity = document.dist?.integrity;
  if (!/^[0-9a-f]{40}$/.test(shasum ?? '')) {
    throw new Error('registry response has no valid dist.shasum');
  }
  if (!/^sha512-[A-Za-z0-9+/]+={0,2}$/.test(integrity ?? '')) {
    throw new Error('registry response has no valid sha512 dist.integrity');
  }
  if (shasum !== localDigests.shasum || integrity !== localDigests.integrity) {
    throw new Error(
      `published bytes differ from the packed artifact (registry sha1 ${shasum}, local sha1 ${localDigests.shasum})`,
    );
  }

  const provenance = hasExpectedProvenance(document.dist, version) ? 'present' : 'absent';
  if (requireProvenance && provenance !== 'present') {
    throw new ProvenanceUnavailableError(
      `registry metadata for ${PACKAGE_NAME}@${version} does not expose npm provenance`,
    );
  }

  return { state: 'identical', provenance, ...localDigests };
}

function validateVersion(version) {
  if (!/^[0-9]+\.[0-9]+\.[0-9]+(?:-[0-9A-Za-z.-]+)?$/.test(version ?? '')) {
    throw new Error(`invalid release version: ${version ?? '<missing>'}`);
  }
}

export async function loadArtifact(version, input, options = {}) {
  if (!input || isAbsolute(input) || basename(input) !== input) {
    throw new Error('TARBALL must be a basename in the current working directory');
  }
  const expected = `${PACKAGE_NAME}-${version}.tgz`;
  if (input !== expected) {
    throw new Error(`unexpected tarball name: expected ${expected}, got ${input}`);
  }

  const workingDirectory = resolve(options.cwd ?? '.');
  const fullPath = resolve(workingDirectory, input);
  if (dirname(fullPath) !== workingDirectory) {
    throw new Error('tarball resolved outside the current working directory');
  }

  const bytes = await readOpenedRegularFile(
    fullPath,
    'tarball must be a regular, non-symlink file',
    options,
  );
  return artifactDigests(bytes);
}

async function fetchRegistryDocument(version) {
  const url = `https://registry.npmjs.org/${encodeURIComponent(PACKAGE_NAME)}/${encodeURIComponent(version)}`;
  const response = await fetch(url, {
    headers: {
      accept: 'application/json',
      'user-agent': 'agent-passport-system-release-guard',
    },
    redirect: 'error',
    signal: AbortSignal.timeout(15_000),
  });

  if (response.status !== 200) {
    return { status: response.status, document: undefined };
  }

  const text = await response.text();
  try {
    return { status: response.status, document: JSON.parse(text) };
  } catch (error) {
    throw new Error(`registry returned invalid JSON: ${error.message}`);
  }
}

async function writeOutputs(result) {
  if (!process.env.GITHUB_OUTPUT) return;
  const lines = [
    `state=${result.state}`,
    `provenance=${result.provenance}`,
    `shasum=${result.shasum}`,
    `integrity=${result.integrity}`,
    `sha256=${result.sha256}`,
  ];
  await appendFile(process.env.GITHUB_OUTPUT, `${lines.join('\n')}\n`, { encoding: 'utf8' });
}

async function main() {
  const version = process.env.PACKAGE_VERSION;
  validateVersion(version);
  const localDigests = await loadArtifact(version, process.env.TARBALL);
  const requirePresent = process.env.REQUIRE_PRESENT === 'true';
  const requireProvenance = process.env.REQUIRE_PROVENANCE === 'true';

  let result;
  for (let attempt = 1; attempt <= 6; attempt += 1) {
    const response = await fetchRegistryDocument(version);
    try {
      result = classifyRegistryResponse(response, {
        version,
        localDigests,
        requirePresent,
        requireProvenance,
      });
      break;
    } catch (error) {
      if (!(error instanceof ProvenanceUnavailableError) || attempt === 6) throw error;
      await new Promise((resolveDelay) => setTimeout(resolveDelay, 5_000));
    }
  }

  await writeOutputs(result);
  if (result.state === 'absent') {
    console.log(`${PACKAGE_NAME}@${version}: registry state absent (HTTP 404)`);
  } else {
    console.log(
      `${PACKAGE_NAME}@${version}: registry bytes identical; npm provenance ${result.provenance}; sha1 ${result.shasum}`,
    );
  }
}

const invokedPath = process.argv[1] ? pathToFileURL(resolve(process.argv[1])).href : '';
if (import.meta.url === invokedPath) {
  main().catch((error) => {
    console.error(`::error::${error.message}`);
    process.exitCode = 1;
  });
}
