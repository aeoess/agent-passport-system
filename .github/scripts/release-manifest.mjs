#!/usr/bin/env node

import { basename, dirname, isAbsolute, resolve } from 'node:path';
import { pathToFileURL } from 'node:url';

import { readOpenedRegularFile } from './opened-regular-file.mjs';

const PACKAGE_NAME = 'agent-passport-system';
const REPOSITORY_URL = 'git+https://github.com/aeoess/agent-passport-system.git';
export function validatePublishManifest(manifest, expectedVersion) {
  if (!manifest || typeof manifest !== 'object' || Array.isArray(manifest)) {
    throw new Error('publish manifest is not an object');
  }
  if (manifest.name !== PACKAGE_NAME || manifest.version !== expectedVersion) {
    throw new Error(`publish manifest identity mismatch: expected ${PACKAGE_NAME}@${expectedVersion}`);
  }
  if (manifest.repository?.url !== REPOSITORY_URL) {
    throw new Error('publish manifest repository does not match the trusted publisher');
  }
  if (Object.hasOwn(manifest, 'publishConfig')) {
    throw new Error('publishConfig is forbidden because it can redirect privileged npm publication');
  }
  return { name: manifest.name, version: manifest.version };
}

function validateVersion(version) {
  if (!/^[0-9]+\.[0-9]+\.[0-9]+(?:-[0-9A-Za-z.-]+)?$/.test(version ?? '')) {
    throw new Error(`invalid release version: ${version ?? '<missing>'}`);
  }
}

export async function loadManifest(input, options = {}) {
  if (!input || isAbsolute(input) || basename(input) !== input) {
    throw new Error('MANIFEST must be a basename in the current working directory');
  }
  const workingDirectory = resolve(options.cwd ?? '.');
  const fullPath = resolve(workingDirectory, input);
  if (dirname(fullPath) !== workingDirectory) {
    throw new Error('publish manifest resolved outside the current working directory');
  }
  const text = await readOpenedRegularFile(
    fullPath,
    'publish manifest must be a regular, non-symlink file',
    { ...options, encoding: 'utf8' },
  );
  try {
    return JSON.parse(text);
  } catch (error) {
    throw new Error(`publish manifest is not valid JSON: ${error.message}`);
  }
}

async function main() {
  const version = process.env.PACKAGE_VERSION;
  validateVersion(version);
  const manifest = await loadManifest(process.env.MANIFEST);
  const result = validatePublishManifest(manifest, version);
  console.log(`publish manifest: ${result.name}@${result.version}; no publishConfig redirection`);
}

const invokedPath = process.argv[1] ? pathToFileURL(resolve(process.argv[1])).href : '';
if (import.meta.url === invokedPath) {
  main().catch((error) => {
    console.error(`::error::${error.message}`);
    process.exitCode = 1;
  });
}
