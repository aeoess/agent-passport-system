#!/usr/bin/env node

import { lstat, readFile } from 'node:fs/promises';
import { basename, dirname, isAbsolute, resolve } from 'node:path';
import { pathToFileURL } from 'node:url';

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

async function loadManifest(input) {
  if (!input || isAbsolute(input) || basename(input) !== input) {
    throw new Error('MANIFEST must be a basename in the current working directory');
  }
  const fullPath = resolve(input);
  if (dirname(fullPath) !== resolve('.')) {
    throw new Error('publish manifest resolved outside the current working directory');
  }
  const stat = await lstat(fullPath);
  if (!stat.isFile() || stat.isSymbolicLink()) {
    throw new Error('publish manifest must be a regular, non-symlink file');
  }
  try {
    return JSON.parse(await readFile(fullPath, 'utf8'));
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
