import { constants } from 'node:fs';
import { open } from 'node:fs/promises';

function secureReadFlags(fsConstants) {
  const required = ['O_RDONLY', 'O_NOFOLLOW', 'O_NONBLOCK'];
  for (const name of required) {
    if (typeof fsConstants[name] !== 'number') {
      throw new Error(`${name} is unavailable; refusing an unsafe pathname-based fallback`);
    }
  }
  return fsConstants.O_RDONLY | fsConstants.O_NOFOLLOW | fsConstants.O_NONBLOCK;
}

export async function readOpenedRegularFile(
  fullPath,
  regularFileError,
  { encoding, openFile = open, fsConstants = constants } = {},
) {
  let handle;
  try {
    handle = await openFile(fullPath, secureReadFlags(fsConstants));
    const stat = await handle.stat();
    if (!stat.isFile()) {
      throw new Error(regularFileError);
    }
    return encoding === undefined
      ? await handle.readFile()
      : await handle.readFile({ encoding });
  } catch (error) {
    if (error?.code === 'ELOOP' || error?.code === 'EMLINK') {
      throw new Error(regularFileError, { cause: error });
    }
    throw error;
  } finally {
    if (handle) {
      await handle.close();
    }
  }
}
