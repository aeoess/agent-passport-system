// Copyright 2026 Tymofii Pidlisnyi. Apache-2.0 license. See LICENSE.
/**
 * Deterministic POSIX ustar reader/writer for the policy-bundle primitive.
 *
 * This is a minimal, dependency-free tar implementation scoped to what the
 * policy-bundle format needs: regular files only, no symlinks, no devices,
 * no PAX extensions. It is deterministic by construction so that the same
 * file set always serializes to the same bytes, which is required for the
 * content-addressed bundle hash to be stable.
 *
 * Determinism rules applied here:
 *   - entries are sorted by name (Unicode code point) before writing
 *   - mtime, uid, gid, uname, gname are fixed to constant values
 *   - file mode is fixed to 0o644
 *
 * This is a FORMAT primitive only. It is not a general archiver and is not a
 * tar service. It reads and writes a byte array in memory.
 */

const BLOCK_SIZE = 512
const NAME_MAX = 100

/** A single regular-file entry inside a policy-bundle tar. */
export interface TarEntry {
  /** POSIX path inside the archive (forward slashes, no leading slash). */
  name: string
  /** Raw file bytes. */
  data: Uint8Array
}

// Fixed header field values. Constants, not host-derived, so output is
// reproducible across machines and runs.
const FIXED_MODE = '000644 '
const FIXED_ID = '0000000 '
const FIXED_MTIME = '00000000000 ' // epoch 0, octal, 11 digits + space
const FIXED_MAGIC = 'ustar\0'
const FIXED_VERSION = '00'

function octal(value: number, width: number): string {
  // width includes the trailing space/null terminator handling done by caller.
  return value.toString(8).padStart(width, '0')
}

function writeString(buf: Uint8Array, offset: number, value: string, length: number): void {
  const bytes = new TextEncoder().encode(value)
  if (bytes.length > length) {
    throw new Error(`tar: field value too long (${bytes.length} > ${length}) for "${value}"`)
  }
  buf.set(bytes, offset)
}

function computeChecksum(header: Uint8Array): number {
  let sum = 0
  for (let i = 0; i < BLOCK_SIZE; i++) {
    // Checksum field (offset 148, length 8) is treated as spaces during compute.
    if (i >= 148 && i < 156) {
      sum += 0x20
    } else {
      sum += header[i]
    }
  }
  return sum
}

function buildHeader(entry: TarEntry): Uint8Array {
  const nameBytes = new TextEncoder().encode(entry.name)
  if (nameBytes.length > NAME_MAX) {
    throw new Error(`tar: entry name exceeds ${NAME_MAX} bytes: "${entry.name}"`)
  }
  if (entry.name.startsWith('/')) {
    throw new Error(`tar: entry name must not be absolute: "${entry.name}"`)
  }

  const header = new Uint8Array(BLOCK_SIZE)

  writeString(header, 0, entry.name, NAME_MAX)              // name (100)
  writeString(header, 100, FIXED_MODE, 8)                   // mode (8)
  writeString(header, 108, FIXED_ID, 8)                     // uid (8)
  writeString(header, 116, FIXED_ID, 8)                     // gid (8)
  writeString(header, 124, octal(entry.data.length, 11) + ' ', 12) // size (12)
  writeString(header, 136, FIXED_MTIME, 12)                 // mtime (12)
  // checksum (8) at 148, filled after compute
  header[156] = 0x30                                        // typeflag '0' (regular file)
  // linkname (100) at 157, left zero
  writeString(header, 257, FIXED_MAGIC, 6)                  // magic (6)
  writeString(header, 263, FIXED_VERSION, 2)                // version (2)
  // uname (32) at 265, gname (32) at 297, left empty/zero (deterministic)

  const checksum = computeChecksum(header)
  // POSIX: 6 octal digits, NUL, space.
  const checksumField = octal(checksum, 6) + '\0 '
  writeString(header, 148, checksumField, 8)

  return header
}

/**
 * Serialize a set of entries into a deterministic ustar byte array.
 * Entries are sorted by name before writing. Two equal file sets always
 * produce identical bytes.
 */
export function packTar(entries: TarEntry[]): Uint8Array {
  const names = new Set<string>()
  for (const e of entries) {
    if (names.has(e.name)) throw new Error(`tar: duplicate entry name "${e.name}"`)
    names.add(e.name)
  }

  const sorted = [...entries].sort((a, b) => (a.name < b.name ? -1 : a.name > b.name ? 1 : 0))

  const blocks: Uint8Array[] = []
  for (const entry of sorted) {
    blocks.push(buildHeader(entry))
    blocks.push(entry.data)
    const remainder = entry.data.length % BLOCK_SIZE
    if (remainder !== 0) {
      blocks.push(new Uint8Array(BLOCK_SIZE - remainder))
    }
  }
  // Two zero blocks mark end of archive.
  blocks.push(new Uint8Array(BLOCK_SIZE))
  blocks.push(new Uint8Array(BLOCK_SIZE))

  let total = 0
  for (const b of blocks) total += b.length
  const out = new Uint8Array(total)
  let pos = 0
  for (const b of blocks) {
    out.set(b, pos)
    pos += b.length
  }
  return out
}

function readString(buf: Uint8Array, offset: number, length: number): string {
  let end = offset
  const limit = offset + length
  while (end < limit && buf[end] !== 0) end++
  return new TextDecoder().decode(buf.subarray(offset, end)).trimEnd()
}

function readOctal(buf: Uint8Array, offset: number, length: number): number {
  const raw = readString(buf, offset, length).trim()
  if (raw === '') return 0
  const n = parseInt(raw, 8)
  if (Number.isNaN(n)) throw new Error('tar: invalid octal field')
  return n
}

function isZeroBlock(buf: Uint8Array, offset: number): boolean {
  for (let i = 0; i < BLOCK_SIZE; i++) {
    if (buf[offset + i] !== 0) return false
  }
  return true
}

/**
 * Parse a ustar byte array back into entries. Validates each header
 * checksum so a corrupted archive is rejected at read time. Only regular
 * files (typeflag '0' or '\0') are accepted.
 */
export function unpackTar(archive: Uint8Array): TarEntry[] {
  if (archive.length % BLOCK_SIZE !== 0) {
    throw new Error('tar: archive length is not a multiple of 512')
  }
  const entries: TarEntry[] = []
  let pos = 0

  while (pos + BLOCK_SIZE <= archive.length) {
    if (isZeroBlock(archive, pos)) break

    const header = archive.subarray(pos, pos + BLOCK_SIZE)

    // Validate checksum.
    const storedChecksum = readOctal(archive, pos + 148, 8)
    const computed = computeChecksum(header)
    if (storedChecksum !== computed) {
      throw new Error('tar: header checksum mismatch (archive corrupted)')
    }

    const name = readString(archive, pos, NAME_MAX)
    const size = readOctal(archive, pos + 124, 12)
    const typeflag = archive[pos + 156]
    if (typeflag !== 0x30 && typeflag !== 0x00) {
      throw new Error(`tar: unsupported entry type (flag ${typeflag}) for "${name}"`)
    }

    pos += BLOCK_SIZE
    const data = archive.slice(pos, pos + size)
    if (data.length !== size) {
      throw new Error('tar: truncated archive (entry data shorter than declared size)')
    }
    entries.push({ name, data })

    const consumed = Math.ceil(size / BLOCK_SIZE) * BLOCK_SIZE
    pos += consumed
  }

  return entries
}
