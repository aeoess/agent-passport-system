// ══════════════════════════════════════════════════════════════════
// Key Storage Backend — B-10 Security Hardening
// ══════════════════════════════════════════════════════════════════
// Pluggable key storage interface. Reference implementation stores
// keys in memory (same as before). Production deployments should
// implement encrypted file, HSM, or KMS backends.
//
// WARNING: The default InMemoryKeyStorage stores keys as raw hex
// in process memory. This is NOT safe for production. Use
// EncryptedFileKeyStorage or implement your own backend.
// ══════════════════════════════════════════════════════════════════

/**
 * Interface for pluggable key storage backends.
 * Implementations must handle key material securely.
 */
export interface KeyStorageBackend {
  /** Store a keypair under an agent ID */
  store(agentId: string, privateKey: string, publicKey: string): Promise<void>
  /** Retrieve a keypair by agent ID. Returns null if not found. */
  retrieve(agentId: string): Promise<{ privateKey: string; publicKey: string } | null>
  /** Delete a stored keypair */
  delete(agentId: string): Promise<boolean>
  /** List all stored agent IDs */
  list(): Promise<string[]>
}

import { createCipheriv, createDecipheriv, randomBytes, scryptSync } from 'crypto'

/**
 * Default in-memory key storage. Keys stored as raw hex in a Map.
 * WARNING: Not safe for production — keys lost on process restart,
 * no encryption at rest.
 */
export class InMemoryKeyStorage implements KeyStorageBackend {
  private keys = new Map<string, { privateKey: string; publicKey: string }>()

  async store(agentId: string, privateKey: string, publicKey: string): Promise<void> {
    this.keys.set(agentId, { privateKey, publicKey })
  }
  async retrieve(agentId: string) {
    return this.keys.get(agentId) ?? null
  }
  async delete(agentId: string) {
    return this.keys.delete(agentId)
  }
  async list() {
    return Array.from(this.keys.keys())
  }
}

/**
 * Encrypted file key storage. Keys encrypted with AES-256-GCM
 * using a password-derived key (scrypt). Stores as JSON file.
 * Better than raw hex — suitable for development and testing.
 * For production, implement HSM/KMS backend.
 */
export class EncryptedFileKeyStorage implements KeyStorageBackend {
  private password: string
  private filePath: string
  private cache: Map<string, { privateKey: string; publicKey: string }> = new Map()
  private loaded = false

  constructor(filePath: string, password: string) {
    this.filePath = filePath
    this.password = password
  }

  private encrypt(plaintext: string): string {
    const salt = randomBytes(16)
    const key = scryptSync(this.password, salt, 32)
    const iv = randomBytes(12)
    const cipher = createCipheriv('aes-256-gcm', key, iv)
    const encrypted = Buffer.concat([cipher.update(plaintext, 'utf8'), cipher.final()])
    const tag = cipher.getAuthTag()
    return [salt, iv, tag, encrypted].map(b => b.toString('hex')).join(':')
  }

  private decrypt(ciphertext: string): string {
    const [saltHex, ivHex, tagHex, encHex] = ciphertext.split(':')
    const salt = Buffer.from(saltHex, 'hex')
    const iv = Buffer.from(ivHex, 'hex')
    const tag = Buffer.from(tagHex, 'hex')
    const encrypted = Buffer.from(encHex, 'hex')
    const key = scryptSync(this.password, salt, 32)
    const decipher = createDecipheriv('aes-256-gcm', key, iv)
    decipher.setAuthTag(tag)
    return decipher.update(encrypted) + decipher.final('utf8')
  }

  private async load(): Promise<void> {
    if (this.loaded) return
    try {
      const { readFile } = await import('fs/promises')
      const data = JSON.parse(await readFile(this.filePath, 'utf8'))
      for (const [id, enc] of Object.entries(data as Record<string, string>)) {
        const decrypted = JSON.parse(this.decrypt(enc))
        this.cache.set(id, decrypted)
      }
    } catch { /* file doesn't exist yet */ }
    this.loaded = true
  }

  private async save(): Promise<void> {
    const { writeFile } = await import('fs/promises')
    const data: Record<string, string> = {}
    for (const [id, keys] of this.cache) {
      data[id] = this.encrypt(JSON.stringify(keys))
    }
    await writeFile(this.filePath, JSON.stringify(data, null, 2))
  }

  async store(agentId: string, privateKey: string, publicKey: string): Promise<void> {
    await this.load()
    this.cache.set(agentId, { privateKey, publicKey })
    await this.save()
  }
  async retrieve(agentId: string) {
    await this.load()
    return this.cache.get(agentId) ?? null
  }
  async delete(agentId: string) {
    await this.load()
    const deleted = this.cache.delete(agentId)
    if (deleted) await this.save()
    return deleted
  }
  async list() {
    await this.load()
    return Array.from(this.cache.keys())
  }
}
