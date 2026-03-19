// Key Rotation & Identity Continuity — Types (Module 22)
// Tracks Ed25519 key lifecycle: creation, rotation, emergency recovery
// Each rotation is signed by BOTH old and new keys, proving continuity + possession

export interface IdentityDocument {
  identityId: string              // 'id_' + uuid prefix
  currentPublicKey: string        // hex-encoded Ed25519 public key
  previousPublicKey: string | null // null for initial identity
  rotationLog: KeyRotationEntry[] // append-only log of rotations
  recoveryKeys: string[]          // pre-committed recovery public keys (N-of-M)
  createdAt: string               // ISO timestamp
  updatedAt: string               // ISO timestamp
}

export interface KeyRotationEntry {
  rotationId: string              // 'rot_' + uuid prefix
  oldPublicKey: string            // key being rotated OUT
  newPublicKey: string            // key being rotated IN
  reason: 'scheduled' | 'compromise' | 'upgrade' | 'recovery'
  rotatedAt: string               // ISO timestamp
  // Signed by OLD key — proves the old key holder authorized this rotation
  continuitySignature: string
  // Signed by NEW key — proves possession of the new key
  possessionSignature: string
}

export interface RotationVerification {
  valid: boolean
  errors: string[]
  continuityValid: boolean    // old key signed the rotation
  possessionValid: boolean    // new key signed the rotation
  chainValid: boolean         // rotation log is internally consistent
}
