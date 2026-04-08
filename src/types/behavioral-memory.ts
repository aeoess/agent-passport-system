// Copyright 2024-2026 Tymofii Pidlisnyi. Apache-2.0 license. See LICENSE.
// Behavioral Memory Object — observation governance primitive

export interface BehavioralMemoryObject {
  id: string
  principal_id: string
  issuer_id: string
  issuer_signature: string
  pattern: {
    category: string
    description: string
    confidence: number
    observation_count: number
    observation_window: { start: string; end: string }
  }
  derivation_source: string
  retention_policy: { ttl: number; expires_at: string }
  relational_entities: boolean
  portable: boolean
  format_version: string
}

export interface BMOReceipt {
  receipt_id: string
  bmo_id: string
  event_type: 'create' | 'update' | 'export' | 'import' | 'delete' | 'expire'
  actor_id: string
  timestamp: string
  signature: string
}

export interface BMOExportBundle {
  bundle_id: string
  exported_at: string
  bmos: BehavioralMemoryObject[]
  exporter_id: string
  signature: string
}
