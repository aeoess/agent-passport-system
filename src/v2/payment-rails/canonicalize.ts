// Copyright 2026 Tymofii Pidlisnyi. Apache-2.0 license. See LICENSE.
// ══════════════════════════════════════════════════════════════════
// Payment Rails — canonicalization helpers
// ══════════════════════════════════════════════════════════════════
// Receipts and denials are signed over RFC 8785 JCS canonical bytes
// of the object with `signature` emptied. This module wraps the
// SDK's existing canonicalizeJCS for the rail-specific shape, and
// exposes a sha256 helper rails use to derive receipt_id.
//
// Pattern mirrors src/v2/accountability/construct/*.ts: build the
// envelope with signature: '', canonicalize, sha256 → receipt_id,
// re-canonicalize with the populated receipt_id and empty signature,
// Ed25519 sign that, store the signature.
// ══════════════════════════════════════════════════════════════════

import { createHash } from 'node:crypto'
import { canonicalizeJCS } from '../../core/canonical-jcs.js'
import type { PaymentDenial, PaymentInvoice, PaymentReceipt } from './types.js'

/** sha256 hex of a UTF-8 canonical string. */
export function sha256Hex(s: string): string {
  return createHash('sha256').update(s, 'utf8').digest('hex')
}

/**
 * Build the canonical bytes used for receipt_id derivation and
 * signing. The signature field is forced to empty string ('') and
 * receipt_id is forced to empty when deriving the id; the signing
 * payload uses the populated receipt_id with empty signature. This
 * matches the Wave 1 accountability id-then-signature ordering.
 */
export function canonicalizeReceiptForId(receipt: PaymentReceipt): string {
  return canonicalizeJCS({ ...receipt, receipt_id: '', signature: '' })
}

export function canonicalizeReceiptForSig(receipt: PaymentReceipt): string {
  return canonicalizeJCS({ ...receipt, signature: '' })
}

export function canonicalizeDenialForId(denial: PaymentDenial): string {
  return canonicalizeJCS({ ...denial, receipt_id: '', signature: '' })
}

export function canonicalizeDenialForSig(denial: PaymentDenial): string {
  return canonicalizeJCS({ ...denial, signature: '' })
}

/**
 * Canonicalize a PaymentInvoice for round-trip equality testing.
 * Invoices are not signed (the rail's settlement proof is the
 * settled-state evidence; the invoice is a payment request). This
 * helper exists so callers can hash an invoice for content-addressed
 * lookup and confirm two invoice objects represent the same request.
 */
export function canonicalizeInvoice(invoice: PaymentInvoice): string {
  return canonicalizeJCS(invoice)
}

/** sha256 hex of an invoice's canonical form. Useful for indexing. */
export function invoiceDigest(invoice: PaymentInvoice): string {
  return sha256Hex(canonicalizeInvoice(invoice))
}
