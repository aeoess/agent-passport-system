// Copyright 2024-2026 Tymofii Pidlisnyi. Apache-2.0 license. See LICENSE.
// Attribution Consent — cited-principal consent signing

import { sign, verify } from '../../crypto/keys.js'
import { receiptCore } from './create.js'
import type { AttributionReceipt } from './types.js'

/** Add the cited principal's consent signature. The private key must match
 *  cited_principal_public_key on the receipt or this throws. Does not
 *  mutate the input receipt. */
export function signAttributionConsent(
  receipt: AttributionReceipt,
  cited_principal_private_key: string,
): AttributionReceipt {
  const core = receiptCore(receipt)
  const cited_principal_signature = sign(core, cited_principal_private_key)

  if (!verify(core, cited_principal_signature, receipt.cited_principal_public_key)) {
    throw new Error(
      'signAttributionConsent: consent signature does not verify against cited_principal_public_key — wrong private key?',
    )
  }

  return { ...receipt, cited_principal_signature }
}
