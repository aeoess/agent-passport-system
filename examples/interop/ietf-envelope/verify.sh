#!/bin/bash
# Verify IETF draft envelope receipts — chain integrity and structure
# Usage: bash verify.sh
#
# These receipts follow draft-farley-acta-signed-receipts-01.
# Each receipt is Ed25519-signed over the JCS-canonicalized (RFC 8785) payload.
# Chain verification: each receipt's previousReceiptHash matches the prior receipt_id.
#
# For full cryptographic verification (Ed25519 + JCS), use the SDK:
#   npx tsx examples/interop/ietf-envelope/generate-receipts.ts

set -euo pipefail

DIR="$(cd "$(dirname "$0")" && pwd)"
PUBKEY=$(cat "$DIR/gateway-pubkey.txt" | tr -d '[:space:]')

echo "Gateway public key: ${PUBKEY:0:16}..."
echo "Spec: draft-farley-acta-signed-receipts-01"
echo ""

PASS=0
FAIL=0

# ── Structure checks ──

for receipt in "$DIR"/receipt-*.json; do
  NAME=$(basename "$receipt")
  SPEC=$(jq -r '.spec' "$receipt")
  RECEIPT_ID=$(jq -r '.receipt_id' "$receipt")
  ISSUER=$(jq -r '.issuer_id' "$receipt")
  ALG=$(jq -r '.signature.alg' "$receipt")
  SIG=$(jq -r '.signature.sig' "$receipt")
  PREV=$(jq -r '.previousReceiptHash // "null"' "$receipt")

  ERRORS=""

  # Check spec field
  [ "$SPEC" = "draft-farley-acta-signed-receipts-01" ] || ERRORS="${ERRORS}spec mismatch; "

  # Check receipt_id format
  [[ "$RECEIPT_ID" == sha256:* ]] || ERRORS="${ERRORS}receipt_id not sha256-prefixed; "

  # Check issuer is a DID
  [[ "$ISSUER" == did:* ]] || ERRORS="${ERRORS}issuer_id not a DID; "

  # Check EdDSA algorithm
  [ "$ALG" = "EdDSA" ] || ERRORS="${ERRORS}algorithm not EdDSA; "

  # Check signature present and 128 hex chars (Ed25519 = 64 bytes)
  [ "${#SIG}" -eq 128 ] || ERRORS="${ERRORS}signature wrong length (${#SIG}); "

  # Check payload has required fields
  jq -e '.payload.agentId' "$receipt" > /dev/null 2>&1 || ERRORS="${ERRORS}missing payload.agentId; "
  jq -e '.payload.delegationId' "$receipt" > /dev/null 2>&1 || ERRORS="${ERRORS}missing payload.delegationId; "
  jq -e '.payload.action' "$receipt" > /dev/null 2>&1 || ERRORS="${ERRORS}missing payload.action; "
  jq -e '.payload.extensions.aps' "$receipt" > /dev/null 2>&1 || ERRORS="${ERRORS}missing APS extensions; "

  if [ -z "$ERRORS" ]; then
    echo "  PASS  $NAME"
    echo "        receipt_id: ${RECEIPT_ID:0:30}..."
    echo "        chain: $PREV"
    PASS=$((PASS + 1))
  else
    echo "  FAIL  $NAME: $ERRORS"
    FAIL=$((FAIL + 1))
  fi
done

echo ""

# ── Chain integrity ──

echo "Chain integrity check:"
R1_ID=$(jq -r '.receipt_id' "$DIR/receipt-permit.json")
R2_PREV=$(jq -r '.previousReceiptHash' "$DIR/receipt-deny.json")
R2_ID=$(jq -r '.receipt_id' "$DIR/receipt-deny.json")
R3_PREV=$(jq -r '.previousReceiptHash' "$DIR/receipt-commerce.json")

if [ "$R2_PREV" = "$R1_ID" ] && [ "$R3_PREV" = "$R2_ID" ]; then
  echo "  PASS  receipt-permit -> receipt-deny -> receipt-commerce (chain valid)"
  PASS=$((PASS + 1))
else
  echo "  FAIL  Chain broken"
  echo "    receipt-deny.previousReceiptHash:    $R2_PREV"
  echo "    receipt-permit.receipt_id:           $R1_ID"
  echo "    receipt-commerce.previousReceiptHash: $R3_PREV"
  echo "    receipt-deny.receipt_id:             $R2_ID"
  FAIL=$((FAIL + 1))
fi

echo ""
echo "Results: $PASS passed, $FAIL failed"
[ "$FAIL" -eq 0 ] || exit 1
