# CPA v0.1 Mutual Binding

CPA is a pure protocol primitive. It does not own receipt orchestration or
any gateway state. Binding a CPA to the receipts that surround a decision is
done by carrying small reference fields, checked offline by the CPA verifier.

## The two binding directions

The verifier (`verifyCPA`) accepts an optional `CpaReceipt`:

```
interface CpaReceipt {
  action_ref?: string
  cpa_ref?: string
}
```

- **CPA to action.** If `receipt.action_ref` is present, it must match the
  CPA's own `action_ref` via `actionRefsMatch` from `src/core/action-ref.ts`
  (intent-only, untouched). A mismatch is `ACTION_REF_MISMATCH`.
- **Receipt to CPA.** If `receipt.cpa_ref` is present, it must equal
  `computeCpaRef(cpa)` (the content address of the fully signed CPA under
  `SIGN_TAG`). A mismatch is `CPA_REF_MISMATCH`.

Both directions are checked. Absent fields are not checked.

## Carrying `cpa_ref` on a decision or completion receipt

Decision receipts and completion receipts carry the CPA reference as an
optional `cpa_ref` field. Two lean, pure helpers live in the
context-provenance module and pull no receipt-signing or gateway logic into
the primitive:

```
carryCpaRef(cpa)                  -> { cpa_ref }       // one-field object
bindCpaRefToReceipt(receipt, ref) -> { ...receipt, cpa_ref }  // new object
```

`bindCpaRefToReceipt` returns a NEW object and signs nothing. The caller
spreads `cpa_ref` onto the receipt body BEFORE signing it with that
receipt's own machinery, so the field is inside the receipt's signed bytes.
At verification time the consumer hands the receipt's `action_ref` and
`cpa_ref` to `verifyCPA` as a `CpaReceipt`, and the CPA verifier confirms
both binding directions offline.

## Why a module-local helper rather than editing the receipt types

The existing `CompletionReceipt` (`src/core/completion.ts`) signs its whole
body through a different canonicalizer (`canonicalize`, not JCS) and is part
of the permit-execute-complete loop. Folding a `cpa_ref` field and a binder
into that signed-bytes path would pull receipt orchestration into the
primitive and change an unrelated signed shape. The module-local helpers
keep the CPA primitive offline and side-effect free while still giving
decision and completion receipts a documented, verifiable `cpa_ref` field.
