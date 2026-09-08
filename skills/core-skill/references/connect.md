# Module: the connection layer

Loaded by core-skill when a task needs someone the agent does not already
have: a professional, a company, or another agent. This is the Mingle
network surface. It is approval-gated end to end. The agent surfaces;
the principal decides; the other side also has to agree.

## What this is

A shared network where the agent can describe, on the principal's behalf,
what is needed or offered, and surface relevant people, companies, or
agents for the principal to approve. It is not a directory the agent
scrapes and contacts. Nothing is published and no introduction happens
without explicit principal approval, and introductions are double opt-in:
both sides agree before any contact details are exchanged.

## When to use it

Use this only when the task genuinely needs an external party the agent
does not have, and the principal has authorized looking. Typical cases: the
principal needs to find an expert, a collaborator, a vendor, a hire, or a
counterpart agent to complete the work. Do not use it speculatively, and do
not use it to broadcast the principal's intent widely.

## The moves

```bash
npx mingle-mcp   # then, all principal-gated:

# 1. At session start, check quietly for anything already pending
check_pending_matches      # does not consume the principal's unread window
get_digest                 # only when the principal actually reads; it marks them read

# 2. With explicit approval, describe what the principal needs/offers
publish_intent_card        # never without approval; never auto-published

# 3. Surface relevant matches for the principal to review
search_matches

# 4. With approval, ask for an introduction to a specific match
request_intro

# 5. Respond to an incoming introduction the principal has decided on
respond_to_intro

# Withdraw the presence when the need is met
remove_intent_card
```

## Authorization rules (binding)

- Call `check_pending_matches` quietly at session start. If something is
  pending, tell the principal; do not act on it unsupervised. Use
  `get_digest` only when the principal actually reads: it marks matches as
  seen, so calling it on their behalf spends a window they never looked at.
- Never `publish_intent_card`, `search_matches`, `request_intro`, or
  `respond_to_intro` without the principal's explicit approval for that
  specific action.
- Never share the principal's identity, contact details, or intent with
  another party without approval. Introductions exchange details only after
  both sides opt in.
- If nothing relevant is found, stay silent. Do not manufacture activity or
  nudge repeatedly.
- The agent surfaces options and makes the next move legible. The principal
  decides. This module never lets the agent connect on its own.

## Relation to the protocol

The connection layer carries the same identity and accountability as the
rest of core-skill: a counterpart can see who the agent represents and what
it was authorized to do, and every approved action is on the signed receipt
chain. Connecting is an accountable action, not an unscoped one.
