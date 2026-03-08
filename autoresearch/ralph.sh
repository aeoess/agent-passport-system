#!/bin/bash
# AEOESS Autoresearch — Ralph Wiggum Edition
# The simplest possible autonomous research loop.
# Usage: ./ralph.sh
#
# This is the "bash loop" version. No frills, no metrics dashboard.
# Just: prompt → agent → test → keep/discard → repeat.

cd ~/agent-passport-system
BRANCH="autoresearch-ralph-$(date +%Y%m%d-%H%M%S)"
git checkout -b "$BRANCH"

# Initialize test file if needed
if [ ! -f tests/autoresearch-adversarial.test.ts ]; then
  cat > tests/autoresearch-adversarial.test.ts << 'EOF'
import { describe, test, expect } from 'vitest';
import { generateKeyPair, sign, verify } from '../src/crypto/keys';
import { createPassport, signPassport } from '../src/core/passport';
import { createDelegation, subDelegate, revokeDelegation, cascadeRevoke, validateChain } from '../src/core/delegation';
import { loadFloor, attestFloor, evaluateCompliance } from '../src/core/values';
import { createActionIntent, evaluateIntent } from '../src/core/policy';

describe('Autoresearch: Adversarial Hardening', () => {
  test('baseline', () => { expect(true).toBe(true); });
});
EOF
  git add -A && git commit -m "autoresearch: init"
fi

ITER=0
while true; do
  ITER=$((ITER + 1))
  echo "═══ Iteration $ITER ═══"
  
  cat autoresearch/program.md | claude --print \
    -p "Iteration $ITER. Read program.md (piped in). Then: 1) Read tests/autoresearch-adversarial.test.ts 2) Add ONE new adversarial test 3) Run npm test 4) Report result per program.md format" \
    2>&1 | tee "autoresearch/logs/iter-${ITER}.log"
  
  # Check if tests pass
  if npm test 2>&1 | tail -5 | grep -q "fail"; then
    echo "  ★ Possible bug or broken test — keeping for review"
    git add -A && git commit -m "autoresearch($ITER): review needed" --allow-empty
  elif git diff --stat | grep -q "autoresearch-adversarial"; then
    echo "  ✓ Kept"
    git add -A && git commit -m "autoresearch($ITER): new adversarial test" --allow-empty
  else
    echo "  ✗ No changes, discarding"
    git checkout -- . 2>/dev/null || true
  fi
  
  sleep 2
done
