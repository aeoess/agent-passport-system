# Build Spec: Mixed-Scope Steady-Eval Round

## Context
Signet-AI #312 / Nanook PDR collaboration. The current steady-eval runs all 11 MolTrust agents with fixed scope=governance. Nanook needs denial rate variance for the PDR Adaptation axis. Running with varied scopes will produce some permits and some denials across agents.

## What
Modify the steady-eval script to run a mixed-scope round alongside the regular governance round.

## Where
- `~/aeoess-gateway/scripts/steady-eval-mixed.sh` (new script)
- Results exported to `~/aeoess-gateway/exports/mixed-scope-eval-<timestamp>.csv`

## How

The regular steady-eval uses scope=governance for all agents. The mixed-scope round should:

1. For each of the 11 MolTrust agents, cycle through 4 scopes:
   - `governance` (all agents should be permitted)
   - `commerce:checkout` (some agents will be denied — not all have commerce delegation)
   - `admin:delete` (most agents should be denied — high-privilege scope)
   - `data:write` (mixed — depends on agent delegation)

2. Record each evaluation: `agent_id, action_type, scope_required, verdict, duration_ms, timestamp`

3. Export as CSV (the format Nanook requested)

## Script template

```bash
#!/bin/bash
# Mixed-scope steady-eval for PDR Adaptation axis
TIMESTAMP=$(date -u +%Y%m%dT%H%M%SZ)
EXPORT_FILE=~/aeoess-gateway/exports/mixed-scope-eval-${TIMESTAMP}.csv
GATEWAY="https://gateway.aeoess.com"
API_KEY=$(cat ~/aeoess-gateway/.gateway-credentials.md | grep 'API_KEY' | cut -d= -f2 | tr -d ' ')

echo "agent_id,action_type,scope_required,verdict,duration_ms,timestamp" > $EXPORT_FILE

SCOPES=("governance" "commerce:checkout" "admin:delete" "data:write")

for agent_id in $(curl -s -H "Authorization: Bearer $API_KEY" "$GATEWAY/api/v1/agents" | jq -r '.[].agentId'); do
  for scope in "${SCOPES[@]}"; do
    START=$(date +%s%N)
    RESULT=$(curl -s -w "\n%{http_code}" -H "Authorization: Bearer $API_KEY" \
      "$GATEWAY/api/v1/evaluate" \
      -d "{\"agentId\":\"$agent_id\",\"actionType\":\"tool_call\",\"scope\":\"$scope\"}")
    END=$(date +%s%N)
    DURATION=$(( (END - START) / 1000000 ))
    HTTP_CODE=$(echo "$RESULT" | tail -1)
    BODY=$(echo "$RESULT" | head -1)
    VERDICT=$(echo "$BODY" | jq -r '.verdict // "error"')
    echo "$agent_id,tool_call,$scope,$verdict,$DURATION,$(date -u +%Y-%m-%dT%H:%M:%SZ)" >> $EXPORT_FILE
  done
done

echo "Mixed-scope eval complete: $EXPORT_FILE"
echo "Total rows: $(wc -l < $EXPORT_FILE)"
```

Adjust the API endpoint paths to match actual gateway routes. Check `~/aeoess-gateway/scripts/steady-eval.sh` for the correct endpoint format.

## After building
- Run the script once to verify it produces valid CSV
- Email the CSV to Nanook (nanookclaw) or post on Signet-AI #312
- Note in the comment that this is the mixed-scope round for PDR Adaptation axis
