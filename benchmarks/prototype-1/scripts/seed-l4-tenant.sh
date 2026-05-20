#!/usr/bin/env bash
# Seed a test tenant + agent + delegation for L4 benchmarking against a
# local @aeoess/gateway. Sourced by run-canonical.sh; can also be sourced
# standalone for ad-hoc L4 runs.
#
# Exports on success:
#   L4_API_KEY     bearer token for the test tenant
#   L4_TENANT_ID   tenant UUID
#   L4_AGENT_ID    agent id (literal string "l4-bench-agent")
#   L4_TENANT_NAME the tenant name (used by cleanup)
#
# Idempotency: if the tenant already exists, the script reuses it and
# rotates the API key. Cleanup is the caller's responsibility (see
# cleanup_l4 in run-canonical.sh).

set -euo pipefail

readonly GATEWAY_URL="${L4_GATEWAY_URL:-http://localhost:3200}"
export L4_TENANT_NAME="${L4_TENANT_NAME:-l4-bench}"
export L4_AGENT_ID="${L4_AGENT_ID:-l4-bench-agent}"
readonly EMAIL="${L4_EMAIL:-l4-bench@local.test}"
readonly SCOPE="${L4_SCOPE:-read:customer}"
readonly DB_PATH="${L4_DB_PATH:-$HOME/aps-canonical-run/aeoess-gateway/gateway.db}"

require_cmd() {
    command -v "$1" >/dev/null 2>&1 || { echo "missing: $1" >&2; exit 1; }
}
require_cmd curl
require_cmd jq
require_cmd sqlite3

# Pre-clean: if a prior run left state, remove it so signup will succeed
# (the gateway rejects email collisions on signup).
if [[ -f "$DB_PATH" ]]; then
    sqlite3 "$DB_PATH" "DELETE FROM tenants WHERE name='$L4_TENANT_NAME' OR email='$EMAIL';" || true
fi

signup_response="$(curl -fsS -X POST "$GATEWAY_URL/api/v1/signup" \
    -H "Content-Type: application/json" \
    -d "{\"name\":\"$L4_TENANT_NAME\",\"email\":\"$EMAIL\"}")"

export L4_TENANT_ID
L4_TENANT_ID="$(echo "$signup_response" | jq -r .tenant_id)"
export L4_API_KEY
L4_API_KEY="$(echo "$signup_response" | jq -r .api_key)"

if [[ -z "$L4_TENANT_ID" ]] || [[ "$L4_TENANT_ID" == "null" ]]; then
    echo "signup failed: $signup_response" >&2
    exit 1
fi

# Upgrade plan to pro so the run doesn't hit the 1000/mo free-plan eval
# cap. Direct DB write is fine here because the tenant is the test
# fixture; the /signup endpoint deliberately only allows plan=free.
sqlite3 "$DB_PATH" "UPDATE tenants SET plan='pro' WHERE id='$L4_TENANT_ID';"

# Register agent. Ed25519 public key is a placeholder; the gateway does
# not verify it during /evaluate, only stores it.
curl -fsS -X POST "$GATEWAY_URL/api/v1/agents" \
    -H "Authorization: Bearer $L4_API_KEY" \
    -H "Content-Type: application/json" \
    -d "{\"agent_id\":\"$L4_AGENT_ID\",\"public_key\":\"ed25519:$(printf '0%.0s' {1..64})\"}" \
    > /dev/null

# Self-delegation with the required scope. No spend_limit so the
# benchmark doesn't exhaust a budget over 1000 iterations.
curl -fsS -X POST "$GATEWAY_URL/api/v1/delegations" \
    -H "Authorization: Bearer $L4_API_KEY" \
    -H "Content-Type: application/json" \
    -d "{\"parent_agent_id\":\"$L4_AGENT_ID\",\"child_agent_id\":\"$L4_AGENT_ID\",\"scope\":\"$SCOPE\"}" \
    > /dev/null

echo "L4 seed OK: tenant=$L4_TENANT_ID agent=$L4_AGENT_ID scope=$SCOPE" >&2
