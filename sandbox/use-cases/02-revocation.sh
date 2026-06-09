#!/usr/bin/env bash
set -euo pipefail
SCRIPT_DIR="$(cd "$(dirname "$0")/.." && pwd)"
# shellcheck source=../lib/common.sh
source "${SCRIPT_DIR}/lib/common.sh"
require_cmds curl jq
load_profile

log_step "Use case 2 — Real-time revocation"

agent="revoke-$(date +%s)-$$"

# Baseline exchange
resp=$(exchange_stub "https://api.example.com" "$agent")
sub=$(jwt_payload "$(echo "$resp" | jq -r '.access_token')" | jq -r .sub)
log_ok "baseline exchange for $sub"

# CAEP session-revoked
jti=$(uuidgen 2>/dev/null || cat /proc/sys/kernel/random/uuid)
iat=$(date +%s)
signal_code=$(curl -s -o /tmp/starfly-signal.json -w "%{http_code}" -X POST "${STARFLY_URL}/v1/signals/events" \
  -H "Content-Type: application/json" \
  -d "{
    \"iss\": \"starfly\",
    \"jti\": \"${jti}\",
    \"iat\": ${iat},
    \"aud\": \"starfly\",
    \"sub_id\": {\"format\": \"uri\", \"uri\": \"${sub}\"},
    \"events\": {
      \"https://schemas.openid.net/secevent/caep/event-type/session-revoked\": {
        \"reason\": \"sandbox compromised credential drill\",
        \"event_timestamp\": ${iat}
      }
    }
  }")

[[ "$signal_code" == "200" || "$signal_code" == "202" ]] \
  || { log_fail "CAEP signal HTTP $signal_code"; cat /tmp/starfly-signal.json; exit 1; }
log_ok "CAEP signal accepted (HTTP $signal_code)"

# Same subject should be denied
deny_code=$(curl -s -o /tmp/starfly-deny.json -w "%{http_code}" -X POST "${STARFLY_URL}/v1/exchange/token" \
  -H "Content-Type: application/json" \
  -d "{
    \"grant_type\": \"urn:ietf:params:oauth:grant-type:token-exchange\",
    \"subject_token\": \"$(stub_subject_token "$agent")\",
    \"subject_token_type\": \"urn:ietf:params:oauth:token-type:jwt\",
    \"audience\": \"https://api.example.com\"
  }")

if grep -qi revoked /tmp/starfly-deny.json 2>/dev/null || [ "$deny_code" != "200" ]; then
  log_ok "revoked identity denied (HTTP $deny_code)"
else
  log_fail "expected denial after revocation, got HTTP $deny_code"
  cat /tmp/starfly-deny.json
  exit 1
fi

log_note "screenshot: docs/screenshots/federation.png"
