#!/usr/bin/env bash
set -euo pipefail
SCRIPT_DIR="$(cd "$(dirname "$0")/.." && pwd)"
# shellcheck source=../lib/common.sh
source "${SCRIPT_DIR}/lib/common.sh"
require_cmds curl jq
load_profile

log_step "Use case 1 — Token exchange"

resp=$(exchange_stub "https://api.example.com" "sandbox-agent")
token=$(echo "$resp" | jq -r '.access_token')
[ -n "$token" ] && [ "$token" != "null" ] || { log_fail "no access_token in response"; exit 1; }

claims=$(jwt_payload "$token" | jq -c '{sub,iss,aud,td,exp}')
log_ok "WIMSE JWT issued"
log_note "claims: $claims"
log_note "screenshot: docs/screenshots/fabric-pulse.png"
