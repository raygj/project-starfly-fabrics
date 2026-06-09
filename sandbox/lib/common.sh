#!/usr/bin/env bash
# Shared helpers for Starfly sandbox use cases.

set -euo pipefail

SANDBOX_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

GREEN='\033[1;32m'
YELLOW='\033[1;33m'
CYAN='\033[1;36m'
RED='\033[1;31m'
DIM='\033[2m'
RESET='\033[0m'

log_step() { echo -e "\n${CYAN}==> $1${RESET}"; }
log_ok()   { echo -e "  ${GREEN}ok${RESET}  $1"; }
log_warn() { echo -e "  ${YELLOW}warn${RESET}  $1"; }
log_fail() { echo -e "  ${RED}fail${RESET}  $1"; }
log_note() { echo -e "  ${DIM}$1${RESET}"; }

require_cmds() {
  for cmd in "$@"; do
    command -v "$cmd" >/dev/null 2>&1 || { log_fail "missing command: $cmd"; exit 1; }
  done
}

load_profile() {
  STARFLY_PROFILE="${STARFLY_PROFILE:-local}"
  case "$STARFLY_PROFILE" in
    local)
      STARFLY_URL="${STARFLY_URL:-http://localhost:8693}"
      STARFLY_ALPHA_URL="${STARFLY_ALPHA_URL:-}"
      ;;
    lab)
      STARFLY_URL="${STARFLY_URL:-http://192.168.1.98:30095}"
      STARFLY_ALPHA_URL="${STARFLY_ALPHA_URL:-http://192.168.1.98:31104}"
      ;;
    personal)
      STARFLY_URL="${STARFLY_URL:?set STARFLY_URL for personal profile}"
      ;;
    *)
      log_fail "unknown STARFLY_PROFILE: $STARFLY_PROFILE (use local, lab, or personal)"
      exit 1
      ;;
  esac
  export STARFLY_URL STARFLY_PROFILE STARFLY_ALPHA_URL
}

check_health() {
  local health
  health=$(curl -sf "${STARFLY_URL}/v1/sys/health" 2>/dev/null) || {
    log_fail "cannot reach ${STARFLY_URL}/v1/sys/health"
    log_note "bootstrap: see sandbox/manifest.yaml and run ./sandbox/init.sh"
    exit 1
  }
  log_ok "health $(echo "$health" | jq -c '{initialized,locked,version,unit_id}')"
}

jwt_payload() {
  local token="$1"
  echo "$token" | cut -d. -f2 | tr '_-' '/+' | awk '{while (length % 4) $0 = $0 "="; print}' | base64 -d 2>/dev/null
}

# Dev-mode stub subject token (accepted when Starfly runs with dev policy).
stub_subject_token() {
  local sub="${1:-sandbox-agent}"
  local payload b64
  payload=$(jq -nc --arg s "$sub" '{sub:$s,iss:"dev",exp:9999999999}')
  b64=$(printf '%s' "$payload" | base64 | tr '+/' '-_' | tr -d '=')
  echo "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.${b64}.stub"
}

exchange_stub() {
  local audience="$1"
  local subject="${2:-sandbox-agent}"
  local stub
  stub=$(stub_subject_token "$subject")
  curl -sf -X POST "${STARFLY_URL}/v1/exchange/token" \
    -H "Content-Type: application/json" \
    -d "{
      \"grant_type\": \"urn:ietf:params:oauth:grant-type:token-exchange\",
      \"subject_token\": \"${stub}\",
      \"subject_token_type\": \"urn:ietf:params:oauth:token-type:jwt\",
      \"audience\": \"${audience}\"
    }"
}
