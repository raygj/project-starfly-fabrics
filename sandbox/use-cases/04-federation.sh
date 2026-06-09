#!/usr/bin/env bash
set -euo pipefail
SCRIPT_DIR="$(cd "$(dirname "$0")/.." && pwd)"
# shellcheck source=../lib/common.sh
source "${SCRIPT_DIR}/lib/common.sh"
require_cmds curl jq
load_profile

log_step "Use case 4 — Federation sync"

hash_local=$(curl -sf "${STARFLY_URL}/v1/federation/revocation-hash")
log_ok "local hash $(echo "$hash_local" | jq -c '{hash,count,timestamp}')"

lag=$(curl -sf "${STARFLY_URL}/metrics" | grep 'starfly_federation_revocation_lag_seconds' | head -1 || true)
if [ -n "$lag" ]; then
  log_ok "peer lag metric present"
  log_note "$lag"
else
  log_warn "no federation lag metrics (single fabric or peers not configured)"
fi

if [ -n "${STARFLY_ALPHA_URL:-}" ]; then
  hash_alpha=$(curl -sf "${STARFLY_ALPHA_URL}/v1/federation/revocation-hash" 2>/dev/null || true)
  if [ -n "$hash_alpha" ]; then
    log_ok "alpha peer hash $(echo "$hash_alpha" | jq -c '{hash,count}')"
    log_note "sandbox peers to alpha for cross-fabric revocation sync"
  else
    log_warn "could not reach alpha at ${STARFLY_ALPHA_URL}"
  fi
fi

log_note "screenshot: docs/screenshots/federation.png"
