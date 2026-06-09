#!/usr/bin/env bash
set -euo pipefail
SCRIPT_DIR="$(cd "$(dirname "$0")/.." && pwd)"
# shellcheck source=../lib/common.sh
source "${SCRIPT_DIR}/lib/common.sh"
require_cmds curl jq
load_profile

log_step "Use case 5 — Observability"

health=$(curl -sf "${STARFLY_URL}/v1/sys/health")
log_ok "health $(echo "$health" | jq -c '{initialized,locked,version,unit_id}')"

kid=$(curl -sf "${STARFLY_URL}/v1/identity/jwks" | jq -r '.keys[0].kid // "none"')
log_ok "jwks kid: $kid"

metric_count=$(curl -sf "${STARFLY_URL}/metrics" | grep -c '^starfly_' || true)
log_ok "prometheus: ${metric_count} starfly_* metric lines"

# Touch exchange so counters move, then sample exchange metrics
exchange_stub "https://observability.example.com" "observe-agent" >/dev/null
sample=$(curl -sf "${STARFLY_URL}/metrics" | grep 'starfly_exchange_requests_total' | head -3 || true)
if [ -n "$sample" ]; then
  log_ok "exchange counters updating"
  log_note "$sample"
fi

# SSE smoke — read one event line if any (timeout 3s)
if curl -sfN --max-time 3 "${STARFLY_URL}/v1/events" 2>/dev/null | head -1 | grep -q .; then
  log_ok "SSE /v1/events stream open"
else
  log_note "SSE stream quiet (run more exchanges or open dashboard for live feed)"
fi

log_note "screenshot: docs/screenshots/soul.png"
