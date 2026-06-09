#!/usr/bin/env bash
set -euo pipefail
SCRIPT_DIR="$(cd "$(dirname "$0")/.." && pwd)"
# shellcheck source=../lib/common.sh
source "${SCRIPT_DIR}/lib/common.sh"
require_cmds curl jq
load_profile

log_step "Use case 3 — MCP confused deputy"

register_tool() {
  local json="$1"
  local code
  code=$(curl -s -o /dev/null -w "%{http_code}" -X POST "${STARFLY_URL}/v1/mcp/tools" \
    -H "Content-Type: application/json" -d "$json")
  [[ "$code" == "201" || "$code" == "409" ]] || log_warn "register HTTP $code (may already exist)"
}

register_tool '{"tool_id":"code-search","name":"Code Search","resource_uri":"https://mcp.example.com/tools/code-search","server_id":"sandbox"}'
register_tool '{"tool_id":"sql-admin","name":"SQL Admin","resource_uri":"https://mcp.example.com/tools/sql-admin","server_id":"sandbox"}'
log_ok "tools registered (code-search, sql-admin)"

resp=$(exchange_stub "https://mcp.example.com/tools/code-search" "demo-agent")
token=$(echo "$resp" | jq -r '.access_token')

allow_code=$(curl -s -o /tmp/starfly-mcp-allow.json -w "%{http_code}" -X POST "${STARFLY_URL}/v1/mcp/verify" \
  -H "Content-Type: application/json" \
  -d "{\"token\":\"${token}\",\"tool_id\":\"code-search\"}")
[ "$allow_code" = "200" ] || { log_fail "expected allow on code-search, got $allow_code"; exit 1; }
log_ok "token allowed for code-search (HTTP 200)"

deny_code=$(curl -s -o /tmp/starfly-mcp-deny.json -w "%{http_code}" -X POST "${STARFLY_URL}/v1/mcp/verify" \
  -H "Content-Type: application/json" \
  -d "{\"token\":\"${token}\",\"tool_id\":\"sql-admin\"}")
[ "$deny_code" = "403" ] || { log_fail "expected 403 on sql-admin, got $deny_code"; exit 1; }
log_ok "confused deputy blocked for sql-admin (HTTP 403)"
log_note "$(jq -r '.error_description // .claims.sub' /tmp/starfly-mcp-deny.json 2>/dev/null || true)"
log_note "screenshot: docs/screenshots/mcp-security.png"
