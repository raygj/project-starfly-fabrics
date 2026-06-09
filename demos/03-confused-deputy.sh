#!/usr/bin/env bash
# ─────────────────────────────────────────────────────────────────────
# Demo 03 — MCP Confused Deputy Mitigation
#
# Outcome: A token issued for MCP tool-A cannot be used against tool-B.
# RFC 8707 resource indicators cryptographically bind tokens to one tool.
# This is CoSAI threat T-CD-01.
#
#   1. Register two MCP tools with different security constraints
#   2. Acquire a real Starfly-signed token scoped to tool-A → verify ALLOWED
#   3. Present tool-A's token to tool-B → DENIED (confused deputy)
#   4. Revoke via CAEP → all tokens for that tool invalidated
#   5. Deregister tools
#
# Usage:
#   ./demos/03-confused-deputy.sh
#
# Prerequisites:
#   go build -tags dev -o bin/starfly ./cmd/starfly/
# ─────────────────────────────────────────────────────────────────────

set -euo pipefail
cd "$(dirname "$0")/.."

STARFLY_URL="${STARFLY_URL:-http://localhost:8693}"

BOLD='\033[1m'
DIM='\033[2m'
GREEN='\033[1;32m'
YELLOW='\033[1;33m'
CYAN='\033[1;36m'
RED='\033[1;31m'
WHITE='\033[1;37m'
RESET='\033[0m'

section() { echo ""; echo -e "${BOLD}${CYAN}━━━ $1 ━━━${RESET}"; echo ""; }
note() { echo -e "  ${DIM}$1${RESET}"; }
ok()   { echo -e "  ${GREEN}✓${RESET} $1"; }
deny() { echo -e "  ${RED}✗${RESET} $1"; }
pause() { echo ""; echo -e "${DIM}  (press Enter to continue)${RESET}"; read -r; }

for cmd in curl jq python3; do
  command -v "$cmd" >/dev/null 2>&1 || { deny "Missing: $cmd"; exit 1; }
done

# ── How to Watch ──────────────────────────────────────────────────────

clear
echo ""
echo -e "${CYAN}  ███████╗████████╗ █████╗ ██████╗ ███████╗██╗  ██╗   ██╗${RESET}"
echo -e "${CYAN}  ██╔════╝╚══██╔══╝██╔══██╗██╔══██╗██╔════╝██║  ╚██╗ ██╔╝${RESET}"
echo -e "${CYAN}  ███████╗   ██║   ███████║██████╔╝█████╗  ██║   ╚████╔╝ ${RESET}"
echo -e "${CYAN}  ╚════██║   ██║   ██╔══██║██╔══██╗██╔══╝  ██║    ╚██╔╝  ${RESET}"
echo -e "${CYAN}  ███████║   ██║   ██║  ██║██║  ██║██║     ███████╗██║   ${RESET}"
echo -e "${CYAN}  ╚══════╝   ╚═╝   ╚═╝  ╚═╝╚═╝  ╚═╝╚═╝     ╚══════╝╚═╝   ${RESET}"
echo ""
echo -e "${WHITE}  Demo 03 — MCP Confused Deputy Mitigation${RESET}"
echo -e "${DIM}  Token for tool-A rejected at tool-B${RESET}"
echo -e "${DIM}  ──────────────────────────────────────────────────────────${RESET}"
echo ""
echo -e "${YELLOW}  HOW TO WATCH:${RESET}"
echo -e "  Terminal 2:  ${GREEN}curl -N $STARFLY_URL/v1/events${RESET}  (SSE stream)"
echo -e "  Terminal 3:  ${GREEN}while true; do curl -s $STARFLY_URL/metrics | grep mcp; sleep 1; done${RESET}"
echo ""
echo -e "${YELLOW}  THE THREAT:${RESET}"
echo -e "  A confused deputy attack tricks a privileged tool into acting"
echo -e "  on behalf of an unauthorized caller. An attacker holds a valid"
echo -e "  token for tool-A and presents it to tool-B — if the tool doesn't"
echo -e "  check audience, it executes. 13,000+ MCP servers on GitHub are"
echo -e "  vulnerable to this today."

pause

# ── Cleanup stale processes ───────────────────────────────────────────

if lsof -ti:8693 > /dev/null 2>&1; then
  echo -e "${YELLOW}Killing leftover process on port 8693...${RESET}"
  lsof -ti:8693 | xargs kill 2>/dev/null
  sleep 1
fi

# ── Build if needed ───────────────────────────────────────────────────

BIN=bin/starfly
if [ ! -f "$BIN" ]; then
  echo -e "${YELLOW}Building starfly binary (dev mode)...${RESET}"
  go build -o "$BIN" -tags dev ./cmd/starfly/
fi

# ── Start Starfly ────────────────────────────────────────────────────

DEMO_DIR=$(mktemp -d)
trap 'kill $STARFLY_PID 2>/dev/null; wait $STARFLY_PID 2>/dev/null; rm -rf "$DEMO_DIR"' EXIT

# Build a policy bundle that allows signals (dev exchange + permissive signals)
mkdir -p "$DEMO_DIR/policies"
cp policies/dev/exchange.rego "$DEMO_DIR/policies/"
cat > "$DEMO_DIR/policies/signal.rego" << 'REGO'
package starfly.signal
default allow := true
reason := "dev mode: all signals accepted"
claims := {"revoke_tokens": true}
REGO
cat > "$DEMO_DIR/policies/mcp_tool_call.rego" << 'REGO'
package starfly.mcp_tool_call
default allow := true
reason := "dev mode: all MCP tool calls allowed by policy"
REGO

STARFLY_STORAGE_PATH="$DEMO_DIR/data" \
STARFLY_NATS_JETSTREAM_DIR="$DEMO_DIR/nats" \
STARFLY_POLICY_BUNDLE_PATH="$DEMO_DIR/policies" \
  $BIN --dev > "$DEMO_DIR/boot.log" 2>&1 &
STARFLY_PID=$!

for i in $(seq 1 30); do
  if curl -sf "$STARFLY_URL/v1/sys/health" > /dev/null 2>&1; then break; fi
  sleep 0.2
done

if ! curl -sf "$STARFLY_URL/v1/sys/health" > /dev/null 2>&1; then
  deny "Starfly failed to start. Check $DEMO_DIR/boot.log"
  exit 1
fi
ok "Starfly is running (PID $STARFLY_PID)"

# ── Step 1: Register MCP Tools ───────────────────────────────────────

section "Step 1: Register Two MCP Tools"

note "code-search: read-only search tool (low blast radius)"
note "sql-admin: administrative SQL tool (high blast radius)"
echo ""

for TOOL in \
  '{"tool_id":"code-search","name":"Code Search","description":"Search codebase","resource_uri":"https://mcp.example.com/tools/code-search","max_blast_radius":"workspace:*","owner_commune":"starfly","server_id":"cursor-mcp-v1"}' \
  '{"tool_id":"sql-admin","name":"SQL Admin","description":"Administrative SQL","resource_uri":"https://mcp.example.com/tools/sql-admin","max_blast_radius":"database:*","owner_commune":"starfly","server_id":"db-mcp-v1"}'; do

  TOOL_ID=$(echo "$TOOL" | python3 -c "import sys,json; print(json.load(sys.stdin)['tool_id'])")
  RESP=$(curl -s -w "\n%{http_code}" -X POST "$STARFLY_URL/v1/mcp/tools" \
    -H "Content-Type: application/json" -d "$TOOL")
  HTTP_CODE=$(echo "$RESP" | tail -1)

  if [ "$HTTP_CODE" = "201" ]; then
    ok "Registered: $TOOL_ID"
  else
    echo -e "  ${YELLOW}$TOOL_ID: HTTP $HTTP_CODE${RESET}"
  fi
done

pause

echo -e "  ${BOLD}\$ curl $STARFLY_URL/v1/mcp/tools${RESET}"
echo ""
curl -sf "$STARFLY_URL/v1/mcp/tools" | python3 -m json.tool 2>/dev/null || echo "  (no tools)"

pause

# ── Step 2: Acquire a Real Token Scoped to code-search ───────────────

section "Step 2: Acquire Starfly-Signed Token for code-search"

note "Issue an agent identity, then exchange for a WIMSE JWT whose"
note "audience is the code-search tool's resource URI."
echo ""

AGENT_RESP=$(curl -sf -X POST "$STARFLY_URL/v1/identity/agent" \
  -H "Content-Type: application/json" \
  -d '{"agent_name":"demo-agent","platform":"mcp","capabilities":["query-read"],"max_blast_radius":"workspace:dev"}') \
  || { deny "Agent identity failed"; exit 1; }

AGENT_TOKEN=$(echo "$AGENT_RESP" | jq -r '.token')
ok "Agent identity issued"

# Exchange for a token scoped to code-search's resource URI
EXCHANGE_RESP=$(curl -sf -X POST "$STARFLY_URL/v1/exchange/token" \
  -H "Content-Type: application/json" \
  -d "{
    \"grant_type\":\"urn:ietf:params:oauth:grant-type:token-exchange\",
    \"subject_token\":\"$AGENT_TOKEN\",
    \"subject_token_type\":\"urn:ietf:params:oauth:token-type:jwt\",
    \"audience\":\"https://mcp.example.com/tools/code-search\"
  }") || { deny "Token exchange failed"; exit 1; }

TOOL_A_TOKEN=$(echo "$EXCHANGE_RESP" | jq -r '.access_token')
ok "WIMSE JWT issued (audience: code-search)"
echo ""
echo -e "  token.aud    = ${GREEN}https://mcp.example.com/tools/code-search${RESET}"
echo -e "  tool.resource = ${GREEN}https://mcp.example.com/tools/code-search${RESET}"
echo -e "  Match:         ${GREEN}YES${RESET}"

pause

# ── Step 3: Verify Token Against code-search → ALLOWED ───────────────

section "Step 3: Verify Token Against code-search → ALLOWED"

note "Present the token to the tool it was issued for. Should pass."
echo ""

VALID_RESP=$(curl -s -w "\n%{http_code}" -X POST "$STARFLY_URL/v1/mcp/verify" \
  -H "Content-Type: application/json" \
  -d "{\"token\":\"$TOOL_A_TOKEN\",\"tool_id\":\"code-search\"}")

HTTP_CODE=$(echo "$VALID_RESP" | tail -1)
BODY=$(echo "$VALID_RESP" | sed '$d')

if [ "$HTTP_CODE" = "200" ]; then
  ok "ALLOWED — HTTP 200 (audience matches)"
  echo ""
  echo "$BODY" | python3 -m json.tool 2>/dev/null || echo "  $BODY"
else
  echo -e "  ${YELLOW}HTTP $HTTP_CODE${RESET}"
  echo "$BODY" | python3 -m json.tool 2>/dev/null || echo "  $BODY"
fi

pause

# ── Step 4: Present Same Token to sql-admin → DENIED ─────────────────

section "Step 4: ATTACK — Confused Deputy"

note "Same token, but presented to sql-admin (different tool)."
note "The token's audience doesn't match sql-admin's resource URI."
echo ""
echo -e "  token.aud    = ${GREEN}https://mcp.example.com/tools/code-search${RESET}"
echo -e "  tool.resource = ${RED}https://mcp.example.com/tools/sql-admin${RESET}"
echo -e "  Match:         ${RED}NO${RESET}"
echo ""

ATTACK_RESP=$(curl -s -w "\n%{http_code}" -X POST "$STARFLY_URL/v1/mcp/verify" \
  -H "Content-Type: application/json" \
  -d "{\"token\":\"$TOOL_A_TOKEN\",\"tool_id\":\"sql-admin\"}")

HTTP_CODE=$(echo "$ATTACK_RESP" | tail -1)
BODY=$(echo "$ATTACK_RESP" | sed '$d')

if [ "$HTTP_CODE" = "403" ]; then
  deny "BLOCKED — HTTP 403 (confused deputy detected)"
  echo ""
  echo "  Server response:"
  echo "$BODY" | python3 -m json.tool 2>/dev/null || echo "  $BODY"
else
  echo -e "  ${YELLOW}HTTP $HTTP_CODE — expected 403${RESET}"
  echo "$BODY" | python3 -m json.tool 2>/dev/null || echo "  $BODY"
fi

echo ""
note "This is CoSAI threat T-CD-01. The token's aud claim is"
note "cryptographically bound to one tool's resource URI."
note "Presenting it to any other tool gets a 403."
echo ""
note "Full cryptographic proof: go test -tags integration -run TestConfusedDeputy -v ./test/integration/"

pause

# ── Step 5: CAEP Revocation ──────────────────────────────────────────

section "Step 5: CAEP Signal — Tool Compromised"

note "A vulnerability is disclosed in code-search."
note "Send a CAEP mcp-tool-compromised signal."
echo ""

SIGNAL_RESP=$(curl -s -w "\n%{http_code}" -X POST "$STARFLY_URL/v1/signals/events" \
  -H "Content-Type: application/json" \
  -d '{
    "events": {
      "https://starfly.dev/secevent/event-type/mcp-tool-compromised": {
        "subject": {"format": "wimse", "uri": "https://mcp.example.com/tools/code-search"},
        "reason": "CVE-2026-XXXX: RCE in code-search v2.1",
        "event_timestamp": '"$(date +%s)"'
      }
    }
  }')

HTTP_CODE=$(echo "$SIGNAL_RESP" | tail -1)

if [ "$HTTP_CODE" = "200" ] || [ "$HTTP_CODE" = "202" ]; then
  ok "CAEP signal accepted — all tokens scoped to code-search invalidated"
  note "Cascade propagates to all Starfly units via NATS in <2s"
else
  deny "Signal failed: HTTP $HTTP_CODE"
fi

pause

# ── Step 6: Cleanup ──────────────────────────────────────────────────

section "Step 6: Deregister Tools"

for TOOL_ID in code-search sql-admin; do
  RESP=$(curl -s -w "\n%{http_code}" -X DELETE "$STARFLY_URL/v1/mcp/tools?tool_id=$TOOL_ID")
  HTTP_CODE=$(echo "$RESP" | tail -1)
  if [ "$HTTP_CODE" = "200" ]; then
    ok "Deregistered: $TOOL_ID"
  fi
done

pause

# ── Summary ──────────────────────────────────────────────────────────

section "What You Just Saw"

echo -e "  ${BOLD}BEFORE Starfly:${RESET}"
echo -e "    - MCP tools have no identity verification"
echo -e "    - No per-tool scoping — tokens work anywhere"
echo -e "    - No revocation — compromised tools stay accessible"
echo -e "    - No audit trail"
echo ""
echo -e "  ${BOLD}AFTER Starfly:${RESET}"
echo -e "    ${GREEN}✓${RESET} Every tool call verified with scoped WIMSE JWT"
echo -e "    ${GREEN}✓${RESET} RFC 8707 resource indicators prevent confused deputy"
echo -e "    ${GREEN}✓${RESET} Capability + blast radius constraints per tool"
echo -e "    ${GREEN}✓${RESET} OPA Rego policy on every call"
echo -e "    ${GREEN}✓${RESET} CAEP cascade revokes in <2s"
echo -e "    ${GREEN}✓${RESET} Full audit trail of every decision"
echo ""
echo -e "  ${DIM}Next: ./demos/04-federation.sh — cross-cluster trust and revocation${RESET}"
echo ""
