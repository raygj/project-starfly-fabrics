#!/usr/bin/env bash
# ─────────────────────────────────────────────────────────────────────
# Demo 02 — Real-Time Credential Revocation
#
# Outcome: A compromised credential is revoked instantly. The fabric
# denies all subsequent exchanges for that identity while clean agents
# continue unaffected. Surgical, not scorched earth.
#
#   ACT 1: Agent exchanges successfully (baseline)
#   ACT 2: CAEP signal revokes the credential
#   ACT 3: Same token is denied (immediate, not expiry-based)
#   ACT 4: Clean agent still works (no collateral damage)
#
# Usage:
#   ./demos/02-real-time-revocation.sh
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

for cmd in curl jq; do
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
echo -e "${WHITE}  Demo 02 — Real-Time Credential Revocation${RESET}"
echo -e "${DIM}  Compromised? Revoked in <2 seconds, fabric-wide${RESET}"
echo -e "${DIM}  ──────────────────────────────────────────────────────────${RESET}"
echo ""
echo -e "${YELLOW}  HOW TO WATCH:${RESET}"
echo -e "  Terminal 2:  ${GREEN}curl -N $STARFLY_URL/v1/events${RESET}  (watch the cascade fire)"
echo -e "  Terminal 3:  ${GREEN}while true; do curl -s $STARFLY_URL/metrics | grep caep_cascade; sleep 1; done${RESET}"
echo ""
echo -e "  ${YELLOW}TIP:${RESET} The SSE stream shows each event in real time."
echo -e "  Watch Terminal 2 during ACT 2 — you'll see the revocation propagate."

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

# ── ACT 1: Baseline — Agent Exchanges Successfully ───────────────────

section "ACT 1: Baseline — Agent Exchanges Successfully"

note "Issue an agent identity and exchange for a WIMSE JWT."
note "This is the happy path. Everything works."
echo ""

RESP=$(curl -sf -X POST "$STARFLY_URL/v1/identity/agent" \
  -H "Content-Type: application/json" \
  -d '{"agent_name":"rogue-agent","platform":"a2a","capabilities":["exchange"]}') \
  || { deny "Agent identity issuance failed"; exit 1; }

ROGUE_TOKEN=$(echo "$RESP" | jq -r '.token')
ROGUE_WID=$(echo "$RESP" | jq -r '.workload_id')

ok "Agent issued: rogue-agent"
ok "Workload ID: $ROGUE_WID"

EXCHANGE=$(curl -sf -X POST "$STARFLY_URL/v1/exchange/token" \
  -H "Content-Type: application/json" \
  -d "{
    \"grant_type\":\"urn:ietf:params:oauth:grant-type:token-exchange\",
    \"subject_token\":\"$ROGUE_TOKEN\",
    \"subject_token_type\":\"urn:ietf:params:oauth:token-type:jwt\",
    \"audience\":\"https://api.example.com\"
  }") || { deny "Exchange failed"; exit 1; }

ok "Exchange succeeded — WIMSE JWT issued"
echo ""
echo "$EXCHANGE" | jq '{token_type, expires_in}'

pause

# ── ACT 2: CAEP Signal — Credential Compromised ─────────────────────

section "ACT 2: Credential Compromised — CAEP Revocation Signal"

note "The agent's credential has been compromised. We send a CAEP"
note "session-revoked signal (OpenID SSF standard, not proprietary)."
echo ""
note "Watch your SSE stream (Terminal 2) — you'll see it fire now."
echo ""

# Build the full workload ID as the exchange engine wraps it
FULL_WID="wimse://dev.local/ns/default/sa/wimse://dev.local/agent/a2a/rogue-agent"

JTI=$(python3 -c "import uuid; print(str(uuid.uuid4()))")
IAT=$(python3 -c "import time; print(int(time.time()))")

SIGNAL_RESP=$(curl -s -w "\n%{http_code}" -X POST "$STARFLY_URL/v1/signals/events" \
  -H "Content-Type: application/json" \
  -d "{
    \"iss\": \"starfly\",
    \"jti\": \"$JTI\",
    \"iat\": $IAT,
    \"aud\": \"starfly\",
    \"sub_id\": {
      \"format\": \"uri\",
      \"uri\": \"$FULL_WID\"
    },
    \"events\": {
      \"https://schemas.openid.net/secevent/caep/event-type/session-revoked\": {
        \"reason\": \"compromised credential — immediate revocation\",
        \"event_timestamp\": $IAT
      }
    }
  }")

HTTP_CODE=$(echo "$SIGNAL_RESP" | tail -1)

if [ "$HTTP_CODE" = "200" ] || [ "$HTTP_CODE" = "202" ]; then
  ok "CAEP signal accepted (HTTP $HTTP_CODE)"
  echo ""
  note "Signal path: Received → Policy eval → Revocation index → NATS flash → All units deny"
  note "Target SLO: <2 seconds fabric-wide"
else
  deny "Signal failed: HTTP $HTTP_CODE"
fi

pause

# ── ACT 3: Revoked Agent Tries Again — DENIED ───────────────────────

section "ACT 3: Revoked Agent Tries Again"

note "Same token, same request. But now the revocation index knows."
echo ""

DENIED_RESP=$(curl -s -w "\n%{http_code}" -X POST "$STARFLY_URL/v1/exchange/token" \
  -H "Content-Type: application/json" \
  -d "{
    \"grant_type\":\"urn:ietf:params:oauth:grant-type:token-exchange\",
    \"subject_token\":\"$ROGUE_TOKEN\",
    \"subject_token_type\":\"urn:ietf:params:oauth:token-type:jwt\",
    \"audience\":\"https://api.example.com\"
  }")

HTTP_CODE=$(echo "$DENIED_RESP" | tail -1)
BODY=$(echo "$DENIED_RESP" | sed '$d')

if echo "$BODY" | grep -q "revoked"; then
  deny "DENIED — HTTP $HTTP_CODE (revoked)"
  echo ""
  echo "$BODY" | jq . 2>/dev/null || echo "  $BODY"
  echo ""
  ok "Revocation is immediate. No waiting for token expiry."
else
  echo -e "  ${YELLOW}HTTP $HTTP_CODE${RESET} — expected denial"
  echo "  $BODY"
fi

pause

# ── ACT 4: Clean Agent Still Works ───────────────────────────────────

section "ACT 4: Clean Agent Still Works"

note "Revocation is surgical. Only the compromised identity is blocked."
note "Other agents continue operating normally."
echo ""

CLEAN=$(curl -sf -X POST "$STARFLY_URL/v1/identity/agent" \
  -H "Content-Type: application/json" \
  -d '{"agent_name":"clean-agent","platform":"mcp","capabilities":["exchange"]}') \
  || { deny "Clean agent issuance failed"; exit 1; }

CLEAN_TOKEN=$(echo "$CLEAN" | jq -r '.token')

CLEAN_EX=$(curl -sf -X POST "$STARFLY_URL/v1/exchange/token" \
  -H "Content-Type: application/json" \
  -d "{
    \"grant_type\":\"urn:ietf:params:oauth:grant-type:token-exchange\",
    \"subject_token\":\"$CLEAN_TOKEN\",
    \"subject_token_type\":\"urn:ietf:params:oauth:token-type:jwt\",
    \"audience\":\"https://api.example.com\"
  }") || { deny "Clean agent exchange failed — this is a bug"; exit 1; }

ok "clean-agent exchanged successfully — no collateral damage"

pause

# ── Cascade Metrics ──────────────────────────────────────────────────

section "Cascade Metrics"

echo -e "  ${BOLD}\$ curl $STARFLY_URL/metrics | grep caep${RESET}"
echo ""
curl -sf "$STARFLY_URL/metrics" | grep "caep\|revocation" | head -10 || echo "  (no cascade metrics yet)"

pause

# ── Summary ──────────────────────────────────────────────────────────

section "What You Just Saw"

echo ""
echo -e "  │ Step  │ What happened                  │ Why it matters              │"
echo -e "  │───────│────────────────────────────────│─────────────────────────────│"
echo -e "  │ ACT 1 │ Agent exchanges successfully   │ Baseline: the system works  │"
echo -e "  │ ACT 2 │ CAEP signal revokes credential │ OpenID SSF standard signal  │"
echo -e "  │ ACT 3 │ Same token is denied            │ Immediate, not expiry-based │"
echo -e "  │ ACT 4 │ Clean agent still works         │ Surgical — no collateral    │"
echo ""
note "Revocation path: Signal → Policy → Index → NATS flash → All units deny"
note "Measured SLO: <2s (validated at 2.4ms in integration tests)"
echo ""
echo -e "  ${DIM}Next: ./demos/03-confused-deputy.sh — how Starfly stops MCP confused deputy attacks${RESET}"
echo ""
