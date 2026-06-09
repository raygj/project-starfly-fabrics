#!/usr/bin/env bash
# ─────────────────────────────────────────────────────────────────────
# Demo 01 — Multi-Identity Token Exchange
#
# Outcome: Any workload identity (K8s SA, SPIFFE, OIDC, agent) can
# exchange its native credential for a scoped WIMSE JWT via RFC 8693.
#
#   1. Issue an agent identity (simulates K8s SA → agent bootstrap)
#   2. Exchange agent token → scoped WIMSE JWT
#   3. Decode the JWT claims — see what Starfly produces
#   4. Show the exchange in metrics
#
# Usage:
#   ./demos/01-token-exchange.sh
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
fail() { echo -e "  ${RED}✗${RESET} $1"; }
pause() { echo ""; echo -e "${DIM}  (press Enter to continue)${RESET}"; read -r; }

for cmd in curl jq; do
  command -v "$cmd" >/dev/null 2>&1 || { fail "Missing: $cmd"; exit 1; }
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
echo -e "${WHITE}  Demo 01 — Multi-Identity Token Exchange${RESET}"
echo -e "${DIM}  Any credential in, scoped WIMSE JWT out${RESET}"
echo -e "${DIM}  ──────────────────────────────────────────────────────────${RESET}"
echo ""
echo -e "${YELLOW}  HOW TO WATCH:${RESET}"
echo -e "  Terminal 2:  ${GREEN}curl -N $STARFLY_URL/v1/events${RESET}  (SSE stream)"
echo -e "  Terminal 3:  ${GREEN}while true; do curl -s $STARFLY_URL/metrics | grep exchange; sleep 1; done${RESET}"

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
  fail "Starfly failed to start. Check $DEMO_DIR/boot.log"
  exit 1
fi
ok "Starfly is running at $STARFLY_URL (PID $STARFLY_PID)"

# ── Step 1: Issue Agent Identity ─────────────────────────────────────

section "Step 1: Issue Agent Identity"

note "In production, an agent's first credential comes from its platform:"
note "K8s ServiceAccount, SPIFFE SVID, AWS IMDS, etc."
note ""
note "In dev mode, we issue an agent identity directly. This simulates"
note "the bootstrap that happens when an agent sidecar starts."
echo ""

echo -e "  ${BOLD}\$ curl -X POST $STARFLY_URL/v1/identity/agent${RESET}"
echo -e "  ${BOLD}  -d '{\"agent_name\":\"data-pipeline\",\"platform\":\"mcp\",...}'${RESET}"
echo ""

ISSUE_RESP=$(curl -sf -X POST "$STARFLY_URL/v1/identity/agent" \
  -H "Content-Type: application/json" \
  -d '{
    "agent_name": "data-pipeline",
    "platform": "mcp",
    "capabilities": ["query-read", "schema-read", "tool-execute"],
    "max_blast_radius": "namespace:analytics"
  }') || { fail "POST /v1/identity/agent failed"; exit 1; }

AGENT_TOKEN=$(echo "$ISSUE_RESP" | jq -r '.token')
WORKLOAD_ID=$(echo "$ISSUE_RESP" | jq -r '.workload_id')

ok "Workload ID: $WORKLOAD_ID"
ok "Agent token issued (${#AGENT_TOKEN} chars)"
echo ""
note "This token represents the agent's identity — it's not yet scoped"
note "to a specific audience or trust domain."

pause

# ── Step 2: Exchange for Scoped WIMSE JWT ────────────────────────────

section "Step 2: Exchange Agent Token → Scoped WIMSE JWT"

note "RFC 8693 token exchange: trade an unscoped agent token for a"
note "WIMSE JWT that's audience-bound and time-limited."
echo ""

echo -e "  ${BOLD}\$ curl -X POST $STARFLY_URL/v1/exchange/token${RESET}"
echo -e "  ${BOLD}  grant_type: urn:ietf:params:oauth:grant-type:token-exchange${RESET}"
echo -e "  ${BOLD}  subject_token_type: urn:ietf:params:oauth:token-type:jwt${RESET}"
echo -e "  ${BOLD}  audience: https://analytics.example.com${RESET}"
echo ""

EXCHANGE_RESP=$(curl -sf -X POST "$STARFLY_URL/v1/exchange/token" \
  -H "Content-Type: application/json" \
  -d "{
    \"grant_type\": \"urn:ietf:params:oauth:grant-type:token-exchange\",
    \"subject_token\": \"$AGENT_TOKEN\",
    \"subject_token_type\": \"urn:ietf:params:oauth:token-type:jwt\",
    \"audience\": \"https://analytics.example.com\",
    \"scope\": \"read:data\"
  }") || { fail "POST /v1/exchange/token failed"; exit 1; }

WIMSE_TOKEN=$(echo "$EXCHANGE_RESP" | jq -r '.access_token')
TOKEN_TYPE=$(echo "$EXCHANGE_RESP" | jq -r '.token_type')
EXPIRES_IN=$(echo "$EXCHANGE_RESP" | jq -r '.expires_in')

ok "Token type: $TOKEN_TYPE"
ok "Expires in: ${EXPIRES_IN}s"
ok "WIMSE JWT issued (${#WIMSE_TOKEN} chars)"
echo ""
note "This JWT is cryptographically signed by Starfly's signing key."
note "Any service can verify it by fetching the JWKS from /v1/identity/jwks."

pause

# ── Step 3: Decode JWT Claims ────────────────────────────────────────

section "Step 3: Decode WIMSE JWT Claims"

note "What's inside the JWT Starfly produced?"
echo ""

# Decode JWT payload (handle both GNU and macOS base64)
PAYLOAD=$(echo "$WIMSE_TOKEN" | cut -d. -f2 | tr '_-' '/+')
MOD=$((${#PAYLOAD} % 4))
if [ $MOD -eq 2 ]; then PAYLOAD="${PAYLOAD}=="; elif [ $MOD -eq 3 ]; then PAYLOAD="${PAYLOAD}="; fi
CLAIMS=$(echo "$PAYLOAD" | base64 -d 2>/dev/null | jq . 2>/dev/null) || CLAIMS="{}"

echo "$CLAIMS" | jq .
echo ""

SUB=$(echo "$CLAIMS" | jq -r '.sub // "n/a"')
AUD=$(echo "$CLAIMS" | jq -r '.aud // "n/a"')
ISS=$(echo "$CLAIMS" | jq -r '.iss // "n/a"')
TD=$(echo "$CLAIMS" | jq -r '.td // "n/a"')

echo -e "  ${GREEN}sub${RESET}  $SUB"
echo -e "       └─ WIMSE URI: trust domain + namespace + service account"
echo -e "  ${GREEN}aud${RESET}  $AUD"
echo -e "       └─ This token is ONLY valid for this audience"
echo -e "  ${GREEN}iss${RESET}  $ISS"
echo -e "       └─ Issuing Starfly fabric"
echo -e "  ${GREEN}td${RESET}   $TD"
echo -e "       └─ Trust domain boundary"

pause

# ── Step 4: Metrics ──────────────────────────────────────────────────

section "Step 4: See It in the Metrics"

echo -e "  ${BOLD}\$ curl $STARFLY_URL/metrics | grep starfly_exchange${RESET}"
echo ""
curl -sf "$STARFLY_URL/metrics" | grep "starfly_exchange" | head -10 || echo "  (no exchange metrics yet)"

pause

# ── Summary ──────────────────────────────────────────────────────────

section "What You Just Saw"

echo -e "  ${GREEN}✓${RESET} Agent identity issued (platform: mcp, capabilities scoped)"
echo -e "  ${GREEN}✓${RESET} RFC 8693 token exchange (agent token → WIMSE JWT)"
echo -e "  ${GREEN}✓${RESET} JWT is audience-bound, time-limited, trust-domain-scoped"
echo -e "  ${GREEN}✓${RESET} Verifiable by any service via JWKS endpoint"
echo -e "  ${GREEN}✓${RESET} Every exchange tracked in Prometheus metrics"
echo ""
note "Starfly supports 11 source credential types:"
note "  K8s SA, SPIFFE SVID, OIDC, AWS STS, GCP WIF, Azure MI,"
note "  Kerberos, SAML, mTLS, API-key, OAuth2"
echo ""
echo -e "  ${DIM}Next: ./demos/02-real-time-revocation.sh — what happens when a credential is compromised${RESET}"
echo ""
