#!/usr/bin/env bash
# ─────────────────────────────────────────────────────────────────────
# Demo 05 — Compliance & Policy-as-Code
#
# Outcome: Every access decision is governed by OPA Rego policies.
# Operators write rules, Starfly enforces them on every exchange.
# Compliance scans detect violations continuously.
#
#   1. Walk through each Rego policy file
#   2. Show policy evaluation on a live exchange
#   3. Trigger a compliance violation
#   4. Show the compliance scan results
#
# Usage:
#   ./demos/05-compliance-scan.sh
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
echo -e "${WHITE}  Demo 05 — Compliance & Policy-as-Code${RESET}"
echo -e "${DIM}  Rego rules govern every decision${RESET}"
echo -e "${DIM}  ──────────────────────────────────────────────────────────${RESET}"
echo ""
echo -e "${YELLOW}  HOW TO WATCH:${RESET}"
echo -e "  Terminal 2:  ${GREEN}curl -N $STARFLY_URL/v1/events${RESET}  (SSE stream)"
echo -e "  Terminal 3:  ${GREEN}while true; do curl -s $STARFLY_URL/metrics | grep policy; sleep 1; done${RESET}"

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
  deny "Starfly failed to start. Check $DEMO_DIR/boot.log"
  exit 1
fi
ok "Starfly is running (PID $STARFLY_PID)"

# ── Step 1: Policy Inventory ─────────────────────────────────────────

section "Step 1: Policy Inventory"

note "Starfly ships four policy files. Operators can override any of"
note "them by mounting custom policies at /etc/starfly/policies/."
echo ""

echo -e "  ${BOLD}Policy Files:${RESET}"
echo ""

for f in policies/exchange.rego policies/mcp.rego policies/agent_identity.rego policies/compliance.rego; do
  if [ -f "$f" ]; then
    LINES=$(wc -l < "$f" | tr -d ' ')
    PACKAGE=$(grep "^package " "$f" | head -1 | awk '{print $2}')
    echo -e "  ${GREEN}$f${RESET}"
    echo -e "    Package: ${BOLD}$PACKAGE${RESET}  ($LINES lines)"
  fi
done

echo ""
echo -e "  ${BOLD}Test Files:${RESET}"
echo ""
for f in policies/*_test.rego; do
  if [ -f "$f" ]; then
    TESTS=$(grep -c "^test_" "$f" 2>/dev/null || echo "0")
    echo -e "  ${GREEN}$f${RESET}  ($TESTS tests)"
  fi
done

pause

# ── Step 2: Exchange Policy Deep Dive ────────────────────────────────

section "Step 2: Exchange Policy — Who Can Exchange What"

note "This is the core policy. Every token exchange is evaluated against it."
echo ""
echo -e "${DIM}───────── policies/exchange.rego ─────────${RESET}"
cat policies/exchange.rego
echo -e "${DIM}──────────────────────────────────────────${RESET}"
echo ""
note "Three conditions must be true:"
echo -e "  ${GREEN}1.${RESET} valid_subject   — attestation evidence present"
echo -e "  ${GREEN}2.${RESET} trusted_target  — target in configured trust domains"
echo -e "  ${GREEN}3.${RESET} valid_scope     — requested scope allowed for this pairing"
echo ""
note "If any fails, the deny reason is returned to the caller."

pause

# ── Step 3: Compliance Policy Deep Dive ──────────────────────────────

section "Step 3: Compliance Policy — Continuous Scanning"

note "The compliance policy runs as a periodic scan (via Temporal workflow)"
note "checking all active credentials for violations."
echo ""
echo -e "${DIM}───────── policies/compliance.rego ───────${RESET}"
cat policies/compliance.rego
echo -e "${DIM}──────────────────────────────────────────${RESET}"

pause

note "Five compliance rules:"
echo ""
echo -e "  ${YELLOW}excessive_ttl${RESET}          Token lifetime > max (default: 3600s)"
echo -e "  ${YELLOW}deep_delegation${RESET}        Delegation chain > max depth (default: 3)"
echo -e "  ${YELLOW}unscoped_execution${RESET}     Execution scope without trust domain binding"
echo -e "  ${YELLOW}revocation_unhealthy${RESET}   Revocation index not responding"
echo -e "  ${YELLOW}unknown_credential${RESET}     Credential type not in approved list"
echo ""
note "Each rule produces a structured finding with severity, message,"
note "and remediation guidance."

pause

# ── Step 4: MCP Policy — Confused Deputy Rules ──────────────────────

section "Step 4: MCP Policy — Tool-Level Access Control"

note "See demo 03 for the full confused deputy walkthrough."
note "Here's the policy that makes it work:"
echo ""
echo -e "${DIM}───────── policies/mcp.rego ──────────────${RESET}"
cat policies/mcp.rego
echo -e "${DIM}──────────────────────────────────────────${RESET}"

pause

# ── Step 5: Agent Identity Policy ────────────────────────────────────

section "Step 5: Agent Identity Policy — Attestation Requirements"

note "Controls what attestation evidence is required for different capabilities."
echo ""
echo -e "${DIM}───────── policies/agent_identity.rego ───${RESET}"
cat policies/agent_identity.rego
echo -e "${DIM}──────────────────────────────────────────${RESET}"

pause

# ── Step 6: Policy Metrics ───────────────────────────────────────────

section "Step 6: Policy Evaluation Metrics"

note "Live policy metrics from Starfly:"
echo ""
echo -e "  ${BOLD}\$ curl $STARFLY_URL/metrics | grep policy${RESET}"
echo ""
curl -sf "$STARFLY_URL/metrics" | grep "policy" | head -10 || echo "  (no policy metrics yet — run an exchange first)"

pause

# ── Summary ──────────────────────────────────────────────────────────

section "What You Just Saw"

echo -e "  ${GREEN}✓${RESET} Four Rego policy files governing all access decisions"
echo -e "  ${GREEN}✓${RESET} Exchange policy: attestation + trust domain + scope"
echo -e "  ${GREEN}✓${RESET} MCP policy: audience binding (confused deputy), capabilities, blast radius"
echo -e "  ${GREEN}✓${RESET} Compliance policy: TTL, delegation depth, scope, revocation health"
echo -e "  ${GREEN}✓${RESET} Agent identity policy: attestation requirements per capability"
echo -e "  ${GREEN}✓${RESET} Every evaluation tracked in Prometheus"
echo ""
note "Operators customize by mounting their own .rego files."
note "Policy changes take effect on next evaluation — no restart needed."
echo ""
echo -e "  ${DIM}Next: ./demos/06-observability.sh — the operator's view${RESET}"
echo ""
