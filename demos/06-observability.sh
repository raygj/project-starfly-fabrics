#!/usr/bin/env bash
# ─────────────────────────────────────────────────────────────────────
# Demo 06 — Observability & Operator Visibility
#
# Outcome: Operators see everything — health, metrics, live events,
# federation status — without leaving the terminal or browser.
#
#   1. Health endpoint — system status + TLS cert expiry
#   2. Prometheus metrics — 40+ gauges and counters
#   3. CLI: starfly status — fabric health at a glance
#   4. CLI: starfly watch — live event stream (the "green screen")
#   5. SSE Luminescence — browser-based real-time events
#   6. Signal generator — background traffic for live demos
#   7. Grafana dashboards — 5 pre-built dashboards
#   8. Prometheus alerts — 10+ alert rules
#
# Usage:
#   ./demos/06-observability.sh
#
# Prerequisites:
#   go build -tags dev -o bin/starfly ./cmd/starfly/
#   go build -o bin/starfly-siggen ./cmd/starfly-siggen/  (optional, for step 6)
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
echo -e "${WHITE}  Demo 06 — Observability & Operator Visibility${RESET}"
echo -e "${DIM}  See everything, from terminal to browser${RESET}"
echo -e "${DIM}  ──────────────────────────────────────────────────────────${RESET}"
echo ""
echo -e "${YELLOW}  HOW TO WATCH — This demo IS the observability tour.${RESET}"
echo -e "  Have a browser ready for the SSE stream."
echo -e "  Have a second terminal ready for live commands."

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
TRAFFIC_PID=""
trap 'kill $TRAFFIC_PID 2>/dev/null; kill $STARFLY_PID 2>/dev/null; wait $STARFLY_PID 2>/dev/null; rm -rf "$DEMO_DIR"' EXIT

# Build a policy bundle with signal support for the signal generator
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

# ── 1. Health Endpoint ───────────────────────────────────────────────

section "1. Health Endpoint"

note "The first thing any monitoring system hits."
echo ""
echo -e "  ${BOLD}\$ curl $STARFLY_URL/v1/sys/health | jq${RESET}"
echo ""
curl -sf "$STARFLY_URL/v1/sys/health" | python3 -m json.tool 2>/dev/null || echo "  (not responding)"

echo ""
note "Fields:"
echo -e "  ${GREEN}initialized${RESET}      Lock unsealed, storage ready"
echo -e "  ${GREEN}locked${RESET}           Encryption state (false = unsealed)"
echo -e "  ${GREEN}version${RESET}          Build version"
echo -e "  ${GREEN}unit_id${RESET}          Unique fabric unit identifier"
echo -e "  ${GREEN}tls_cert_expiry${RESET}  Certificate expiry (when TLS enabled)"

pause

# ── 2. Prometheus Metrics ────────────────────────────────────────────

section "2. Prometheus Metrics — 40+ Metrics from Day One"

note "Every exchange, policy decision, revocation, and signal is metered."
echo ""
echo -e "  ${BOLD}\$ curl $STARFLY_URL/metrics | grep ^starfly_ | head -30${RESET}"
echo ""
curl -sf "$STARFLY_URL/metrics" | grep "^starfly_" | head -30
echo ""

TOTAL=$(curl -sf "$STARFLY_URL/metrics" | grep "^starfly_" | wc -l | tr -d ' ')
echo -e "  ${GREEN}$TOTAL${RESET} total Starfly metric lines"

pause

note "Key metric categories:"
echo ""
echo -e "  ${GREEN}starfly_exchange_*${RESET}       Token exchange latency + counts"
echo -e "  ${GREEN}starfly_policy_*${RESET}         Policy evaluation performance"
echo -e "  ${GREEN}starfly_revocation_*${RESET}     Revocation index size + lookup speed"
echo -e "  ${GREEN}starfly_caep_cascade_*${RESET}   Cascade latency + invalidation count"
echo -e "  ${GREEN}starfly_federation_*${RESET}     Per-peer relay, lag, sync"
echo -e "  ${GREEN}starfly_tls_*${RESET}            Certificate expiry tracking"
echo -e "  ${GREEN}starfly_soul_*${RESET}           Manifest sequence, anchor health"
echo -e "  ${GREEN}starfly_jwks_*${RESET}           JWKS cache hits/misses"
echo -e "  ${GREEN}starfly_nats_*${RESET}           Signal bus pub/sub stats"
echo -e "  ${GREEN}starfly_audit_*${RESET}          Audit event counts"

pause

# ── 3. CLI: starfly status ───────────────────────────────────────────

section "3. CLI: starfly status"

note "Fabric health at a glance — no browser needed."
echo ""
echo -e "  ${BOLD}\$ starfly status --endpoint $STARFLY_URL/metrics${RESET}"
echo ""

$BIN status --endpoint "$STARFLY_URL/metrics" 2>/dev/null || \
  note "(status command requires metrics endpoint to be accessible)"

pause

# ── 4. CLI: starfly watch ───────────────────────────────────────────

section "4. CLI: starfly watch — The Green Screen"

note "This is the live terminal feed operators keep open during incidents."
note "Every exchange, revocation, and signal appears in real time."
echo ""
echo -e "  ${BOLD}To try it now (Ctrl-C to stop):${RESET}"
echo -e "  ${GREEN}\$ ./bin/starfly watch --endpoint $STARFLY_URL/v1/events${RESET}"
echo ""
note "Pair it with the signal generator for continuous traffic:"
echo -e "  ${GREEN}\$ ./bin/starfly-siggen watch --target $STARFLY_URL --interval 2s${RESET}"
echo ""
note "The watch command streams SSE events and formats them for the terminal."
note "In a demo, this is your 'green screen' — always running, always showing"
note "the fabric's heartbeat."

pause

# ── 5. SSE Luminescence — Live Fabric ────────────────────────────────

section "5. SSE Luminescence — Live Fabric"

note "Before we look at the stream, let's spin up a live fabric."
note "Background traffic will flow so the SSE stream and metrics have"
note "real data."
echo ""
echo -e "${DIM}  ┌──────────────────────────────────────────────────────────┐${RESET}"
echo -e "${DIM}  │                                                          │${RESET}"
echo -e "${DIM}  │   ${GREEN}firefly-1${DIM}──┐                                        │${RESET}"
echo -e "${DIM}  │   ${GREEN}firefly-2${DIM}──┤   ┌─────────────┐   ┌──────────────┐  │${RESET}"
echo -e "${DIM}  │   ${GREEN}firefly-3${DIM}──┼──▶│  ${CYAN}Starfly${DIM}      │──▶│  ${YELLOW}/v1/events${DIM}  │  │${RESET}"
echo -e "${DIM}  │   ${GREEN}firefly-4${DIM}──┤   │  ${CYAN}:8693${DIM}        │   │  ${YELLOW}SSE stream${DIM}  │  │${RESET}"
echo -e "${DIM}  │   ${RED}siggen${DIM}────┘   └─────────────┘   └──────────────┘  │${RESET}"
echo -e "${DIM}  │                    │                                     │${RESET}"
echo -e "${DIM}  │              ┌─────┴─────┐                               │${RESET}"
echo -e "${DIM}  │              │ ${WHITE}/metrics${DIM}  │                               │${RESET}"
echo -e "${DIM}  │              │ ${WHITE}Prometheus${DIM}│                               │${RESET}"
echo -e "${DIM}  │              └───────────┘                               │${RESET}"
echo -e "${DIM}  │                                                          │${RESET}"
echo -e "${DIM}  └──────────────────────────────────────────────────────────┘${RESET}"
echo ""

note "Starting background traffic: 4 agents exchanging + signal generator..."
echo ""

# Spin up a burst of exchanges from multiple agents
(
  for i in 1 2 3 4; do
    TK=$(curl -sf -X POST "$STARFLY_URL/v1/identity/agent" \
      -H "Content-Type: application/json" \
      -d "{\"agent_name\":\"firefly-$i\",\"platform\":\"mcp\",\"capabilities\":[\"exchange\"]}" 2>/dev/null \
      | python3 -c "import sys,json; print(json.load(sys.stdin).get('token',''))" 2>/dev/null) || continue
    [ -z "$TK" ] && continue
    # Each agent does repeated exchanges
    while true; do
      curl -sf -X POST "$STARFLY_URL/v1/exchange/token" \
        -H "Content-Type: application/json" \
        -d "{
          \"grant_type\":\"urn:ietf:params:oauth:grant-type:token-exchange\",
          \"subject_token\":\"$TK\",
          \"subject_token_type\":\"urn:ietf:params:oauth:token-type:jwt\",
          \"audience\":\"https://api-$i.example.com\"
        }" > /dev/null 2>&1 || true
      sleep $((RANDOM % 3 + 1))
    done &
  done

  # Also run the signal generator if available
  SIGGEN=bin/starfly-siggen
  if [ -f "$SIGGEN" ]; then
    $SIGGEN watch --target "$STARFLY_URL" --interval 3s > /dev/null 2>&1
  fi
) &
TRAFFIC_PID=$!

# Give it a moment to generate some data
sleep 3

ok "4 agents exchanging + signal generator running"
ok "Traffic is flowing — SSE stream and metrics are live"
echo ""

note "Open in a browser or stream in a terminal:"
echo ""
echo -e "  ${BOLD}${GREEN}$STARFLY_URL/v1/events${RESET}"
echo -e "  ${GREEN}\$ curl -N $STARFLY_URL/v1/events${RESET}"

pause

# ── 6. Signal Generator ─────────────────────────────────────────────

section "6. Signal Generator — What's Running"

note "The signal generator is already running in the background (started in step 5)."
note "It sends random CAEP events every 3 seconds. Here's what it supports:"
echo ""

SIGGEN=bin/starfly-siggen
if [ -f "$SIGGEN" ]; then
  echo -e "  ${BOLD}\$ starfly-siggen list${RESET}"
  echo ""
  $SIGGEN list 2>/dev/null || note "(list command not available)"
  echo ""
fi

note "Commands for targeted demos:"
echo ""
echo -e "  ${GREEN}starfly-siggen revoke${RESET}                 Single credential revocation"
echo -e "  ${GREEN}starfly-siggen mcp-compromised${RESET}        MCP tool compromise"
echo -e "  ${GREEN}starfly-siggen compliance-change${RESET}      Device compliance violation"
echo -e "  ${GREEN}starfly-siggen test${RESET}                   Full integration test (11 event types)"
echo -e "  ${GREEN}starfly-siggen watch --interval 1s${RESET}    Crank up the event rate"
echo ""

note "Let's check the live metrics with traffic flowing:"
echo ""
echo -e "  ${BOLD}\$ curl $STARFLY_URL/metrics | grep starfly_signals${RESET}"
echo ""
curl -sf "$STARFLY_URL/metrics" | grep "starfly_signals\|starfly_caep\|starfly_exchange_requests" | head -15 || echo "  (no signal metrics yet)"

pause

# ── 7. Grafana Dashboards ────────────────────────────────────────────

section "7. Grafana Dashboards (Helm-Provisioned)"

note "Five pre-built dashboards ship as Helm ConfigMaps:"
echo ""
echo -e "  ${GREEN}1.${RESET} Starfly Fabric Overview     — unit health, exchange rates, federation"
echo -e "  ${GREEN}2.${RESET} Revocation Intelligence     — cascade latency, index size, denial rate"
echo -e "  ${GREEN}3.${RESET} Federation Topology         — per-peer relay health, lag per cluster"
echo -e "  ${GREEN}4.${RESET} MCP Tool Security           — tool calls per agent, denied accesses"
echo -e "  ${GREEN}5.${RESET} TLS & Certificate           — expiry tracking, rotation events"
echo ""
note "Deployed automatically with Helm:"
echo -e "  ${GREEN}\$ helm install starfly ./deploy/helm --set grafana.dashboards.enabled=true${RESET}"

pause

# ── 8. Prometheus Alerts ─────────────────────────────────────────────

section "8. Prometheus Alert Rules"

note "10+ alert rules ship in the Helm chart (PrometheusRule CRD):"
echo ""
echo -e "  ${RED}CRITICAL${RESET}"
echo -e "    StarflyExchangeLatencyHigh         p99 > 15ms"
echo -e "    StarflyRevocationCascadeSlow        cascade > 2s"
echo -e "    StarflySplitBrainDetected           no anchors reachable"
echo -e "    StarflyFederationRelayLatencyHigh   p99 relay > 2s"
echo ""
echo -e "  ${YELLOW}WARNING${RESET}"
echo -e "    StarflySoulManifestStale            anchor > 5m old"
echo -e "    StarflyFabricUnitDown               unit count < expected"
echo -e "    StarflyRevocationIndexLarge          index > threshold"
echo -e "    StarflyFederationPeerUnreachable    peer errors > 3 in 5m"
echo -e "    StarflyFederationRevocationLagHigh  no relay in 60s"
echo -e "    StarflyTLSCertExpiringSoon          cert expires < 7 days"

pause

# ── 9. Putting It Together ───────────────────────────────────────────

section "9. The Demo Setup"

note "For a live demo or sprint review, here's the recommended setup:"
echo ""
echo -e "  ${BOLD}Screen 1 (main):${RESET}  This demo script"
echo -e "  ${BOLD}Screen 2:${RESET}         ${GREEN}./bin/starfly watch${RESET}  — green screen event feed"
echo -e "  ${BOLD}Screen 3:${RESET}         ${GREEN}./bin/starfly-siggen watch --interval 2s${RESET}  — traffic"
echo -e "  ${BOLD}Browser tab 1:${RESET}    ${GREEN}$STARFLY_URL/v1/sys/health${RESET}"
echo -e "  ${BOLD}Browser tab 2:${RESET}    ${GREEN}$STARFLY_URL/v1/events${RESET}  — Luminescence SSE"
echo ""
note "Container mode (podman or docker):"
echo -e "  ${GREEN}\$ make docker-run${RESET}"
echo -e "  ${GREEN}\$ podman run --rm -p 8693:8693 starfly-fabrics/starfly:dev --dev${RESET}"
echo -e "  Then hit the same endpoints from the host."
echo ""
note "For the confused deputy demo (03), open the Excalidraw diagram:"
echo -e "  ${GREEN}architecture/mcp-confused-deputy-demo.excalidraw${RESET}"

pause

# ── Summary ──────────────────────────────────────────────────────────

section "What You Just Saw"

echo -e "  ${GREEN}✓${RESET} Health endpoint with TLS cert expiry"
echo -e "  ${GREEN}✓${RESET} 40+ Prometheus metrics covering every subsystem"
echo -e "  ${GREEN}✓${RESET} CLI: starfly status — fabric health at a glance"
echo -e "  ${GREEN}✓${RESET} CLI: starfly watch — live terminal event stream"
echo -e "  ${GREEN}✓${RESET} SSE Luminescence — browser real-time visibility"
echo -e "  ${GREEN}✓${RESET} Signal generator — simulate production traffic"
echo -e "  ${GREEN}✓${RESET} 5 Grafana dashboards (auto-provisioned)"
echo -e "  ${GREEN}✓${RESET} 10+ Prometheus alert rules in Helm"
echo ""
echo -e "  ${DIM}The fabric doesn't just work. It communicates.${RESET}"
echo ""
echo -e "  ${BOLD}${CYAN}Each drawn to the other's light. The swarm finds its rhythm.${RESET}"
echo ""
