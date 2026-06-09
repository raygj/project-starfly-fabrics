#!/usr/bin/env bash
# ─────────────────────────────────────────────────────────────────────
# Demo 00 — What Is Starfly?
#
# Walk through the system from the CLI:
#   1. Boot sequence — what does an operator see on day one?
#   2. Configuration anatomy — YAML config, env vars, CLI flags
#   3. Rego policy engine — the rules that govern every decision
#   4. KMS unseal — encryption at rest, KMS as root of trust
#   5. K8s as secret zero — ServiceAccount → WIMSE JWT chain
#   6. API surface — every endpoint, explained
#
# Usage:
#   ./demos/00-what-is-starfly.sh
#
# Prerequisites:
#   go build -tags dev -o bin/starfly ./cmd/starfly/
# ─────────────────────────────────────────────────────────────────────

set -euo pipefail
cd "$(dirname "$0")/.."

BOLD='\033[1m'
DIM='\033[2m'
GREEN='\033[1;32m'
YELLOW='\033[1;33m'
CYAN='\033[1;36m'
RED='\033[1;31m'
WHITE='\033[1;37m'
RESET='\033[0m'

section() {
  echo ""
  echo -e "${BOLD}${CYAN}━━━ $1 ━━━${RESET}"
  echo ""
}

note() { echo -e "  ${DIM}$1${RESET}"; }

pause() {
  echo ""
  echo -e "${DIM}  (press Enter to continue)${RESET}"
  read -r
}

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
echo -e "${WHITE}  Demo 00 — What Is Starfly?${RESET}"
echo -e "${DIM}  Identity fabric for agentic workloads${RESET}"
echo -e "${DIM}  ──────────────────────────────────────────────────────────${RESET}"
echo ""
echo -e "${YELLOW}  HOW TO WATCH:${RESET}"
echo -e "  Terminal 2:  ${GREEN}curl -N http://localhost:8693/v1/events${RESET}  (SSE stream)"
echo -e "  Browser:     ${GREEN}http://localhost:8693/v1/sys/health${RESET}     (health JSON)"
echo -e "  Browser:     ${GREEN}http://localhost:8693/v1/events${RESET}         (Luminescence)"

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

# ── 1. Boot Sequence ─────────────────────────────────────────────────

section "1. Boot Sequence — First Impressions"

note "Starfly is an identity exchange fabric. It issues, validates, and"
note "revokes WIMSE JWTs for agentic workloads — agents, MCP tools,"
note "microservices — across clusters and trust domains."
echo ""
note "Let's boot it in dev mode and see what an operator sees."
echo ""

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
  if curl -sf http://localhost:8693/v1/sys/health > /dev/null 2>&1; then
    break
  fi
  sleep 0.2
done

cat "$DEMO_DIR/boot.log"

echo ""
note "Every component reports its startup time. If something is slow,"
note "you see it immediately — no guessing."

pause

# ── 2. Configuration Anatomy ────────────────────────────────────────

section "2. Configuration Anatomy"

note "Starfly configures through three layers (highest priority wins):"
echo ""
echo -e "  ${BOLD}1. CLI flags${RESET}     --listen-addr :8693  --dev"
echo -e "  ${BOLD}2. Env vars${RESET}      STARFLY_LOCK_TYPE=awskms"
echo -e "  ${BOLD}3. Config file${RESET}   --config /etc/starfly/config.yaml"
echo ""
note "Key configuration sections:"
echo ""
echo -e "  ${GREEN}lock${RESET}          Encryption at rest (dev | awskms | gcpkms | azurekeyvault | transit)"
echo -e "  ${GREEN}storage${RESET}       Persistent state (BadgerDB path)"
echo -e "  ${GREEN}tls${RESET}           mTLS dual-port (cert, key, CA, cert-manager)"
echo -e "  ${GREEN}nats${RESET}          Signal bus (embedded in dev, external in prod)"
echo -e "  ${GREEN}federation${RESET}    Cross-cluster peers (JWKS endpoints, refresh intervals)"
echo -e "  ${GREEN}identity${RESET}      Trust domains, JWKS resolution"

pause

note "Helm values.yaml drives all of this in Kubernetes:"
echo ""
echo -e "  ${BOLD}\$ head -40 deploy/helm/values.yaml${RESET}"
echo ""
head -40 deploy/helm/values.yaml 2>/dev/null || echo "  (values.yaml not found — run from communes/starfly/)"

pause

# ── 3. Rego Policy Engine ────────────────────────────────────────────

section "3. Rego Policy Engine — Rules That Govern Every Decision"

note "Starfly delegates ALL access decisions to OPA. Four policy files:"
echo ""
echo -e "  ${GREEN}exchange.rego${RESET}        Token exchange — who can exchange what for whom"
echo -e "  ${GREEN}mcp.rego${RESET}             MCP tool calls — audience, capabilities, blast radius"
echo -e "  ${GREEN}agent_identity.rego${RESET}  Agent attestation — hardware, platform, workload"
echo -e "  ${GREEN}compliance.rego${RESET}      Compliance scans — TTL, delegation depth, revocation health"
echo ""

note "Let's look at the exchange policy — this is the core rule:"
echo ""
echo -e "${DIM}───────── policies/exchange.rego ─────────${RESET}"
cat policies/exchange.rego
echo -e "${DIM}──────────────────────────────────────────${RESET}"

pause

note "And the MCP policy — this prevents confused deputy attacks:"
echo ""
echo -e "${DIM}───────── policies/mcp.rego ──────────────${RESET}"
cat policies/mcp.rego
echo -e "${DIM}──────────────────────────────────────────${RESET}"

pause

# ── 4. KMS Unseal — Secret Zero ──────────────────────────────────────

section "4. KMS Unseal — Encryption at Rest"

note "Starfly encrypts all persistent state (revocation index, signing keys,"
note "audit logs) at rest. The 'lock' is the encryption envelope."
echo ""
note "In dev mode, the lock is a static key (not secure — for demos only)."
note "In production, the lock key lives in your cloud KMS:"
echo ""
echo -e "  ${GREEN}awskms${RESET}          AWS KMS — key ARN + IAM role"
echo -e "  ${GREEN}gcpkms${RESET}          GCP Cloud KMS — resource name + service account"
echo -e "  ${GREEN}azurekeyvault${RESET}   Azure Key Vault — vault URL + managed identity"
echo -e "  ${GREEN}transit${RESET}         HashiCorp Vault Transit — mount path + token"
echo ""
note "The trust chain:"
echo ""
echo -e "  ${BOLD}Cloud KMS${RESET} (root of trust)"
echo -e "    └─ encrypts → ${BOLD}Starfly lock key${RESET} (data encryption key)"
echo -e "         └─ encrypts → ${BOLD}BadgerDB${RESET} (signing keys, revocation index, state)"
echo -e "              └─ signs → ${BOLD}WIMSE JWTs${RESET} (issued to workloads)"
echo ""
note "Migrate between KMS providers without downtime:"
echo ""
echo -e "  ${BOLD}\$ starfly lock migrate --from-type awskms --to-type gcpkms${RESET}"

pause

# ── 5. K8s as Secret Zero ────────────────────────────────────────────

section "5. Kubernetes as Secret Zero"

note "In Kubernetes, the trust chain starts with the ServiceAccount token:"
echo ""
echo -e "  ${BOLD}K8s API Server${RESET} (cluster root of trust)"
echo -e "    └─ issues → ${BOLD}ServiceAccount JWT${RESET} (projected volume)"
echo -e "         └─ authenticates → ${BOLD}Starfly Pod${RESET} (via TokenReview)"
echo -e "              └─ exchanges → ${BOLD}WIMSE JWT${RESET} (scoped, delegatable, revocable)"
echo ""
note "The K8s ServiceAccount JWT is the 'secret zero' — the first credential"
note "in the chain. Everything else derives from it."
echo ""
note "Starfly validates K8s SA tokens via the TokenReview API, then issues"
note "a WIMSE JWT with:"
echo ""
echo -e "  ${GREEN}sub${RESET}     wimse://\${trust_domain}/ns/\${namespace}/sa/\${sa_name}"
echo -e "  ${GREEN}iss${RESET}     starfly fabric ID"
echo -e "  ${GREEN}aud${RESET}     target trust domain or tool URI"
echo -e "  ${GREEN}td${RESET}      trust domain"
echo -e "  ${GREEN}caps${RESET}    scoped capabilities"
echo -e "  ${GREEN}exp${RESET}     short-lived (configurable TTL, default 1h)"
echo ""
note "Other secret-zero sources: SPIFFE SVID, AWS IMDS, GCP metadata,"
note "Azure managed identity, mTLS client cert, OIDC tokens."

pause

# ── 6. API Surface ───────────────────────────────────────────────────

section "6. API Surface — What Can You Hit?"

echo -e "  ${BOLD}PUBLIC (port 8693)${RESET}"
echo ""
echo -e "  ${GREEN}GET  /v1/sys/health${RESET}              Health check + TLS cert expiry"
echo -e "  ${GREEN}GET  /v1/identity/jwks${RESET}           Public signing keys (JWKS)"
echo -e "  ${GREEN}GET  /metrics${RESET}                    Prometheus (40+ gauges/counters)"
echo -e "  ${GREEN}GET  /openapi.yaml${RESET}               OpenAPI 3.1 spec"
echo -e "  ${GREEN}GET  /v1/events${RESET}                  SSE stream (Luminescence)"
echo -e "  ${GREEN}GET  /.well-known/ssf-configuration${RESET}  SSF discovery"
echo ""
echo -e "  ${BOLD}PROTECTED (port 8694 — mTLS in prod, 8693 in dev)${RESET}"
echo ""
echo -e "  ${GREEN}POST /v1/exchange/token${RESET}          RFC 8693 token exchange"
echo -e "  ${GREEN}POST /v1/identity/agent${RESET}          Agent identity issuance"
echo -e "  ${GREEN}POST /v1/signals/events${RESET}          CAEP/SSF signal receiver"
echo -e "  ${GREEN}POST /v1/signals/stream${RESET}          SSF stream management"
echo -e "  ${GREEN}GET  /v1/signals/status${RESET}          Stream health"
echo -e "  ${GREEN}POST /v1/mcp/tools${RESET}               Register MCP tool"
echo -e "  ${GREEN}GET  /v1/mcp/tools${RESET}               List MCP tools"
echo -e "  ${GREEN}POST /v1/mcp/verify${RESET}              Verify MCP tool token"
echo -e "  ${GREEN}GET  /v1/federation/revocation-hash${RESET}    Revocation state hash"
echo -e "  ${GREEN}GET  /v1/federation/revocation-export${RESET}  Full revocation export"
echo ""

note "Let's hit the live endpoints:"
echo ""
echo -e "  ${BOLD}\$ curl localhost:8693/v1/sys/health | jq${RESET}"
echo ""
curl -sf http://localhost:8693/v1/sys/health | python3 -m json.tool 2>/dev/null || echo "  (health endpoint not responding)"

pause

echo -e "  ${BOLD}\$ curl localhost:8693/v1/identity/jwks | jq '.keys | length'${RESET}"
echo ""
JWKS_COUNT=$(curl -sf http://localhost:8693/v1/identity/jwks 2>/dev/null | python3 -c "import sys,json; print(len(json.load(sys.stdin).get('keys',[])))" 2>/dev/null || echo "0")
echo -e "  ${GREEN}$JWKS_COUNT signing key(s)${RESET} published in JWKS"

pause

echo -e "  ${BOLD}\$ curl localhost:8693/metrics | grep ^starfly_ | wc -l${RESET}"
echo ""
METRIC_COUNT=$(curl -sf http://localhost:8693/metrics 2>/dev/null | grep "^starfly_" | wc -l | tr -d ' ')
echo -e "  ${GREEN}$METRIC_COUNT${RESET} Prometheus metric lines exported"

pause

# ── Summary ──────────────────────────────────────────────────────────

section "What You Just Saw"

echo -e "  ${GREEN}✓${RESET} Boot sequence with timed component startup"
echo -e "  ${GREEN}✓${RESET} Three-layer config (CLI > env > file)"
echo -e "  ${GREEN}✓${RESET} OPA Rego policies governing every access decision"
echo -e "  ${GREEN}✓${RESET} KMS-backed encryption at rest (5 lock providers)"
echo -e "  ${GREEN}✓${RESET} K8s ServiceAccount as secret zero (+ 10 other identity sources)"
echo -e "  ${GREEN}✓${RESET} Dual-port API: public (8693) + mTLS-protected (8694)"
echo ""
echo -e "  ${DIM}Next: ./demos/01-token-exchange.sh — see the exchange engine in action${RESET}"
echo ""
echo -e "  ${BOLD}${CYAN}Each drawn to the other's light. The swarm finds its rhythm.${RESET}"
echo ""
