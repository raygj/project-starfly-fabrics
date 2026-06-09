#!/usr/bin/env bash
# Bootstrap check — verify a Starfly PEP is reachable before running use cases.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
# shellcheck source=lib/common.sh
source "${SCRIPT_DIR}/lib/common.sh"

require_cmds curl jq
load_profile

echo -e "${CYAN}Starfly sandbox init${RESET}"
log_note "profile: ${STARFLY_PROFILE}"
log_note "url:     ${STARFLY_URL}"

check_health

jwks=$(curl -sf "${STARFLY_URL}/v1/identity/jwks" | jq -r '.keys[0].kid // "none"')
log_ok "jwks kid: ${jwks}"

echo ""
log_ok "sandbox ready — run ./sandbox/run.sh all"
