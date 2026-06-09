#!/usr/bin/env bash
# Run sandbox use cases from manifest.yaml
#
# Usage:
#   ./sandbox/run.sh              # list use cases
#   ./sandbox/run.sh all          # run all five
#   ./sandbox/run.sh 1            # by number
#   ./sandbox/run.sh exchange     # by id
#   STARFLY_PROFILE=lab ./sandbox/run.sh all
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
# shellcheck source=lib/common.sh
source "${SCRIPT_DIR}/lib/common.sh"

USE_CASES=(
  "01-exchange.sh"
  "02-revocation.sh"
  "03-mcp-confused-deputy.sh"
  "04-federation.sh"
  "05-observability.sh"
)
IDS=(exchange revocation mcp federation observability)

list_cases() {
  echo "Starfly sandbox use cases:"
  local i=1
  for uc in "${USE_CASES[@]}"; do
    echo "  $i  ${IDS[$((i - 1))]}  →  sandbox/use-cases/$uc"
    i=$((i + 1))
  done
  echo ""
  echo "Examples:"
  echo "  STARFLY_PROFILE=local ./sandbox/run.sh all"
  echo "  STARFLY_PROFILE=lab   ./sandbox/run.sh exchange"
}

resolve_target() {
  local arg="${1:-}"
  case "$arg" in
    ""|help|-h|--help)
      list_cases
      exit 0
      ;;
    all)
      echo "all"
      ;;
    [1-5])
      echo "${USE_CASES[$((arg - 1))]}"
      ;;
    exchange|revocation|mcp|federation|observability)
      local i=0
      for id in "${IDS[@]}"; do
        if [ "$id" = "$arg" ]; then
          echo "${USE_CASES[$i]}"
          return
        fi
        i=$((i + 1))
      done
      ;;
    *)
      log_fail "unknown target: $arg"
      list_cases
      exit 1
      ;;
  esac
}

main() {
  require_cmds curl jq
  load_profile
  check_health

  local target
  target=$(resolve_target "${1:-}")

  if [ "$target" = "all" ]; then
    local failed=0
    for uc in "${USE_CASES[@]}"; do
      if ! bash "${SCRIPT_DIR}/use-cases/${uc}"; then
        failed=$((failed + 1))
      fi
    done
    if [ "$failed" -gt 0 ]; then
      log_fail "${failed} use case(s) failed"
      exit 1
    fi
    log_ok "all use cases passed"
    exit 0
  fi

  bash "${SCRIPT_DIR}/use-cases/${target}"
}

main "$@"
