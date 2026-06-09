#!/usr/bin/env bash
# Run terraform-provider-starfly acceptance tests against a live Starfly instance.
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
STARFLY_DIR="$(cd "$ROOT/.." && pwd)"
CONTAINER_NAME="${STARFLY_TF_CONTAINER:-starfly-tf-acc}"
ENDPOINT="${STARFLY_ENDPOINT:-http://localhost:8693}"

cleanup() {
  docker rm -f "$CONTAINER_NAME" >/dev/null 2>&1 || true
}

start_starfly() {
  if curl -sf "$ENDPOINT/v1/sys/health" >/dev/null 2>&1; then
    echo "==> Starfly already reachable at $ENDPOINT"
    return 0
  fi

  echo "==> Building starfly:dev"
  docker build -t starfly-fabrics/starfly:dev -f "$STARFLY_DIR/Dockerfile" "$STARFLY_DIR"

  cleanup
  echo "==> Starting $CONTAINER_NAME on :8693"
  docker run -d --rm -p 8693:8693 --name "$CONTAINER_NAME" \
    -v "$STARFLY_DIR/test/red/fixtures/policies:/etc/starfly/policies:ro" \
    -e STARFLY_NATS_JETSTREAM_DIR=/tmp/nats \
    -e STARFLY_STORAGE_PATH=/data/starfly \
    starfly-fabrics/starfly:dev --dev

  for i in $(seq 1 30); do
    if curl -sf "$ENDPOINT/v1/sys/health" >/dev/null 2>&1; then
      echo "==> Starfly ready"
      return 0
    fi
    sleep 1
  done

  echo "ERROR: Starfly failed health check"
  docker logs "$CONTAINER_NAME" 2>&1 | tail -30
  exit 1
}

trap cleanup EXIT

start_starfly

export TF_ACC=1
export STARFLY_ENDPOINT="$ENDPOINT"

if [ -z "${KUBEBUILDER_ASSETS:-}" ]; then
  SETUP_ENVTEST="$(go env GOPATH)/bin/setup-envtest"
  if [ ! -x "$SETUP_ENVTEST" ]; then
    echo "==> Installing setup-envtest"
    go install sigs.k8s.io/controller-runtime/tools/setup-envtest@latest
  fi
  echo "==> Installing envtest kube assets"
  export KUBEBUILDER_ASSETS="$("$SETUP_ENVTEST" use 1.31.0 -p path)"
  echo "==> KUBEBUILDER_ASSETS=$KUBEBUILDER_ASSETS"
fi

cd "$ROOT"
make testacc
