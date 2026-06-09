#!/usr/bin/env bash
# Generate Go gRPC stubs from proto definition.
# Prerequisites: protoc, protoc-gen-go, protoc-gen-go-grpc
#
# Install:
#   go install google.golang.org/protobuf/cmd/protoc-gen-go@latest
#   go install google.golang.org/grpc/cmd/protoc-gen-go-grpc@latest
#
# Run from this directory:
#   ./gen.sh
set -euo pipefail

protoc \
  --go_out=. --go_opt=paths=source_relative \
  --go-grpc_out=. --go-grpc_opt=paths=source_relative \
  agent_identity.proto
