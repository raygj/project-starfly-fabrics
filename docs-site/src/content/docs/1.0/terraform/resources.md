---
title: Resources
description: Terraform resources managed by the Starfly provider.
slug: 1.0/terraform/resources
---

## starfly\_fabric

Manages a `StarlightFabric` CRD — declarative desired state for a Starfly fabric unit.

| Attribute | Required | Notes |
|-----------|----------|-------|
| `name` | yes | CRD resource name |
| `namespace` | no | Defaults to provider `namespace` |
| `spec` | yes | Fabric spec (YAML-compatible) |

Kubernetes-only. Does not call the Starfly HTTP API directly.

## starfly\_mcp\_tool

Registers an MCP tool via `POST /v1/mcp/tools`.

Requires `jwt_token` or mTLS on the provider. Tool `resource_uri` must match exchange `audience` for verification.

## starfly\_ssf\_stream

Configures SSF event stream delivery via `POST /v1/signals/stream`.

Production typically requires mTLS (`endpoint` on :8694).

## starfly\_agent\_identity

Issues agent bootstrap identity via `POST /v1/identity/agent`.

Output `token` can feed `jwt_token` on the provider or child modules for encryption key and MCP resources.

## starfly\_encryption\_key

Registers agent encryption keys via `POST /v1/identity/agent/encryption-key`.

**Requires** bearer JWT (`jwt_token`) — WIMSE-authenticated endpoint.

## Helm

Chart install is **not** a provider resource. Use `helm_release` with values from `starfly_fabric` outputs. See `terraform-provider/examples/complete/`.
