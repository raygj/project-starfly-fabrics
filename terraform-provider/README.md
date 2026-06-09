# terraform-provider-starfly

Incubating Terraform provider for [Starfly Fabrics](https://github.com/raygj/project-starfly-fabrics) — FIAM-as-code.

**Status:** Incubating (private registry). Acceptance tests green locally; CI wired via `.github/workflows/terraform-provider.yml`.

## What it manages

| Resource | Backend | Status |
|----------|---------|--------|
| `starfly_fabric` | `StarlightFabric` CRD (Kubernetes) | v0 |
| `starfly_mcp_tool` | `POST/DELETE /v1/mcp/tools` | v0 |
| `starfly_ssf_stream` | `POST/DELETE /v1/signals/stream` | v0 |
| `starfly_agent_identity` | `POST /v1/identity/agent` | v0 |
| `starfly_encryption_key` | `POST /v1/identity/agent/encryption-key` (JWT) | v0 |

Helm chart install stays in `helm_release` — see `examples/complete/`.

## Build

```bash
cd terraform-provider
make build
make test
```

Local dev install (adjust OS/arch as needed):

```bash
make install
```

## Provider configuration

```hcl
provider "starfly" {
  kubeconfig_path = "~/.kube/config"
  namespace       = "starfly-system"

  # Phase 2 API resources
  endpoint    = "https://starfly.starfly-system.svc:8694"
  ca_cert     = file("${path.module}/certs/ca.pem")
  client_cert = file("${path.module}/certs/client.pem")
  client_key  = file("${path.module}/certs/client-key.pem")

  # Bearer auth for MCP, agent identity, encryption key
  jwt_token = var.starfly_jwt
}
```

Environment fallbacks: `KUBECONFIG`, `STARFLY_ENDPOINT`, `STARFLY_CA_CERT`, `STARFLY_CLIENT_CERT`, `STARFLY_CLIENT_KEY`, `STARFLY_JWT_TOKEN`.

See `docs/auth-migration.md` for mTLS → JWT migration.

## Example

```bash
cd examples/complete
terraform init
terraform validate
```

Acceptance tests require envtest (fabric CRD) and a live Starfly API (MCP/SSF/agent):

```bash
# Full loop: build Starfly container + run all acceptance tests
make testacc-live

# Or with Starfly already running on :8693
TF_ACC=1 STARFLY_ENDPOINT=http://localhost:8693 make testacc
```

From Forge:

```bash
cd terraform-provider: make testacc
```

## Book & backlog

- Book: ``
- Tickets: `terraform-provider (issues)`

## License

Apache 2.0 (match Starfly)
