# Complete example — Helm + Starfly fabric

Agent-runnable deployment chain. No manual kubectl interpretation required.

## Prerequisites

1. Kubernetes cluster (1.28+)
2. `StarlightFabric` CRD installed (`deploy/helm/crds/`)
3. Starfly operator enabled in Helm values
4. Terraform >= 1.6
5. Local provider build: `make install` from provider root

## Steps

```bash
# 1. Build and install provider locally
cd ../../
make install

# 2. Configure for your cluster
cd examples/complete
cp terraform.tfvars.example terraform.tfvars
# Edit kubeconfig_path — use an absolute path (Terraform does not expand ~)

terraform init
terraform validate
terraform plan -out=tfplan
terraform apply tfplan
terraform output -json
```

### Home lab (Talos, single control-plane node)

Use `values_file = "values-home-lab.yaml"` in `terraform.tfvars`. That file:

- Points at your local registry image
- Adds control-plane tolerations
- Disables PrometheusRule/Grafana (no Prometheus Operator required)
- Disables persistence and operator (matches typical single-node lab; set `wait_for_converged = false`)

For production-style deploys with operator convergence, use `values-pinned.yaml` and `wait_for_converged = true`.

## Immutability outputs

| Output | Purpose |
|--------|---------|
| `values_hash` | Detect Helm values drift |
| `spec_hash` | Detect fabric spec drift |
| `fabric_phase` | Convergence status |
| `health_endpoint` | Post-deploy health check |
| `jwks_url` | Token verification endpoint |

## Destroy

```bash
terraform destroy
```
