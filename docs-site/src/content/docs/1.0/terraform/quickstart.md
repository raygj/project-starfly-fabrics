---
title: Quick start
description: Build and configure the Starfly Terraform provider from the public repo.
slug: 1.0/terraform/quickstart
---

## Prerequisites

* Go 1.25+
* Terraform 1.5+
* `kubectl` + cluster access (for `starfly_fabric`)
* Running Starfly PEP for API resources (or local `make dev`)

## Clone and build

```bash
git clone https://github.com/raygj/project-starfly-fabrics.git
cd project-starfly-fabrics/terraform-provider
make build
make install   # installs to ~/.terraform.d/plugins
```

The provider lives beside the Starfly service module in this repository (`replace` in `go.mod`).

## Provider block

```hcl
terraform {
  required_providers {
    starfly = {
      source  = "starfly-fabrics/starfly"
      version = "~> 0.1"
    }
  }
}

provider "starfly" {
  kubeconfig_path = "~/.kube/config"
  namespace       = "starfly-system"

  # API resources (MCP, agent identity, encryption key, SSF stream)
  endpoint    = "https://starfly.starfly-system.svc:8694"
  ca_cert     = file("${path.module}/certs/ca.pem")
  client_cert = file("${path.module}/certs/client.pem")
  client_key  = file("${path.module}/certs/client-key.pem")
  jwt_token   = var.starfly_jwt
}
```

Environment fallbacks: `KUBECONFIG`, `STARFLY_ENDPOINT`, `STARFLY_CA_CERT`, `STARFLY_CLIENT_CERT`, `STARFLY_CLIENT_KEY`, `STARFLY_JWT_TOKEN`.

## Example

```bash
cd examples/complete
terraform init
terraform validate
```

## Acceptance tests

```bash
# Starfly on :8693 in dev mode
TF_ACC=1 STARFLY_ENDPOINT=http://localhost:8693 make testacc
```
