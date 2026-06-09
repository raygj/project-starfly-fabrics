---
tags: [commune/starfly, terraform, eject]
type: pattern
created: 2026-05-23
---

# Eject Checklist — terraform-provider-starfly

When Starfly is ready for formal publish, eject the provider from the Mandala commune to a standalone repo.

## Pre-eject gates

- [x] All TF-001 through TF-011 tickets DONE
- [x] `scripts/testacc.sh` green locally
- [ ] CI job `terraform-provider` green on GitHub Actions
- [x] No secrets or PII in committed files

## Repo split

1. Create `github.com/starfly-fabrics/terraform-provider-starfly`
2. Copy `communes/starfly/terraform-provider-starfly/` to repo root
3. Remove `replace github.com/starfly-fabrics/starfly => ../` from `go.mod`
4. Publish `pkg/operator/api/v1alpha1` types as a small module OR vendor CRD types into provider
5. Update import paths if module path changes

## Registry publish (private first)

1. Build release binaries: `goreleaser release` (see `.github/workflows/release.yml` skeleton)
2. Push to private Terraform Registry or host at `registry.terraform.io/starfly-fabrics/starfly`
3. Update `examples/complete/versions.tf` source path

## Consumer migration

Agents update `required_providers`:

```hcl
terraform {
  required_providers {
    starfly = {
      source  = "starfly-fabrics/starfly"
      version = "~> 0.1"
    }
  }
}
```

## Mandala cleanup

1. Mark book TF-001 DONE with gate signal
2. Archive backlog or move open tickets to standalone repo issues
3. Remove incubation copy from commune OR replace with submodule pointer

## License

Apache 2.0 — match Starfly Fabrics
