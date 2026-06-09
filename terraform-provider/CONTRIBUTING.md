# Contributing to terraform-provider-starfly

Incubating inside the Starfly Mandala commune. See `docs/eject.md` for the standalone-repo path.

## Prerequisites

- Go 1.26+
- Docker (acceptance tests spin up Starfly)
- `setup-envtest` (installed automatically by `scripts/testacc.sh`)

## Development

```bash
cd communes/starfly/terraform-provider-starfly
make build
make test          # unit tests
make testacc-live  # full acceptance loop
```

## Pull requests

1. Run `make test` before opening a PR.
2. If you change provider resources or Starfly API integration, run `make testacc-live`.
3. Follow commit style: `type(scope): description` (e.g. `feat(provider): add ssf stream resource`).
4. Add frontmatter to new `.md` files under `docs/`.

## CI

GitHub Actions workflow `.github/workflows/terraform-provider.yml` runs unit and acceptance tests on changes to this directory.
