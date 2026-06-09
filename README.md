# Starfly Fabrics

**Non-human identity for the agentic fabric.**

Public home for Starfly — service code, Terraform provider, documentation, and website.

| Surface | URL |
|---------|-----|
| Site | [starfly.dev](https://starfly.dev) |
| Docs v1.0 | [starfly.dev/1.0/docs/](https://starfly.dev/1.0/docs/) |
| API reference | [starfly.dev/api/](https://starfly.dev/api/) |
| Terraform | [starfly.dev/terraform/](https://starfly.dev/terraform/) |
| Playground | [starfly.dev/play/](https://starfly.dev/play/) |

## Quick start

```bash
git clone https://github.com/raygj/project-starfly-fabrics.git
cd project-starfly-fabrics
make build-dev
STARFLY_STORAGE_PATH=/tmp/starfly-dev STARFLY_POLICY_BUNDLE_PATH=policies/dev ./bin/starfly --dev
./sandbox/run.sh all
```

## Repository layout

```
cmd/ pkg/ demos/ api/ policies/     Starfly PEP (Go)
terraform-provider/                 Terraform provider (FIAM-as-code)
docs-site/                          Starlight docs (versioned, search, OpenAPI)
docs/                               Markdown source (synced into docs-site)
sandbox/                            Five proof use cases + AGENTS.md
docs-site/public/                   Landing page + playground static assets
```

## Documentation

Built with [Astro Starlight](https://starlight.astro.build/):

- **Versioned** — `starlight-versions` (v1.0 at `/1.0/…`)
- **Search** — Pagefind (built into Starlight)
- **OpenAPI** — `starlight-openapi` from `api/openapi.yaml`
- **Terraform subsite** — `/terraform/`

```bash
cd docs-site && npm ci && npm run dev   # local preview :4321
```

## Terraform provider

```bash
cd terraform-provider
make build
make install
```

Docs: [starfly.dev/terraform/](https://starfly.dev/terraform/)

## Develop

```bash
make test              # Starfly pkg tests
npm run test:tf        # provider unit tests
npm run deploy         # build docs + deploy to Cloudflare
```

## Maintainer exports

From the private Mandala monorepo:

- `communes/starfly/scripts/export-public-min.sh`
- `communes/starfly/scripts/export-terraform-provider.sh`

See [DEPLOY.md](DEPLOY.md).

## License

Apache 2.0 — see [LICENSE](LICENSE).
