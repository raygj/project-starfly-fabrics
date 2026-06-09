# Starfly Fabrics

**Non-human identity for the agentic fabric.**

Starfly issues and validates WIMSE-profile JWTs for agents, enforces delegation policy, and propagates revocation state across federated peers. It is the policy enforcement point of the fabric.

- **Site:** [starfly.dev](https://starfly.dev)
- **Docs:** [starfly.dev/docs](https://starfly.dev/docs) · [getting started](docs/getting-started.md)
- **Playground:** [starfly.dev/play](https://starfly.dev/play)

## Quick start

```bash
git clone https://github.com/raygj/project-starfly-fabrics.git
cd project-starfly-fabrics
make build-dev
STARFLY_STORAGE_PATH=/tmp/starfly-dev STARFLY_POLICY_BUNDLE_PATH=policies/dev ./bin/starfly --dev
```

Then: `./sandbox/run.sh all` — five proof use cases against the running PEP.

Full tutorial: [docs/getting-started.md](docs/getting-started.md)

## Repository layout

```
cmd/ pkg/ demos/ api/ policies/   Starfly service (Go) — minimum runnable export
docs/                             v1 documentation (Diátaxis)
sandbox/                          Manifest-driven use cases + AGENTS.md contract
public/                           Website (Cloudflare Workers → starfly.dev)
wrangler.jsonc                    Workers config
```

## Documentation (v1)

| Quadrant | Start here |
|----------|------------|
| Tutorial | [docs/getting-started.md](docs/getting-started.md) |
| Explanation | [docs/glossary.md](docs/glossary.md) · [concepts/](docs/concepts/) |
| How-to | [docs/integrators/](docs/integrators/) · [sandbox/](sandbox/) |
| Reference | [api/openapi.yaml](api/openapi.yaml) · [public/llms.txt](public/llms.txt) |

**Agents:** read [AGENTS.md](AGENTS.md) first.

## Develop

```bash
make deps
make build-dev      # dev-tagged binary
make test           # pkg unit tests
./demos/01-token-exchange.sh
```

Website:

```bash
npm install
npx wrangler deploy
```

Operator deploy steps: [DEPLOY.md](DEPLOY.md)

## Export from private monorepo

Maintainers regenerate the code slice with:

```bash
communes/starfly/scripts/export-public-min.sh
```

Then merge `/tmp/export-starfly-min/` into this repo. See `system/export-public-SKILL.md` in the private Mandala workspace.

## License

Apache 2.0 — see [LICENSE](LICENSE).
