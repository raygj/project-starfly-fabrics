# Starfly Agent Guide

You are working with the **Starfly public sandbox** — prove exchange, revocation, MCP, federation, and observability against a live PEP before suggesting integration code.

**Outcome:** five `ok`/`fail` scripts that show the fabric works; then point the human to the right integrator doc on [starfly.dev](https://starfly.dev/1.0/docs/).

## Read first

| Order | Source | Why |
|-------|--------|-----|
| 1 | `sandbox/manifest.yaml` | Profiles, use cases, endpoints — **source of truth** |
| 2 | [Getting started](https://starfly.dev/1.0/docs/getting-started/) | Build and first exchange |
| 3 | [Glossary](https://starfly.dev/1.0/docs/glossary/) | Trust domain ≠ audience |
| 4 | [llms.txt](https://starfly.dev/llms.txt) | Full doc index |

Do not guess endpoints or invent curl paths. The manifest wins.

## Bootstrap

```bash
export STARFLY_PROFILE=local    # laptop :8693 (recommended)
export STARFLY_PROFILE=lab      # Talos lab — LAN/VPN only
export STARFLY_PROFILE=personal # set STARFLY_URL to your Helm release

./sandbox/init.sh               # verify PEP health
./sandbox/run.sh all            # five proof scripts
```

### Profiles

| Profile | URL | Use when |
|---------|-----|----------|
| `local` | `http://localhost:8693` | Full dev-mode surface on your machine |
| `lab` | `http://192.168.1.98:30095` | Shared Talos sandbox (LAN only) |
| `personal` | `$STARFLY_URL` | Your own fabric unit |

**Start local PEP** (nothing running yet):

```bash
git clone https://github.com/raygj/project-starfly-fabrics.git
cd project-starfly-fabrics
make build-dev
STARFLY_STORAGE_PATH=/tmp/starfly-dev STARFLY_POLICY_BUNDLE_PATH=policies/dev ./bin/starfly --dev
```

## Use cases

| # | ID | Proves |
|---|-----|--------|
| 1 | `exchange` | Platform credential → scoped WIMSE JWT (RFC 8693) |
| 2 | `revocation` | CAEP kill switch denies revoked identity immediately |
| 3 | `mcp` | Audience binding blocks confused deputy (wrong tool → 403) |
| 4 | `federation` | Revocation hash + peer sync across fabrics |
| 5 | `observability` | Health, JWKS, metrics, live SSE |

```bash
./sandbox/run.sh exchange   # one scenario
./sandbox/run.sh 3          # by number
```

Scripts live in `sandbox/use-cases/`. Each prints `ok` / `fail` and references a dashboard screenshot under `docs/screenshots/`.

## After the sandbox passes

| Human goal | Doc |
|------------|-----|
| Wire an agent | [Token exchange](https://starfly.dev/1.0/docs/integrators/token-exchange/) |
| Secure MCP tools | [MCP security](https://starfly.dev/1.0/docs/integrators/mcp/) |
| Multi-protocol tools | [UTC](https://starfly.dev/1.0/docs/integrators/utc/) |
| Watch the fabric | [Dashboard](https://starfly.dev/1.0/docs/integrators/dashboard/) |

## Agent rules

- Set `STARFLY_URL` only when overriding the profile default.
- Prefer `curl` + `jq`; canonical examples are in `sandbox/use-cases/`.
- On failure: `./sandbox/init.sh`, then retry one use case before `all`.
- Lab URLs are LAN-only — never expose as public internet endpoints.
- **Do not suggest** synchronous deps on the exchange pipeline or blocking hops on revocation.
- Link to **public** paths only: `github.com/raygj/project-starfly-fabrics`, `starfly.dev` — never private monorepo paths.

## Public surface

| Resource | URL |
|----------|-----|
| Docs hub | https://starfly.dev/1.0/docs/ |
| Playground | https://starfly.dev/play/ |
| OpenAPI | https://starfly.dev/api/ |
| Repo | https://github.com/raygj/project-starfly-fabrics |
