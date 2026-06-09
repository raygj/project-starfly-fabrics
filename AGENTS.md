# Starfly Agent Guide

You are working with the **Starfly sandbox** — a minimal, manifest-driven path from bootstrap to five proof use cases.

## Read first

1. `sandbox/manifest.yaml` — profiles, use cases, screenshot map (source of truth)
2. `docs/getting-started.md` — build and run dev mode
3. `docs/glossary.md` — trust domain vs audience (do not conflate)
4. `public/llms.txt` — full doc index

Do not guess endpoints or invent curl paths. The manifest wins.

## Bootstrap

```bash
# 1. Pick a profile
export STARFLY_PROFILE=local   # laptop: ./bin/starfly --dev on :8693
export STARFLY_PROFILE=lab     # Talos lab fabric-sandbox (LAN)
export STARFLY_PROFILE=personal  # requires STARFLY_URL

# 2. Verify PEP is up
./sandbox/init.sh

# 3. Run use cases
./sandbox/run.sh all
```

### Profile notes

| Profile | URL | When to use |
|---------|-----|-------------|
| `local` | `http://localhost:8693` | Personal sandbox — full dev-mode surface |
| `lab` | `http://192.168.1.98:30095` | Shared Talos cluster; LAN/VPN only |
| `personal` | `$STARFLY_URL` | Operator's own Helm release |

**Local bootstrap** (if nothing is running):

```bash
git clone https://github.com/starfly-fabrics/starfly.git
cd starfly && make build
STARFLY_STORAGE_PATH=/tmp/starfly-dev STARFLY_POLICY_BUNDLE_PATH=policies/dev ./bin/starfly --dev
```

## Use cases (run in order)

| # | ID | Script | Proves |
|---|-----|--------|--------|
| 1 | `exchange` | `sandbox/use-cases/01-exchange.sh` | RFC 8693 token exchange → WIMSE JWT |
| 2 | `revocation` | `sandbox/use-cases/02-revocation.sh` | CAEP kill switch denies revoked identity |
| 3 | `mcp` | `sandbox/use-cases/03-mcp-confused-deputy.sh` | MCP audience binding blocks wrong tool |
| 4 | `federation` | `sandbox/use-cases/04-federation.sh` | Revocation hash + peer sync metrics |
| 5 | `observability` | `sandbox/use-cases/05-observability.sh` | Health, JWKS, metrics, SSE |

Run individually: `./sandbox/run.sh exchange` or `./sandbox/run.sh 3`

Each use case prints `ok` / `fail` lines and points at a dashboard screenshot under `docs/screenshots/`.

## Agent rules

- Set `STARFLY_URL` only when overriding the profile default.
- Prefer `curl` + `jq` — scripts in `sandbox/use-cases/` are the canonical examples.
- On failure: run `./sandbox/init.sh`, then retry one use case before `all`.
- Do not expose lab URLs as public internet endpoints; lab is LAN-only unless tunneled.
- Sacred invariants (document, do not violate in suggestions):
  - **124ns exchange hot path** — no new sync deps on exchange pipeline
  - **30ms revocation kill switch** — propagation latency is not negotiable

## Public docs surface

- Site: https://starfly.dev
- Screenshots: `docs/screenshots/`
- Future in-frame UI: `starfly.dev/play` will render this same manifest
