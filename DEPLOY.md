# Deploy — Cloudflare Workers

Operator runbook for **starfly.dev**.

## Architecture

| Piece | Path | Output |
|-------|------|--------|
| Starlight docs | `docs-site/` | `docs-site/dist/` (Pagefind search, v1.0, OpenAPI, Terraform subsite) |
| Landing + play | `docs-site/public/` | Copied to dist root on build |
| Wrangler | `wrangler.jsonc` | Serves `docs-site/dist/` |

## Deploy

### CI (main branch)

Pushes to `main` run `.github/workflows/ci.yml` — build tests, then `npm run deploy` to **starfly.dev**.

**One-time setup:** add repository secret `CLOUDFLARE_API_TOKEN`.

| Token | Use |
|-------|-----|
| **CI token** | GitHub Actions — Workers Scripts Edit + Account Read, **no IP restriction** |
| **Local 8hr token** | Laptop `wrangler deploy` only — IP-filtered tokens fail in CI with error `9109` |

Create the CI token in Cloudflare Dashboard → My Profile → API Tokens → Create Token → Edit Cloudflare Workers template.

### Manual

```bash
npm install                 # wrangler at repo root
cd docs-site && npm ci && cd ..
npm run deploy              # build Starlight + wrangler deploy
```

Custom domain: **Workers & Pages → project-starfly-fabrics → Domains** → `starfly.dev`.

## Observability

Workers Logs are enabled in `wrangler.jsonc` (`observability.logs` — persist + invocation logs). View in **Workers & Pages → project-starfly-fabrics → Logs**. Top-level `observability.enabled` stays `false`; logging is driven by the nested `logs` block (matches dashboard config).

## Maintainer exports (private monorepo)

```bash
# Starfly service slice
communes/starfly/scripts/export-public-min.sh
rsync -a /tmp/export-starfly-min/ /path/to/project-starfly-fabrics/ --exclude LICENSE

# Terraform provider
communes/starfly/scripts/export-terraform-provider.sh
# writes to DEST=/path/to/project-starfly-fabrics/terraform-provider
```

Then update docs in `docs-site/src/content/docs/` if needed, commit, `npm run deploy`.

## Versioning

Docs use [starlight-versions](https://starlight-versions.vercel.app/). v1.0 is archived at `/1.0/…`. Current editable docs live at `/docs/…` until the next version is cut.

## DNS

`starfly.dev` and `starflyfabrics.com` redirect — Cloudflare Terraform or dashboard. This repo ships Worker assets only.
