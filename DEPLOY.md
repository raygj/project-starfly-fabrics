# Deploy — Cloudflare Workers

Operator runbook for hosting **starfly.dev** from this repository.

## Dashboard

| Field | Value |
|---|---|
| Repository | `raygj/project-starfly-fabrics` |
| Project name | `project-starfly-fabrics` (matches `name` in `wrangler.jsonc`) |
| Build command | *(empty)* |
| Deploy command | `npm install && npx wrangler deploy` |

After first deploy: **Workers & Pages → project-starfly-fabrics → Domains** → add `starfly.dev`.

## Local

```bash
npm install
npx wrangler deploy
```

## DNS

`starfly.dev` and `starflyfabrics.com` → `starfly.dev` redirect are managed via Cloudflare (Terraform or dashboard). This repo only ships the Worker assets.
