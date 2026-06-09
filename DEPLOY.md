# Deploy — Cloudflare Workers

Internal operator runbook for `project-starfly-fabrics`. Not required to view the site.

## Prerequisites

- GitHub repo linked to Cloudflare (**Workers & Pages → Git integration**)
- Cloudflare API token with Pages/Workers edit + zone DNS (for Terraform, optional)

## Dashboard (unified Workers app flow)

| Field | Value |
|---|---|
| Repository | `raygj/project-starfly-fabrics` |
| Project name | `project-starfly-fabrics` (must match `name` in `wrangler.jsonc`) |
| Build command | *(empty)* |
| Deploy command | `npm install && npx wrangler deploy` |

After first deploy: **Workers & Pages → project-starfly-fabrics → Domains** → add `starfly.dev`.

Default Workers URL: `project-starfly-fabrics.<account>.workers.dev`

## Local

```bash
npm install
npx wrangler deploy
```

## Terraform (DNS + redirect)

DNS and `starflyfabrics.com` → `starfly.dev` redirect are defined in the monorepo:

`communes/starfly/website/terraform/` on `raygj/project-starfly`

## Sync from monorepo

When updating the placeholder HTML, edit `communes/starfly/website/` in the monorepo, then copy `public/index.html` (and any assets) here and push.
