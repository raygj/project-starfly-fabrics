# Starfly

Public site for **[starfly.dev](https://starfly.dev)** — the non-human identity broker for the agentic fabric.

<<<<<<< HEAD

=======
This repository holds the **static website** only. Product source, docs, and the dashboard live in the private monorepo [`raygj/project-starfly`](https://github.com/raygj/project-starfly).

## What Starfly does

Starfly issues and validates WIMSE-profile JWTs for agents, enforces delegation policy, propagates revocation state across federated peers, and acts as the policy enforcement point for the fabric.

Documentation is rolling out in phases. This site is the Phase 1 placeholder; a full docs build (Starlight) will replace it on the same domain.

## Repository layout

```
public/           Static HTML (served via Cloudflare Workers assets)
wrangler.jsonc    Workers static-asset config
package.json      Wrangler dev dependency
```

## Hosting

Hosted on Cloudflare Workers. Canonical domain: **starfly.dev**.  
**starflyfabrics.com** redirects here.

Operators: see [`DEPLOY.md`](DEPLOY.md) for build and domain steps.

## License

See [LICENSE](LICENSE).
>>>>>>> 716e220 (docs(readme): public-facing README; move Cloudflare steps to DEPLOY.md)
