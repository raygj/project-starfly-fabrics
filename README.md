# Starfly

**Non-human identity for the agentic fabric.**

Starfly issues and validates WIMSE-profile JWTs for agents, enforces delegation policy, and propagates revocation state across federated peers. It is the policy enforcement point of the fabric.

- **Site:** [starfly.dev](https://starfly.dev)
- **Docs:** rolling out on this repo and the site (Starlight)

## Repository

This is the **public home** for Starfly — source, docs, and the website. Exported releases land here.

```
public/           Website (static assets → starfly.dev)
sandbox/          Five use-case scripts + manifest.yaml
AGENTS.md         Agent bootstrap contract (Cursor, Claude, etc.)
docs/             Screenshots + documentation (Phase 0 → Starlight)
wrangler.jsonc    Cloudflare Workers config
```

## Sandbox

Five curl-driven proof use cases against a local or lab PEP:

```bash
./sandbox/init.sh
STARFLY_PROFILE=lab ./sandbox/run.sh all   # Talos lab (LAN)
```

- **Playground UI:** [starfly.dev/play](https://starfly.dev/play)
- **Manifest:** [`sandbox/manifest.yaml`](sandbox/manifest.yaml)
- **Agents:** [`AGENTS.md`](AGENTS.md)

## Develop

```bash
npm install
npx wrangler deploy    # deploy website to Cloudflare Workers
```

Hosting and custom domain: [`DEPLOY.md`](DEPLOY.md).

## License

Apache 2.0 — see [LICENSE](LICENSE).
