# Starfly documentation (v1)

Diátaxis-shaped docs for evaluators, integrators, and operators.

| Quadrant | Pages |
|----------|-------|
| **Tutorial** | [Getting started](getting-started.md) |
| **Explanation** | [Glossary](glossary.md) · [Trust domains](concepts/trust-domains.md) · [Exchange](concepts/exchange.md) · [Revocation](concepts/revocation.md) |
| **How-to** | [Token exchange](integrators/token-exchange.md) · [MCP integration](integrators/mcp.md) · [Sandbox](../sandbox/manifest.yaml) |
| **Reference** | [OpenAPI](../api/openapi.yaml) · [AGENTS.md](../AGENTS.md) · [llms.txt](../public/llms.txt) |

## Quick paths

- **First exchange in 15 minutes** → [getting-started.md](getting-started.md)
- **Agent / Cursor bootstrap** → [AGENTS.md](../AGENTS.md) + `./sandbox/run.sh all`
- **Interactive wizard** → [starfly.dev/play](https://starfly.dev/play)
- **Dashboard screenshots** → [screenshots/](screenshots/)

## Sacred invariants

Document these before changing architecture:

1. **124ns exchange hot path** — no new synchronous dependencies on the exchange pipeline.
2. **30ms revocation kill switch** — propagation latency is not negotiable.
