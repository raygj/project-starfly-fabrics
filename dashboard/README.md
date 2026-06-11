# Operations dashboard

> **Status:** Preview — docs and screenshots live; app export pending.

## Why this exists

Watch exchange rate, revocation cascade, federation health, and MCP denials in real time — read-only, off the exchange and revocation hot paths. If the dashboard is down, the fabric keeps running; you lose visibility, not security.

## Documentation

- [Dashboard integrator guide](https://starfly.dev/1.0/docs/integrators/dashboard/)
- [Playground screenshots](https://starfly.dev/play/)

## Views (when deployed)

| Tab | What you get |
|-----|----------------|
| Fabric Pulse | Live SSE + exchange metrics |
| Delegation | Depth and blast-radius denials |
| MCP Security | Per-tool verification |
| Federation | Peer health and CAEP cascade |
| Soul | Manifest timeline |
| Trust Tree | Trust domain hierarchy |

## Code

Next.js app not in this export yet. Deploy via Helm (`dashboard.enabled=true`) when the dashboard slice is published here.
