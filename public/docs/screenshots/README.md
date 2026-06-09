# Dashboard screenshots

Live captures from the Starfly operations dashboard on the Talos lab cluster (`fabric-alpha`).

| File | Tab |
|------|-----|
| `fabric-pulse.png` | Fabric Pulse — exchange rate, latency, active agents |
| `delegation.png` | Delegation chain graph |
| `mcp-security.png` | MCP tool calls and policy enforcement |
| `federation.png` | Cross-fabric revocation sync |
| `soul.png` | Agent behavioral profile |
| `trust-tree.png` | Trust domain hierarchy |

Captured 2026-06-09 from `http://192.168.1.98:30423`.

Each image maps to a sandbox use case — run `STARFLY_PROFILE=lab ./sandbox/run.sh all` and compare live API output to the dashboard view.
