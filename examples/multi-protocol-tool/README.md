# Multi-protocol tool demo

> **Status:** Preview — runnable demo export pending.

## Why this exists

Prove UTC in one sitting: the same `search` tool answers MCP JSON-RPC and plain REST with the same WIMSE token — no duplicate registration, no protocol-specific policy.

## Documentation

- [UTC integrator guide](https://starfly.dev/1.0/docs/integrators/utc/)
- [Middleware source](../../pkg/toolcall/)

## What it will show

| Client | Wire shape | Same outcome |
|--------|------------|--------------|
| MCP | `tools/call` JSON-RPC | Verified identity + tool result |
| HTTP | `GET /api/search` + Bearer | Same subject, same audit fields |

## Code

Not in the public export yet. Use [`pkg/toolcall`](../../pkg/toolcall/) to wire middleware today; this directory will gain `main.go` and `demo.sh` when the demo is exported.
