# Universal Tool-Calling Layer (`pkg/toolcall`)

Protocol-agnostic middleware: normalize any tool call, verify one WIMSE JWT, enforce one policy surface.

## Documentation

- [UTC integrator guide](https://starfly.dev/1.0/docs/integrators/utc/)
- [MCP security](https://starfly.dev/1.0/docs/integrators/mcp/)

## Layout

| Path | Role |
|------|------|
| `middleware.go` | Mount on your tool server |
| `verifier.go` | Token, audience, revocation gate |
| `adapters/mcp` | JSON-RPC `tools/call` |
| `adapters/httpgeneric` | REST + Bearer |
| `adapters/a2a` | Agent-to-agent tasks |

## Demo

Multi-protocol demo server: [examples/multi-protocol-tool/](../../examples/multi-protocol-tool/) (Preview).

## Build

```bash
go test ./pkg/toolcall/...
```
