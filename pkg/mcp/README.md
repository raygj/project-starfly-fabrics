# MCP security (`pkg/mcp`)

Register MCP tools, verify tool calls, and enforce audience binding on the PEP.

## Documentation

- [MCP integrator guide](https://starfly.dev/1.0/docs/integrators/mcp/)
- [Token exchange](https://starfly.dev/1.0/docs/integrators/token-exchange/)
- [OpenAPI — MCP](https://starfly.dev/api/operations/tags/mcp/)

## Layout

| Path | Role |
|------|------|
| `registry.go` | Tool registration and lookup |
| `middleware.go` | Verify pipeline on the PEP |
| `client.go` | MCP client helpers |

## Build

```bash
go test ./pkg/mcp/...
```
