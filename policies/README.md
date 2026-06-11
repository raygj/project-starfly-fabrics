# OPA policies (`policies/`)

Rego bundles evaluated on the exchange and signal paths.

## Documentation

- [Exchange concepts](https://starfly.dev/1.0/docs/concepts/exchange/)
- [Revocation concepts](https://starfly.dev/1.0/docs/concepts/revocation/)

## Layout

| Path | Role |
|------|------|
| `*.rego` | Production policy modules |
| `dev/` | Permissive policies for `--dev` mode |

## Test

```bash
go test ./pkg/policy/...
```
