# SPIFFE identity provider (`pkg/identity/spiffe`)

Validates SPIFFE X.509 SVIDs and JWT-SVIDs for token exchange.

## Documentation

- [Credential patterns — SPIFFE / SPIRE](https://starfly.dev/1.0/docs/integrators/credential-patterns/#spiffe--spire)
- [Trust domains](https://starfly.dev/1.0/docs/concepts/trust-domains/)
- [Token exchange](https://starfly.dev/1.0/docs/integrators/token-exchange/)

## Exchange

Use `subject_token_type`: `urn:starfly:token-type:spiffe-svid`

## Build

```bash
go test ./pkg/identity/spiffe/...
```
