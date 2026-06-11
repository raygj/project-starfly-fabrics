# Vault OIDC secrets plugin (`providers/oidc-engine`)

> **Status:** Preview — operator-workspace plugin; public export pending.

## Why this exists

Two vault patterns for the fabric:

1. **PEP / PDP** — One Sentinel rule calls OPA; Vault issues scoped agent credentials or denies. See [Vault PEP / PDP](https://starfly.dev/1.0/docs/integrators/vault-pep-pdp/).
2. **OIDC bridge** — Obtain IdP-native tokens (Azure AD, Okta, Google) when downstream APIs require that issuer.

Optionally chain: vault token → [Starfly exchange](https://starfly.dev/1.0/docs/integrators/token-exchange/) → WIMSE JWT.

## Documentation

- [Vault as PEP with external PDP](https://starfly.dev/1.0/docs/integrators/vault-pep-pdp/)
- [Credential patterns — Vault OIDC](https://starfly.dev/1.0/docs/integrators/credential-patterns/#vault-oidc-plugin-preview)

## Code

Plugin source not in this export yet. This README reserves the path for doc links.
