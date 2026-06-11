# Vault OIDC secrets plugin (`providers/oidc-engine`)

> **Status:** Preview — operator-workspace plugin; public export pending.

## Why this exists

Obtain **IdP-native tokens** (Azure AD, Okta, Google, …) for workloads that already authenticate to a credential vault — when downstream APIs require that issuer, not fabric JWKS.

Optionally chain: IdP token → [Starfly exchange](https://starfly.dev/1.0/docs/integrators/token-exchange/) → WIMSE JWT for fabric governance.

## Documentation

- [Credential patterns — Vault OIDC](https://starfly.dev/1.0/docs/integrators/credential-patterns/#vault-oidc-plugin-preview)

## Code

Plugin source not in this export yet. This README reserves the path for doc links.
