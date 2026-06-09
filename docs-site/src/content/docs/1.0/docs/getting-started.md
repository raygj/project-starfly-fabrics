---
title: Getting started
slug: 1.0/docs/getting-started
---

# Getting started

Clone to first WIMSE JWT exchange in under 15 minutes.

## Prerequisites

* Go 1.25+ (`go version`)
* curl and jq
* Make

No Kubernetes cluster required for dev mode.

## 1. Clone and build

```bash
git clone https://github.com/raygj/project-starfly-fabrics.git
cd project-starfly-fabrics
make build-dev
```

Produces `bin/starfly` — single binary, dev-tagged build.

## 2. Start dev mode

```bash
STARFLY_STORAGE_PATH=/tmp/starfly-dev \
STARFLY_POLICY_BUNDLE_PATH=policies/dev \
./bin/starfly --dev
```

Boot banner highlights:

* `using DEV lock` — data at rest is not encrypted (dev only)
* `policy loaded` — `policies/dev/exchange.rego`
* `HTTP server listening on :8693`

## 3. Health check

```bash
curl -s http://localhost:8693/v1/sys/health | jq
```

```json
{
  "initialized": true,
  "locked": false,
  "version": "dev",
  "unit_id": "…"
}
```

## 4. JWKS

```bash
curl -s http://localhost:8693/v1/identity/jwks | jq
```

Downstream services verify WIMSE JWTs against this endpoint (`kid: starfly-dev-1` in dev).

## 5. First exchange

```bash
curl -s -X POST http://localhost:8693/v1/exchange/token \
  -H "Content-Type: application/json" \
  -d '{
    "grant_type": "urn:ietf:params:oauth:grant-type:token-exchange",
    "subject_token": "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJteS1hcHAiLCJpc3MiOiJkZXYiLCJleHAiOjk5OTk5OTk5OTl9.stub",
    "subject_token_type": "urn:ietf:params:oauth:token-type:jwt",
    "audience": "https://api.target.example.com",
    "scope": "read:data"
  }' | jq
```

In dev mode, any parseable JWT is accepted against the synthetic `dev.local` [trust domain](concepts/trust-domains.md).

## 6. Decode the WIMSE JWT

Pipe `.access_token` through base64 decode on the payload segment, or use the [sandbox](../sandbox/run.sh):

```bash
./sandbox/init.sh
./sandbox/run.sh exchange
```

Key claims: `sub`, `aud`, `td` (trust domain), `exp`.

## 7. Metrics and live events

```bash
curl -s http://localhost:8693/metrics | grep starfly_exchange
curl -N http://localhost:8693/v1/events
```

## 8. Sandbox use cases

Five proof scripts (no Go rebuild required against a running PEP):

```bash
./sandbox/run.sh all
```

Or interactive demos with narration:

```bash
./demos/01-token-exchange.sh
./demos/02-real-time-revocation.sh
./demos/03-confused-deputy.sh
```

## What's next

| Goal | Read |
|------|------|
| Terms and vocabulary | [glossary.md](glossary.md) |
| Integrate an agent | [integrators/token-exchange.md](integrators/token-exchange.md) |
| MCP tool security | [integrators/mcp.md](integrators/mcp.md) |
| Playground UI | [starfly.dev/play](https://starfly.dev/play) |
| API contract | [api/openapi.yaml](../api/openapi.yaml) |
