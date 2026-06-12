---
title: Getting started
description: Running PEP and first WIMSE JWT in 15 minutes — no cluster required.
---

**In about 15 minutes you will have a running Starfly fabric unit and your first scoped WIMSE JWT** — proof that exchange, policy, and signing work on your laptop before you wire agents or tools.

## What you'll prove

- Starfly boots in dev mode and answers health checks
- A platform credential exchanges for a WIMSE JWT with `aud`, `td`, and `exp`
- Metrics and live events stream from the PEP
- Sandbox scripts replay exchange, revocation, and MCP scenarios

No Kubernetes required for this path.

## Prerequisites

- Go 1.25+ (`go version`)
- curl and jq
- Make

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

- `using DEV lock` — data at rest is not encrypted (dev only)
- `policy loaded` — `policies/dev/exchange.rego`
- `HTTP server listening on :8693`

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

In dev mode, any parseable JWT is accepted against the synthetic `dev.local` [trust domain](/docs/docs/getting-started/concepts/trust-domains/).

## 6. Read the WIMSE JWT

Pipe `.access_token` through base64 decode on the payload segment, or use the sandbox:

```bash
./sandbox/init.sh
./sandbox/run.sh exchange
```

Key claims: `sub`, `aud`, `td` (trust domain), `exp`. Deeper dive: [exchange concepts](/docs/docs/getting-started/concepts/exchange/).

## 7. Metrics and live events

```bash
curl -s http://localhost:8693/metrics | grep starfly_exchange
curl -N http://localhost:8693/v1/events
```

These same streams power the [operations dashboard](/docs/docs/getting-started/integrators/dashboard/) when deployed.

## 8. Run the proof scripts

Five scenarios — no Go rebuild required against a running PEP:

```bash
./sandbox/run.sh all
```

Narrated demos:

```bash
./demos/01-token-exchange.sh
./demos/02-real-time-revocation.sh
./demos/03-confused-deputy.sh
```

Manifest and agent bootstrap: [`sandbox/`](/docs/docs/sandbox/) · [AGENTS.md](https://github.com/raygj/project-starfly-fabrics/blob/main/AGENTS.md)

## What's next

| Goal | Go here |
|------|---------|
| Vocabulary | [Glossary](/docs/docs/getting-started/glossary/) |
| Wire an agent | [Token exchange](/docs/docs/getting-started/integrators/token-exchange/) |
| MCP tool security | [MCP security](/docs/docs/getting-started/integrators/mcp/) |
| Multi-protocol tools | [UTC](/docs/docs/getting-started/integrators/utc/) |
| Playground UI | [starfly.dev/play](https://starfly.dev/play) |
| API contract | [OpenAPI](https://starfly.dev/api/) |

## Related

- [Documentation voice](/docs/docs/getting-started/voice/)
