# Sandbox

Proof scripts and manifest for local and lab Starfly fabrics.

## Why this exists

Run exchange, revocation, MCP, federation, and UTC scenarios against a live PEP — no custom integration code required. This is the fastest way to validate the fabric before wiring your agents.

## Documentation

- [Getting started](https://starfly.dev/1.0/docs/getting-started/)
- [AGENTS.md](../AGENTS.md) — Cursor / Claude bootstrap
- [Playground](https://starfly.dev/play/) — interactive wizard

## Run

```bash
./sandbox/init.sh          # once per machine
./sandbox/run.sh all       # all five use cases
./sandbox/run.sh exchange  # single scenario
```

Profiles and endpoints: `manifest.yaml`.
