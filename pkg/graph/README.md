# Starfly Graph (`pkg/graph`)

> **Status:** Preview — integrator docs live; graph service export pending.

## Why this exists

Turn fabric events into a queryable identity graph: who exchanged, who delegated, what was revoked, which tools were called — without adding latency to token exchange or revocation.

## Documentation

- [Starfly Graph integrator guide](https://starfly.dev/1.0/docs/integrators/starfly-graph/)
- Design-time counterpart: [CALM Forge](https://github.com/raygj/project-calm-forge)

## Query surfaces (when deployed)

- MCP tools: `query_runtime`, `query_blast_radius`, `query_lineage`, …
- REST: `GET /v1/graph/agents`, `/stats`, read-only Cypher

## Code

NATS → FalkorDB consumer and store packages will land here on export. See [cmd/starfly-graph](../../cmd/starfly-graph/).
