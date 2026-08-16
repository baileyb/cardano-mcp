# cardano-mcp

An [MCP](https://modelcontextprotocol.io) server, written in Rust, that gives
AI agents legible access to the Cardano blockchain: decoded transactions,
resolved token metadata, governance state — served as a small set of
question-shaped tools, with every chain-sourced byte treated as hostile
input.

**Status: pre-release scaffold.** The workspace, standards, and security
posture exist; the tools do not yet. Nothing here is usable — this notice
will change when that does.

## What this will be

- Read-only chain intelligence: inspect addresses, transactions, assets,
  stake pools, and live governance in plain language
- Self-hostable end to end: works against a hosted Blockfrost-compatible
  API or your own [Dolos](https://github.com/txpipe/dolos) data node
- Security-first by construction: the default build contains no signing
  code, performs no off-chain URL fetches, and sanitizes all
  attacker-writable chain content before it reaches a model

Planned: a five-minute quickstart will appear here when the first tools
ship.

## Documentation

| Document | Answers |
| --- | --- |
| [ARCHITECTURE.md](ARCHITECTURE.md) | How the system is built, and why this shape |
| [THREAT_MODEL.md](THREAT_MODEL.md) | What this defends against — and what it explicitly does not |
| [SECURITY.md](SECURITY.md) | How to report a vulnerability |
| [CONTRIBUTING.md](CONTRIBUTING.md) | How to contribute a change that will be accepted |

## License

Apache-2.0.
