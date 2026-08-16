# cardano-mcp

An [MCP](https://modelcontextprotocol.io) server, written in Rust, that gives
AI agents legible access to the Cardano blockchain. Every chain-sourced byte
is treated as attacker-writable and sanitized before it reaches a model.

**Status: early.** One tool ships — `inspect_address` — over an MCP stdio
server. More tools, and a self-hostable HTTP transport, are planned.

## Quickstart

1. Get a free Blockfrost project id (mainnet) at
   [blockfrost.io](https://blockfrost.io).
2. Build: `cargo build --release` (produces `target/release/cardano-mcp`).
3. Add the server to your MCP client. For example:

   ```json
   {
     "mcpServers": {
       "cardano": {
         "command": "/absolute/path/to/cardano-mcp",
         "env": { "BLOCKFROST_PROJECT_ID": "mainnet<your-key>" }
       }
     }
   }
   ```

To self-host the chain data instead of using hosted Blockfrost, point
`BLOCKFROST_BASE_URL` at your own [Dolos](https://github.com/txpipe/dolos)
node (no key needed).

The server speaks MCP over stdio. To exercise the tool without a client,
run it directly: `cardano-mcp inspect-address <address>`.

## Tools

- **`inspect_address`** — classify a Cardano address (network, key/script
  control, staking part) and report ADA balance, native assets with
  resolved names and CIP-14 fingerprints, lifetime transaction count, and
  staking/delegation state. Chain-sourced text is sanitized and wrapped in
  `⟪…⟫` delimiters marking it as unverified, attacker-writable data.

## Design

- **Read-only**: the default build contains no signing code and performs no
  off-chain URL fetches.
- **Self-hostable**: works against hosted Blockfrost or your own Dolos node.
- **Security-first**: all attacker-writable chain content is neutralized and
  delimited before it reaches a model. See [THREAT_MODEL.md](THREAT_MODEL.md).

## Documentation

| Document | Answers |
| --- | --- |
| [ARCHITECTURE.md](ARCHITECTURE.md) | How the system is built, and why this shape |
| [THREAT_MODEL.md](THREAT_MODEL.md) | What this defends against — and what it explicitly does not |
| [SECURITY.md](SECURITY.md) | How to report a vulnerability |
| [CONTRIBUTING.md](CONTRIBUTING.md) | How to contribute a change that will be accepted |

## License

Apache-2.0.
