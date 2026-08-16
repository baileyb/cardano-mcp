//! `cardano-mcp` server binary: MCP wiring, tools, transport, and
//! configuration. Tools orchestrate I/O but never parse chain data; parsing
//! belongs to `cardano-mcp-decode` and all output passes through
//! `cardano-mcp-sanitize`. See `ARCHITECTURE.md` at the repository root.

#![forbid(unsafe_code)]

fn main() {
    // Scaffold stage: the MCP server is not yet implemented.
    println!(
        "cardano-mcp {} (pre-release scaffold)",
        env!("CARGO_PKG_VERSION")
    );
}
