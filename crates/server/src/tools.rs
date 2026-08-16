//! Tool implementations. Tools orchestrate provider calls and formatting;
//! they never parse chain data themselves (that is `cardano-mcp-decode`'s
//! job) and every chain-sourced string they emit passes through
//! `cardano-mcp-sanitize`.

pub mod inspect_address;
