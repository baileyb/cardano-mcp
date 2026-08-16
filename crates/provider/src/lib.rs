//! Chain-data providers for `cardano-mcp`.
//!
//! Defines the narrow `ChainProvider` interface the server's tools consume,
//! and its backends (Blockfrost-compatible HTTP; a self-hosted Dolos node
//! serves the same API shape). Provider responses are semi-trusted: see
//! `THREAT_MODEL.md` (F5) at the repository root.

#![forbid(unsafe_code)]
