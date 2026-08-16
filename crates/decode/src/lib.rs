//! Chain-data decoding for `cardano-mcp`.
//!
//! This crate parses Cardano chain data (CBOR, datums, metadata) and renders
//! it into resolved, human-readable structures. It treats every input as
//! attacker-controlled: see `THREAT_MODEL.md` (F1, F2) at the repository
//! root.
//!
//! Architectural invariant: this crate performs no I/O. Its `Cargo.toml`
//! contains no network, async-runtime, or filesystem dependencies, so the
//! invariant is enforced by the compiler, not by convention.

#![forbid(unsafe_code)]
