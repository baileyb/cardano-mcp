//! Chain-data decoding for `cardano-mcp`.
//!
//! Parses Cardano chain data and renders it into resolved, legible
//! structures. Every input is treated as attacker-controlled: see
//! `THREAT_MODEL.md` (F1, F2) at the repository root.
//!
//! Architectural invariant: this crate performs no I/O. Its `Cargo.toml`
//! contains no network, async-runtime, or filesystem dependencies, so the
//! invariant is enforced by the compiler, not by convention.

#![forbid(unsafe_code)]

pub mod address;
pub mod asset;
pub mod value;

/// Errors produced while decoding chain data.
#[derive(Debug, PartialEq, Eq, thiserror::Error)]
pub enum DecodeError {
    /// The input is not a recognizable Cardano address.
    #[error("not a recognizable Cardano address")]
    UnrecognizedAddress,
    /// An asset unit string is malformed (not `lovelace` and not
    /// `policy-hex ++ name-hex`).
    #[error("malformed asset unit")]
    MalformedUnit,
    /// An asset name exceeds the ledger's 32-byte maximum.
    #[error("asset name longer than 32 bytes")]
    OversizedAssetName,
    /// Internal encoding failure that should be unreachable with valid
    /// inputs; surfaced instead of panicking per the no-panic policy.
    #[error("internal encoding failure")]
    Encoding,
}
