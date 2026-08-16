//! The sanitize boundary for `cardano-mcp`.
//!
//! Every chain-sourced value passes through this crate before leaving the
//! server: size and depth ceilings, control-character and ANSI-escape
//! stripping, unicode normalization, and data delimiting. No output path
//! may bypass it. See `THREAT_MODEL.md` (F1) at the repository root.
//!
//! Safe output types are constructible only through this boundary.

#![forbid(unsafe_code)]
