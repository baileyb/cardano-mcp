//! Fuzz `decode::address::classify`: arbitrary address strings must never
//! panic (including inside the underlying bech32/base58 parsers).

#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    if let Ok(s) = core::str::from_utf8(data) {
        let _ = cardano_mcp_decode::address::classify(s);
        let _ = cardano_mcp_decode::address::is_stake_address(s);
        let _ = cardano_mcp_decode::address::derive_stake_address(s);
    }
});
