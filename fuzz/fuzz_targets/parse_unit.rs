//! Fuzz `decode::asset::parse_unit`: arbitrary unit strings must never
//! panic or hang, only return `Ok`/`Err`.

#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    if let Ok(s) = core::str::from_utf8(data) {
        let _ = cardano_mcp_decode::asset::parse_unit(s);
    }
});
