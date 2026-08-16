//! Fuzz the sanitize boundary: arbitrary bytes in, and the output must
//! uphold the boundary's invariants — no panic, and no disallowed
//! character (nor a bare delimiter) ever present in the sanitized text.

#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let out = cardano_mcp_sanitize::bytes(data, 256);
    // The full boundary contract: no character the boundary rejects may
    // appear in the sanitized output (this catches category-arm mutants,
    // not just control characters).
    for c in out.text().chars() {
        assert!(!cardano_mcp_sanitize::is_rejected(c));
    }
});
