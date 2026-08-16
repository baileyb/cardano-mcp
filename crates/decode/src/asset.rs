//! Asset identity: unit parsing and CIP-14 fingerprints.
//!
//! Token names are attacker-writable and non-unique; identity is only
//! `policy id + asset name`. The CIP-14 fingerprint (`asset1…`) is the
//! standard human-comparable digest of that pair, and responses surface it
//! alongside any display name. See `THREAT_MODEL.md` (F1).

use crate::DecodeError;
use pallas_crypto::hash::Hasher;

/// Ledger maximum length of an asset name, in bytes.
pub const MAX_ASSET_NAME_BYTES: usize = 32;

const POLICY_HEX_LEN: usize = 56;

/// A parsed asset unit as returned by Blockfrost-compatible providers:
/// either plain lovelace or a native asset.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Unit {
    /// The native currency (1 ADA = 1,000,000 lovelace).
    Lovelace,
    /// A native asset.
    Asset(AssetId),
}

/// A native asset's identity.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AssetId {
    /// The minting policy id (28 bytes).
    pub policy: Vec<u8>,
    /// The raw asset name (0–32 bytes; arbitrary, attacker-writable).
    pub name: Vec<u8>,
}

impl AssetId {
    /// The policy id as lowercase hex.
    #[must_use]
    pub fn policy_hex(&self) -> String {
        hex::encode(&self.policy)
    }

    /// The CIP-14 fingerprint (`asset1…`) of this asset:
    /// bech32("asset", blake2b-160(policy ‖ name)).
    ///
    /// # Errors
    ///
    /// Returns [`DecodeError::Encoding`] only on internal bech32 failure,
    /// which is unreachable with a valid human-readable part.
    pub fn fingerprint(&self) -> Result<String, DecodeError> {
        let mut hasher = Hasher::<160>::new();
        hasher.input(&self.policy);
        hasher.input(&self.name);
        let digest = hasher.finalize();
        let hrp = bech32::Hrp::parse("asset").map_err(|_| DecodeError::Encoding)?;
        bech32::encode::<bech32::Bech32>(hrp, digest.as_ref()).map_err(|_| DecodeError::Encoding)
    }
}

/// Parse a provider `unit` string: `"lovelace"` or
/// `policy-hex (56 chars) ++ asset-name-hex (0–64 chars)`.
///
/// # Errors
///
/// Returns [`DecodeError::MalformedUnit`] for anything that is neither
/// form, and [`DecodeError::OversizedAssetName`] when the name exceeds the
/// ledger's 32-byte maximum.
pub fn parse_unit(unit: &str) -> Result<Unit, DecodeError> {
    if unit == "lovelace" {
        return Ok(Unit::Lovelace);
    }
    let policy_hex = unit
        .get(..POLICY_HEX_LEN)
        .ok_or(DecodeError::MalformedUnit)?;
    let name_hex = unit
        .get(POLICY_HEX_LEN..)
        .ok_or(DecodeError::MalformedUnit)?;
    // Validate the name length before allocating (each byte is 2 hex
    // chars), so an over-long unit is rejected without decoding it.
    if name_hex.len() > MAX_ASSET_NAME_BYTES * 2 {
        return Err(DecodeError::OversizedAssetName);
    }
    let policy = hex::decode(policy_hex).map_err(|_| DecodeError::MalformedUnit)?;
    let name = hex::decode(name_hex).map_err(|_| DecodeError::MalformedUnit)?;
    Ok(Unit::Asset(AssetId { policy, name }))
}

#[cfg(test)]
#[allow(
    clippy::unwrap_used,
    clippy::panic,
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects,
    reason = "tests panic to fail; proptest-generated code may index and do arithmetic"
)]
mod tests {
    use super::*;

    fn asset(policy_hex: &str, name_hex: &str) -> AssetId {
        AssetId {
            policy: hex::decode(policy_hex).unwrap_or_default(),
            name: hex::decode(name_hex).unwrap_or_default(),
        }
    }

    /// The complete CIP-14 test-vector set.
    #[test]
    fn cip14_fingerprint_vectors() {
        let vectors = [
            (
                "7eae28af2208be856f7a119668ae52a49b73725e326dc16579dcc373",
                "",
                "asset1rjklcrnsdzqp65wjgrg55sy9723kw09mlgvlc3",
            ),
            (
                "7eae28af2208be856f7a119668ae52a49b73725e326dc16579dcc37e",
                "",
                "asset1nl0puwxmhas8fawxp8nx4e2q3wekg969n2auw3",
            ),
            (
                "1e349c9bdea19fd6c147626a5260bc44b71635f398b67c59881df209",
                "",
                "asset1uyuxku60yqe57nusqzjx38aan3f2wq6s93f6ea",
            ),
            (
                "7eae28af2208be856f7a119668ae52a49b73725e326dc16579dcc373",
                "504154415445",
                "asset13n25uv0yaf5kus35fm2k86cqy60z58d9xmde92",
            ),
            (
                "1e349c9bdea19fd6c147626a5260bc44b71635f398b67c59881df209",
                "504154415445",
                "asset1hv4p5tv2a837mzqrst04d0dcptdjmluqvdx9k3",
            ),
            (
                "1e349c9bdea19fd6c147626a5260bc44b71635f398b67c59881df209",
                "7eae28af2208be856f7a119668ae52a49b73725e326dc16579dcc373",
                "asset1aqrdypg669jgazruv5ah07nuyqe0wxjhe2el6f",
            ),
            (
                "7eae28af2208be856f7a119668ae52a49b73725e326dc16579dcc373",
                "1e349c9bdea19fd6c147626a5260bc44b71635f398b67c59881df209",
                "asset17jd78wukhtrnmjh3fngzasxm8rck0l2r4hhyyt",
            ),
            (
                "7eae28af2208be856f7a119668ae52a49b73725e326dc16579dcc373",
                "0000000000000000000000000000000000000000000000000000000000000000",
                "asset1pkpwyknlvul7az0xx8czhl60pyel45rpje4z8w",
            ),
        ];
        for (policy, name, expected) in vectors {
            let got = asset(policy, name).fingerprint().unwrap_or_default();
            assert_eq!(got, expected, "policy={policy} name={name}");
        }
    }

    #[test]
    fn parses_lovelace_unit() {
        assert_eq!(parse_unit("lovelace"), Ok(Unit::Lovelace));
    }

    #[test]
    fn parses_policy_plus_name() {
        let unit = "7eae28af2208be856f7a119668ae52a49b73725e326dc16579dcc373504154415445";
        match parse_unit(unit) {
            Ok(Unit::Asset(a)) => {
                assert_eq!(
                    a.policy_hex(),
                    "7eae28af2208be856f7a119668ae52a49b73725e326dc16579dcc373"
                );
                assert_eq!(a.name, b"PATATE");
            }
            other => panic!("unexpected: {other:?}"),
        }
    }

    #[test]
    fn parses_empty_name_bare_policy() {
        // A 56-char unit with no name portion is a valid asset.
        let policy = "7eae28af2208be856f7a119668ae52a49b73725e326dc16579dcc373";
        match parse_unit(policy) {
            Ok(Unit::Asset(a)) => assert!(a.name.is_empty()),
            other => panic!("unexpected: {other:?}"),
        }
    }

    #[test]
    fn accepts_name_at_exactly_the_max_length() {
        // Boundary: a 32-byte name (64 hex chars) is legal and must parse.
        let unit = format!(
            "7eae28af2208be856f7a119668ae52a49b73725e326dc16579dcc373{}",
            "ab".repeat(MAX_ASSET_NAME_BYTES)
        );
        match parse_unit(&unit) {
            Ok(Unit::Asset(a)) => assert_eq!(a.name.len(), MAX_ASSET_NAME_BYTES),
            other => panic!("unexpected: {other:?}"),
        }
    }

    #[test]
    fn rejects_short_and_non_hex_units() {
        assert_eq!(parse_unit("deadbeef"), Err(DecodeError::MalformedUnit));
        assert_eq!(
            parse_unit(&"zz".repeat(28)),
            Err(DecodeError::MalformedUnit)
        );
    }

    #[test]
    fn rejects_oversized_asset_name() {
        let unit = format!(
            "7eae28af2208be856f7a119668ae52a49b73725e326dc16579dcc373{}",
            "00".repeat(33)
        );
        assert_eq!(parse_unit(&unit), Err(DecodeError::OversizedAssetName));
    }

    proptest::proptest! {
        /// Round-trip: any 28-byte policy + 0..=32-byte name encodes to a
        /// unit string that parses back to the identical `AssetId`.
        #[test]
        fn parse_unit_roundtrips(
            policy in proptest::collection::vec(proptest::num::u8::ANY, 28),
            name in proptest::collection::vec(proptest::num::u8::ANY, 0..=MAX_ASSET_NAME_BYTES),
        ) {
            let unit = format!("{}{}", hex::encode(&policy), hex::encode(&name));
            match parse_unit(&unit) {
                Ok(Unit::Asset(a)) => {
                    proptest::prop_assert_eq!(a.policy, policy);
                    proptest::prop_assert_eq!(a.name, name);
                }
                other => proptest::prop_assert!(false, "unexpected: {:?}", other),
            }
        }
    }
}
