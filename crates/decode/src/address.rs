//! Address classification: what kind of address is this, on which
//! network, and are its credentials keys or scripts?

use crate::DecodeError;
use pallas_addresses::{
    Address, ByronAddress, Network, ShelleyDelegationPart, ShelleyPaymentPart, StakePayload,
};

/// Which network an address belongs to.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NetworkKind {
    /// Cardano mainnet.
    Mainnet,
    /// A public or private test network.
    Testnet,
    /// A network with an unrecognized discriminator.
    Other,
}

/// Classification of a parsed address.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AddressKind {
    /// A Shelley-era payment address.
    Payment {
        /// True when the payment credential is a script hash (funds are
        /// controlled by on-chain logic, not a wallet key).
        payment_is_script: bool,
        /// True when the address carries a staking credential.
        has_stake_part: bool,
        /// True when the staking credential is a script hash.
        stake_is_script: bool,
        /// True when the staking part is a (Conway-deprecated) pointer,
        /// which has no directly-derivable reward address.
        stake_is_pointer: bool,
    },
    /// A stake (reward) address.
    Stake {
        /// True when the staking credential is a script hash.
        is_script: bool,
    },
    /// A legacy Byron-era address (no staking, no scripts).
    Byron,
}

/// A classified address.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AddressReport {
    /// The network the address belongs to.
    pub network: NetworkKind,
    /// What kind of address this is.
    pub kind: AddressKind,
}

fn network_kind(network: Network) -> NetworkKind {
    match network {
        Network::Mainnet => NetworkKind::Mainnet,
        Network::Testnet => NetworkKind::Testnet,
        Network::Other(_) => NetworkKind::Other,
    }
}

/// Classify a Cardano address given in its canonical text form (bech32
/// for Shelley/stake addresses, base58 for Byron).
///
/// The input must be *canonical*: it must equal the re-encoding of the
/// address it parses to. `pallas` discards the bech32 human-readable part
/// (HRP) on decode, and the HRP charset includes URL metacharacters
/// (`/`, `?`, `#`), so without this check a crafted HRP would classify as
/// a valid address and could then be reused in a request path
/// (`THREAT_MODEL.md` F3). Canonicalization rejects that, non-lowercase
/// bech32, and any other non-canonical encoding.
///
/// # Errors
///
/// Returns [`DecodeError::UnrecognizedAddress`] when the input parses as
/// neither, or parses but is not its own canonical encoding.
pub fn classify(input: &str) -> Result<AddressReport, DecodeError> {
    if let Ok(address) = Address::from_bech32(input)
        && address.to_bech32().ok().as_deref() == Some(input)
    {
        return Ok(classify_parsed(&address));
    }
    if let Ok(byron) = ByronAddress::from_base58(input)
        && byron.to_base58() == input
    {
        return Ok(AddressReport {
            network: NetworkKind::Other,
            kind: AddressKind::Byron,
        });
    }
    Err(DecodeError::UnrecognizedAddress)
}

/// True when `input` is a canonical, well-formed stake (reward) address.
#[must_use]
pub fn is_stake_address(input: &str) -> bool {
    matches!(
        classify(input),
        Ok(AddressReport {
            kind: AddressKind::Stake { .. },
            ..
        })
    )
}

/// Derive the canonical bech32 reward address associated with a Shelley
/// payment address that carries a staking part. Returns `None` for
/// enterprise (no stake part), stake, and Byron addresses. The result is
/// canonical and charset-safe, so it can be reused in a request path
/// without further validation.
#[must_use]
pub fn derive_stake_address(input: &str) -> Option<String> {
    let Ok(Address::Shelley(shelley)) = Address::from_bech32(input) else {
        return None;
    };
    let stake = pallas_addresses::StakeAddress::try_from(shelley).ok()?;
    stake.to_bech32().ok()
}

fn classify_parsed(address: &Address) -> AddressReport {
    match address {
        Address::Shelley(shelley) => {
            let delegation = shelley.delegation();
            AddressReport {
                network: network_kind(shelley.network()),
                kind: AddressKind::Payment {
                    payment_is_script: matches!(shelley.payment(), ShelleyPaymentPart::Script(_)),
                    has_stake_part: !matches!(delegation, ShelleyDelegationPart::Null),
                    stake_is_script: matches!(delegation, ShelleyDelegationPart::Script(_)),
                    stake_is_pointer: matches!(delegation, ShelleyDelegationPart::Pointer(..)),
                },
            }
        }
        Address::Stake(stake) => AddressReport {
            network: network_kind(stake.network()),
            kind: AddressKind::Stake {
                is_script: matches!(stake.payload(), StakePayload::Script(_)),
            },
        },
        Address::Byron(_) => AddressReport {
            network: NetworkKind::Other,
            kind: AddressKind::Byron,
        },
    }
}

#[cfg(test)]
#[allow(
    clippy::unwrap_used,
    reason = "tests fail by panicking; that is their job"
)]
mod tests {
    use super::*;

    // Canonical CIP-19 test vectors, one per address shape.
    const MAINNET_PAYMENT: &str = "addr1qx2fxv2umyhttkxyxp8x0dlpdt3k6cwng5pxj3jhsydzer3n0d3vllmyqwsx5wktcd8cc3sq835lu7drv2xwl2wywfgse35a3x";
    const MAINNET_STAKE: &str = "stake1uyehkck0lajq8gr28t9uxnuvgcqrc6070x3k9r8048z8y5gh6ffgw";
    const TESTNET_PAYMENT: &str = "addr_test1qz2fxv2umyhttkxyxp8x0dlpdt3k6cwng5pxj3jhsydzer3n0d3vllmyqwsx5wktcd8cc3sq835lu7drv2xwl2wywfgs68faae";
    const TESTNET_STAKE: &str = "stake_test1uqehkck0lajq8gr28t9uxnuvgcqrc6070x3k9r8048z8y5gssrtvn";
    const MAINNET_SCRIPT_PAYMENT: &str = "addr1z8phkx6acpnf78fuvxn0mkew3l0fd058hzquvz7w36x4gten0d3vllmyqwsx5wktcd8cc3sq835lu7drv2xwl2wywfgs9yc0hh";
    const MAINNET_ENTERPRISE: &str = "addr1vx2fxv2umyhttkxyxp8x0dlpdt3k6cwng5pxj3jhsydzers66hrl8";
    // Byron base58 vector (from pallas-addresses' own test corpus).
    const BYRON: &str = "Ae2tdPwUPEZLs4HtbuNey7tK4hTKrwNwYtGqp7bDfCy2WdR3P6735W5Yfpe";
    // Type-4 pointer address (payment key + pointer delegation), CIP-19.
    const MAINNET_POINTER: &str =
        "addr1gx2fxv2umyhttkxyxp8x0dlpdt3k6cwng5pxj3jhsydzer5pnz75xxcrzqf96k";

    #[test]
    fn mainnet_payment_with_key_stake_part() {
        let report = classify(MAINNET_PAYMENT).unwrap();
        assert_eq!(report.network, NetworkKind::Mainnet);
        assert_eq!(
            report.kind,
            AddressKind::Payment {
                payment_is_script: false,
                has_stake_part: true,
                stake_is_script: false,
                stake_is_pointer: false,
            }
        );
    }

    #[test]
    fn testnet_payment_reports_testnet() {
        let report = classify(TESTNET_PAYMENT).unwrap();
        assert_eq!(report.network, NetworkKind::Testnet);
        assert!(matches!(report.kind, AddressKind::Payment { .. }));
    }

    #[test]
    fn script_payment_credential_is_flagged() {
        let report = classify(MAINNET_SCRIPT_PAYMENT).unwrap();
        assert!(matches!(
            report.kind,
            AddressKind::Payment {
                payment_is_script: true,
                ..
            }
        ));
    }

    #[test]
    fn enterprise_address_has_no_stake_part() {
        let report = classify(MAINNET_ENTERPRISE).unwrap();
        assert_eq!(
            report.kind,
            AddressKind::Payment {
                payment_is_script: false,
                has_stake_part: false,
                stake_is_script: false,
                stake_is_pointer: false,
            }
        );
    }

    #[test]
    fn mainnet_stake_address_classifies_as_stake() {
        let report = classify(MAINNET_STAKE).unwrap();
        assert_eq!(report.network, NetworkKind::Mainnet);
        assert_eq!(report.kind, AddressKind::Stake { is_script: false });
    }

    #[test]
    fn testnet_stake_address_classifies_as_stake_on_testnet() {
        let report = classify(TESTNET_STAKE).unwrap();
        assert_eq!(report.network, NetworkKind::Testnet);
        assert_eq!(report.kind, AddressKind::Stake { is_script: false });
    }

    #[test]
    fn derive_stake_address_matches_the_published_reward_address() {
        // Independent expected value (CIP-19), not derived by the code
        // under test.
        assert_eq!(
            derive_stake_address(MAINNET_PAYMENT).as_deref(),
            Some(MAINNET_STAKE)
        );
    }

    #[test]
    fn derive_stake_address_none_for_enterprise_and_stake() {
        assert_eq!(derive_stake_address(MAINNET_ENTERPRISE), None);
        assert_eq!(derive_stake_address(MAINNET_STAKE), None);
    }

    #[test]
    fn pointer_address_is_detected_and_has_no_reward_address() {
        // Detection through a real parse (not a hand-built struct): the
        // pointer delegation must set stake_is_pointer, and a pointer has
        // no directly-derivable reward address.
        let report = classify(MAINNET_POINTER).unwrap();
        assert_eq!(
            report.kind,
            AddressKind::Payment {
                payment_is_script: false,
                has_stake_part: true,
                stake_is_script: false,
                stake_is_pointer: true,
            }
        );
        assert_eq!(derive_stake_address(MAINNET_POINTER), None);
    }

    #[test]
    fn classifies_byron_address() {
        let report = classify(BYRON).unwrap();
        assert_eq!(report.kind, AddressKind::Byron);
        assert_eq!(report.network, NetworkKind::Other);
    }

    #[test]
    fn rejects_corrupted_byron_address() {
        // A tampered base58 string must not classify as a Byron address.
        assert!(classify(&format!("{BYRON}x")).is_err());
    }

    #[test]
    fn is_stake_address_matches_only_stake_addresses() {
        assert!(is_stake_address(MAINNET_STAKE));
        assert!(is_stake_address(TESTNET_STAKE));
        assert!(!is_stake_address(MAINNET_PAYMENT));
        assert!(!is_stake_address(BYRON));
        assert!(!is_stake_address("garbage"));
    }

    #[test]
    fn rejects_garbage() {
        assert!(classify("not-an-address").is_err());
    }

    #[test]
    fn rejects_noncanonical_encoding() {
        // bech32 is case-insensitive, so pallas accepts an uppercased
        // address, but its canonical form is lowercase. classify must
        // reject the non-canonical input. This is the same mechanism that
        // rejects a tampered HRP (e.g. one containing `/` or `?`), which is
        // what keeps a crafted "address" out of a request path.
        let upper = MAINNET_PAYMENT.to_uppercase();
        assert!(classify(&upper).is_err());
        // The canonical form is still accepted.
        assert!(classify(MAINNET_PAYMENT).is_ok());
    }
}
