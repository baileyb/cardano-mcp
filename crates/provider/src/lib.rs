//! Chain-data providers for `cardano-mcp`.
//!
//! Defines the narrow [`ChainProvider`] interface the server's tools
//! consume, and its backends. Provider responses are semi-trusted: unsigned
//! JSON that a compromised provider could fabricate. See `THREAT_MODEL.md`
//! (F5) at the repository root.

#![forbid(unsafe_code)]

pub mod blockfrost;

use serde::Deserialize;

/// One `unit`/`quantity` pair as reported by Blockfrost-compatible APIs.
/// Quantities arrive as decimal strings and are parsed downstream with
/// checked arithmetic.
#[derive(Debug, Clone, Deserialize, PartialEq, Eq)]
pub struct Amount {
    /// `"lovelace"` or `policy-hex ++ asset-name-hex`.
    pub unit: String,
    /// Decimal quantity as a string.
    pub quantity: String,
}

/// Provider view of an address.
#[derive(Debug, Clone, Deserialize, PartialEq, Eq)]
pub struct AddressInfo {
    /// Current holdings by unit.
    pub amount: Vec<Amount>,
    /// The associated reward account, when the address has a staking part.
    pub stake_address: Option<String>,
    /// True when the payment credential is a script.
    pub script: bool,
}

/// Provider lifetime totals for an address.
#[derive(Debug, Clone, Deserialize, PartialEq, Eq)]
pub struct AddressTotals {
    /// Number of transactions involving the address.
    pub tx_count: u64,
}

/// Provider view of a reward (stake) account.
#[derive(Debug, Clone, Deserialize, PartialEq, Eq)]
pub struct AccountInfo {
    /// True when the account is currently registered.
    pub active: bool,
    /// The pool the account delegates to, if any.
    pub pool_id: Option<String>,
    /// Total controlled lovelace as a decimal string.
    pub controlled_amount: String,
}

/// Errors surfaced by providers.
///
/// `Display` never embeds a response body, a URL, or the configured base
/// URL: these errors may be shown to an MCP client / model, and a
/// `reqwest::Error`'s own `Display` would otherwise append the request URL
/// (disclosing internal topology for a self-hosted deployment). The
/// underlying `reqwest::Error` is retained as `#[source]` for local error
/// chains (CLI / logging), which do not cross that boundary.
#[derive(Debug, thiserror::Error)]
pub enum ProviderError {
    /// The requested entity does not exist on-chain (HTTP 404).
    #[error("not found on-chain")]
    NotFound,
    /// The provider rejected our credentials (HTTP 401/403).
    #[error("provider rejected credentials")]
    Unauthorized,
    /// The provider answered with an unexpected HTTP status.
    #[error("provider returned HTTP status {0}")]
    Status(u16),
    /// The response exceeded the size ceiling.
    #[error("provider response exceeded {0} bytes")]
    OversizedResponse(usize),
    /// The response body did not match the expected shape.
    #[error("provider response failed to parse")]
    Malformed,
    /// A value destined for a request-path segment contained characters
    /// outside the safe reference charset. Rejected rather than sent, so a
    /// crafted identifier cannot manipulate the request path or query
    /// (`THREAT_MODEL.md` F3).
    #[error("unsafe reference rejected before request")]
    InvalidReference,
    /// Transport-level failure (connection, TLS, timeout).
    #[error("transport failure")]
    Transport(#[source] reqwest::Error),
    /// The provider client could not be constructed.
    #[error("provider client construction failed")]
    Construction(#[source] reqwest::Error),
}

/// The narrow interface tools consume. It contains only the fetches tools
/// need — it is deliberately not a general Cardano client.
#[allow(
    async_fn_in_trait,
    reason = "the server runs on a multi-thread runtime and consumes the \
              concrete Blockfrost impl, whose futures are Send; an explicit \
              `+ Send` bound would be needed only if the provider were \
              consumed generically or dynamically across a spawn point (e.g. \
              `Box<dyn ChainProvider>`), and adding it would then require \
              every impl to be Send"
)]
pub trait ChainProvider {
    /// Fetch current holdings and staking association for an address.
    ///
    /// # Errors
    ///
    /// [`ProviderError::NotFound`] when the address has never appeared
    /// on-chain; other variants for transport/protocol failures.
    async fn address_info(&self, address: &str) -> Result<AddressInfo, ProviderError>;

    /// Fetch lifetime totals for an address.
    ///
    /// # Errors
    ///
    /// As [`ChainProvider::address_info`].
    async fn address_totals(&self, address: &str) -> Result<AddressTotals, ProviderError>;

    /// Fetch reward-account state. Returns `Ok(None)` when the account has
    /// never been registered on-chain.
    ///
    /// # Errors
    ///
    /// Transport/protocol failures other than not-found.
    async fn account_info(&self, stake_address: &str)
    -> Result<Option<AccountInfo>, ProviderError>;
}

#[cfg(test)]
#[allow(
    clippy::unwrap_used,
    reason = "tests fail by panicking; that is their job"
)]
mod tests {
    use super::*;

    #[test]
    fn address_info_deserializes_blockfrost_shape() {
        let json = r#"{
            "address": "addr1qx...",
            "amount": [
                {"unit": "lovelace", "quantity": "42000000"},
                {"unit": "7eae28af2208be856f7a119668ae52a49b73725e326dc16579dcc373504154415445", "quantity": "12"}
            ],
            "stake_address": "stake1uy...",
            "type": "shelley",
            "script": false
        }"#;
        let info: AddressInfo = serde_json::from_str(json).unwrap();
        assert_eq!(info.amount.len(), 2);
        assert_eq!(info.stake_address.as_deref(), Some("stake1uy..."));
        assert!(!info.script);
    }

    #[test]
    fn address_totals_deserializes() {
        let json = r#"{"address":"addr1...","received_sum":[],"sent_sum":[],"tx_count":7}"#;
        let totals: AddressTotals = serde_json::from_str(json).unwrap();
        assert_eq!(totals.tx_count, 7);
    }

    #[test]
    fn account_info_deserializes() {
        let json = r#"{
            "stake_address": "stake1uy...",
            "active": true,
            "active_epoch": 500,
            "controlled_amount": "123456789",
            "pool_id": "pool1abc"
        }"#;
        let account: AccountInfo = serde_json::from_str(json).unwrap();
        assert!(account.active);
        assert_eq!(account.pool_id.as_deref(), Some("pool1abc"));
        assert_eq!(account.controlled_amount, "123456789");
    }
}
