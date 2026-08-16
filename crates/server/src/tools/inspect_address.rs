//! `inspect_address`: what is this address, what does it hold, and how is
//! it staked?

use cardano_mcp_decode::address::{AddressKind, AddressReport, NetworkKind};
use cardano_mcp_decode::asset::Unit;
use cardano_mcp_decode::{address, asset, value};
use cardano_mcp_provider::{AccountInfo, ChainProvider, ProviderError};
use cardano_mcp_sanitize as sanitize;

/// Ceiling on the number of native assets listed per response
/// (context-flooding defense; the count of remainder is reported).
const MAX_ASSETS_LISTED: usize = 50;

/// Errors from the tool.
#[derive(Debug, thiserror::Error)]
pub enum ToolError {
    /// The input failed address classification.
    #[error("address did not parse: {0}")]
    BadAddress(#[from] cardano_mcp_decode::DecodeError),
    /// The provider failed.
    #[error("provider: {0}")]
    Provider(#[from] ProviderError),
    /// The provider returned a balance quantity that is non-numeric or
    /// overflows arithmetic. Surfaced instead of guessing (a wrong
    /// balance stated confidently is worse than an error).
    #[error("provider returned a malformed or out-of-range balance quantity")]
    BadQuantity,
}

fn describe_kind(report: &AddressReport) -> String {
    let network = match report.network {
        NetworkKind::Mainnet => "mainnet",
        NetworkKind::Testnet => "testnet",
        NetworkKind::Other => "unrecognized-network",
    };
    match &report.kind {
        AddressKind::Payment {
            payment_is_script,
            has_stake_part,
            stake_is_script,
            stake_is_pointer,
        } => {
            let holder = if *payment_is_script {
                "script-controlled"
            } else {
                "key-controlled"
            };
            let staking = if !has_stake_part {
                "no staking part (enterprise address)"
            } else if *stake_is_pointer {
                "pointer staking part (no reward address)"
            } else if *stake_is_script {
                "script-controlled staking part"
            } else {
                "key-controlled staking part"
            };
            format!("{network} payment address, {holder}, {staking}")
        }
        AddressKind::Stake { is_script } => {
            let holder = if *is_script { "script" } else { "key" };
            format!("{network} stake (reward) address, {holder}-controlled")
        }
        AddressKind::Byron => "legacy Byron-era address".to_owned(),
    }
}

fn parse_quantity(raw: &str) -> Result<u128, ToolError> {
    raw.parse::<u128>().map_err(|_| ToolError::BadQuantity)
}

// Quantity policy is deliberately asymmetric. The primary ADA balance is a
// headline fact an agent acts on, so an unparsable/overflowing lovelace
// quantity fails the whole call (`BadQuantity`) rather than render a
// misleading number. Secondary per-asset and controlled-total quantities
// render as explicitly-labeled data so one bad row does not sink the report.
// A future "consistency" cleanup should not flatten this without deciding
// which way is correct.

/// Render a provider quantity for a display line: numeric when it parses,
/// an explicitly-labeled delimited raw value when it does not (never a
/// silent zero).
fn render_quantity(raw: &str) -> String {
    parse_quantity(raw).map_or_else(
        |_| format!("unparsable {}", sanitize::text(raw, 40).quoted()),
        |q| q.to_string(),
    )
}

/// Render an account's staking state into `lines`.
fn push_account_lines(lines: &mut Vec<String>, account: Option<AccountInfo>) {
    match account {
        Some(account) if account.active => {
            let delegation = account.pool_id.as_deref().map_or_else(
                || "registered, not delegated".to_owned(),
                |pool| format!("delegated to {}", sanitize::text(pool, 128).quoted()),
            );
            lines.push(format!("staking: {delegation}"));
            let controlled = parse_quantity(&account.controlled_amount).map_or_else(
                |_| {
                    format!(
                        "unparsable {}",
                        sanitize::text(&account.controlled_amount, 40).quoted()
                    )
                },
                value::format_lovelace,
            );
            lines.push(format!("controlled total: {controlled}"));
        }
        Some(_) => lines.push("staking: deregistered".to_owned()),
        None => lines.push("staking: never registered".to_owned()),
    }
}

/// Run the inspection: classify locally, then fetch holdings, lifetime
/// totals, and (when present) reward-account state, and render a plain
/// legible report. All chain-sourced free-form values are sanitized and
/// delimited.
///
/// # Errors
///
/// [`ToolError::BadAddress`] when the input is not a Cardano address;
/// [`ToolError::Provider`] for provider failures; [`ToolError::BadQuantity`]
/// when the primary lovelace balance is non-numeric or overflows.
pub async fn run<P: ChainProvider>(provider: &P, input_address: &str) -> Result<String, ToolError> {
    let report = address::classify(input_address)?;
    let mut lines: Vec<String> = Vec::new();
    lines.push(format!("kind: {}", describe_kind(&report)));

    // A stake (reward) address has no holdings to fetch; report its account
    // state directly. The input is canonical (classify enforced it) and so
    // charset-safe for the request path.
    if matches!(report.kind, AddressKind::Stake { .. }) {
        push_account_lines(&mut lines, provider.account_info(input_address).await?);
        let mut out = lines.join("\n");
        out.push('\n');
        return Ok(out);
    }

    let info = provider.address_info(input_address).await?;
    let totals = provider.address_totals(input_address).await?;

    let lovelace: u128 = info
        .amount
        .iter()
        .filter(|a| a.unit == "lovelace")
        .try_fold(0u128, |acc, a| {
            let q = parse_quantity(&a.quantity)?;
            acc.checked_add(q).ok_or(ToolError::BadQuantity)
        })?;
    lines.push(format!("balance: {}", value::format_lovelace(lovelace)));
    lines.push(format!("lifetime transactions: {}", totals.tx_count));

    let assets: Vec<_> = info
        .amount
        .iter()
        .filter(|a| a.unit != "lovelace")
        .collect();
    if assets.is_empty() {
        lines.push("native assets: none".to_owned());
    } else {
        lines.push(format!("native assets: {}", assets.len()));
        for entry in assets.iter().take(MAX_ASSETS_LISTED) {
            match asset::parse_unit(&entry.unit) {
                Ok(Unit::Asset(id)) => {
                    let display_name = sanitize::bytes(&id.name, 64);
                    let fingerprint = id.fingerprint().unwrap_or_else(|_| "-".to_owned());
                    lines.push(format!(
                        "  - name {} (unverified, attacker-writable) | qty {} | policy {} | {}",
                        display_name.quoted(),
                        render_quantity(&entry.quantity),
                        id.policy_hex(),
                        fingerprint,
                    ));
                }
                Ok(Unit::Lovelace) | Err(_) => {
                    lines.push("  - (malformed asset unit from provider)".to_owned());
                }
            }
        }
        if assets.len() > MAX_ASSETS_LISTED {
            let hidden = assets.len().saturating_sub(MAX_ASSETS_LISTED);
            lines.push(format!("  \u{2026} and {hidden} more (capped)"));
        }
    }

    // The reward address is derivable locally from the payment address, so
    // we never trust the provider's `stake_address` for display or for the
    // follow-up fetch (`THREAT_MODEL.md` F5): a compromised provider could
    // otherwise substitute a different valid reward account and fabricate
    // staking state. The derived value is canonical and charset-safe. If
    // the provider's value disagrees, that is worth surfacing.
    if let Some(stake) = address::derive_stake_address(input_address) {
        lines.push(format!("reward account: {stake}"));
        if info.stake_address.as_deref() != Some(stake.as_str()) {
            let reported = info
                .stake_address
                .as_deref()
                .map_or_else(|| "(none)".to_owned(), |p| sanitize::text(p, 128).quoted());
            lines.push(format!(
                "note: provider reported a different reward account {reported} \u{2014} ignored"
            ));
        }
        push_account_lines(&mut lines, provider.account_info(&stake).await?);
    }

    let mut out = lines.join("\n");
    out.push('\n');
    Ok(out)
}

#[cfg(test)]
#[allow(
    clippy::unwrap_used,
    reason = "tests fail by panicking; that is their job"
)]
mod tests {
    use super::*;
    use cardano_mcp_decode::address::derive_stake_address;
    use cardano_mcp_provider::{AddressInfo, AddressTotals, Amount};

    /// CIP-19 mainnet test vector (payment address with staking part).
    const ADDR: &str = "addr1qx2fxv2umyhttkxyxp8x0dlpdt3k6cwng5pxj3jhsydzer3n0d3vllmyqwsx5wktcd8cc3sq835lu7drv2xwl2wywfgse35a3x";

    /// CIP-19 mainnet reward address, and a Byron base58 vector.
    const STAKE_ADDR: &str = "stake1uyehkck0lajq8gr28t9uxnuvgcqrc6070x3k9r8048z8y5gh6ffgw";
    const BYRON_ADDR: &str = "Ae2tdPwUPEZLs4HtbuNey7tK4hTKrwNwYtGqp7bDfCy2WdR3P6735W5Yfpe";

    /// CIP-14 vector: policy + "PATATE"; fingerprint is spec-pinned.
    const PATATE_UNIT: &str =
        "7eae28af2208be856f7a119668ae52a49b73725e326dc16579dcc373504154415445";
    const PATATE_FINGERPRINT: &str = "asset13n25uv0yaf5kus35fm2k86cqy60z58d9xmde92";

    use std::sync::atomic::{AtomicUsize, Ordering};

    struct Mock {
        info: AddressInfo,
        totals: AddressTotals,
        account: Option<AccountInfo>,
        calls: AtomicUsize,
        last_stake_queried: std::sync::Mutex<Option<String>>,
    }

    impl Mock {
        fn new(info: AddressInfo, totals: AddressTotals, account: Option<AccountInfo>) -> Self {
            Self {
                info,
                totals,
                account,
                calls: AtomicUsize::new(0),
                last_stake_queried: std::sync::Mutex::new(None),
            }
        }
        fn calls(&self) -> usize {
            self.calls.load(Ordering::Relaxed)
        }
    }

    impl ChainProvider for Mock {
        async fn address_info(&self, _address: &str) -> Result<AddressInfo, ProviderError> {
            self.calls.fetch_add(1, Ordering::Relaxed);
            Ok(self.info.clone())
        }
        async fn address_totals(&self, _address: &str) -> Result<AddressTotals, ProviderError> {
            self.calls.fetch_add(1, Ordering::Relaxed);
            Ok(self.totals.clone())
        }
        async fn account_info(&self, stake: &str) -> Result<Option<AccountInfo>, ProviderError> {
            self.calls.fetch_add(1, Ordering::Relaxed);
            *self
                .last_stake_queried
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner) = Some(stake.to_owned());
            Ok(self.account.clone())
        }
    }

    fn amount(unit: &str, quantity: &str) -> Amount {
        Amount {
            unit: unit.to_owned(),
            quantity: quantity.to_owned(),
        }
    }

    fn active_delegated() -> AccountInfo {
        AccountInfo {
            active: true,
            pool_id: Some("pool1abc".to_owned()),
            controlled_amount: "123456789".to_owned(),
        }
    }

    #[tokio::test]
    async fn golden_delegated_wallet_with_hostile_asset() {
        // Hostile name: ANSI red escape + zero-width space, hex-encoded
        // into the unit exactly as a provider would report it.
        let hostile_name_hex = hex::encode("\u{1b}[31mEVIL\u{200b}".as_bytes());
        let hostile_unit =
            format!("7eae28af2208be856f7a119668ae52a49b73725e326dc16579dcc37e{hostile_name_hex}");

        let stake = derive_stake_address(ADDR).unwrap();
        let mock = Mock::new(
            AddressInfo {
                amount: vec![
                    amount("lovelace", "42000000"),
                    amount(PATATE_UNIT, "12"),
                    amount(&hostile_unit, "1"),
                ],
                stake_address: Some(stake.clone()),
                script: false,
            },
            AddressTotals { tx_count: 7 },
            Some(active_delegated()),
        );

        let report = run(&mock, ADDR).await.unwrap();

        // The follow-up staking fetch used the locally-derived stake
        // address, not whatever the provider returned.
        assert_eq!(
            mock.last_stake_queried
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .as_deref(),
            Some(stake.as_str())
        );

        // The hostile fingerprint is computed via the already-spec-verified
        // decode path rather than memorized.
        let hostile_fp = match asset::parse_unit(&hostile_unit).unwrap() {
            Unit::Asset(id) => id.fingerprint().unwrap(),
            Unit::Lovelace => unreachable!("unit is an asset"),
        };

        let expected = format!(
            "kind: mainnet payment address, key-controlled, key-controlled staking part\n\
             balance: 42.000000 ADA\n\
             lifetime transactions: 7\n\
             native assets: 2\n  \
             - name \u{27ea}PATATE\u{27eb} (unverified, attacker-writable) | qty 12 | policy 7eae28af2208be856f7a119668ae52a49b73725e326dc16579dcc373 | {PATATE_FINGERPRINT}\n  \
             - name \u{27ea}\u{fffd}[31mEVIL\u{fffd}\u{27eb} (unverified, attacker-writable) | qty 1 | policy 7eae28af2208be856f7a119668ae52a49b73725e326dc16579dcc37e | {hostile_fp}\n\
             reward account: {stake}\n\
             staking: delegated to \u{27ea}pool1abc\u{27eb}\n\
             controlled total: 123.456789 ADA\n"
        );
        assert_eq!(report, expected);
    }

    fn info(amounts: Vec<Amount>, stake: Option<String>) -> AddressInfo {
        AddressInfo {
            amount: amounts,
            stake_address: stake,
            script: false,
        }
    }

    #[tokio::test]
    async fn empty_wallet_never_registered() {
        let mock = Mock::new(
            info(vec![amount("lovelace", "0")], derive_stake_address(ADDR)),
            AddressTotals { tx_count: 0 },
            None,
        );
        let report = run(&mock, ADDR).await.unwrap();
        assert!(report.contains("balance: 0.000000 ADA"));
        assert!(report.contains("native assets: none"));
        assert!(report.contains("staking: never registered"));
    }

    #[tokio::test]
    async fn deregistered_account_is_reported() {
        let mock = Mock::new(
            info(vec![], derive_stake_address(ADDR)),
            AddressTotals { tx_count: 3 },
            Some(AccountInfo {
                active: false,
                pool_id: None,
                controlled_amount: "0".to_owned(),
            }),
        );
        let report = run(&mock, ADDR).await.unwrap();
        assert!(report.contains("staking: deregistered"));
    }

    #[tokio::test]
    async fn provider_disagreeing_stake_address_is_ignored_with_note() {
        // The provider returns a *different* reward account than the one
        // derivable from the queried address (the F5 substitution attack).
        // The tool must report the derived one, flag the disagreement, and
        // fetch staking against the derived value.
        let derived = derive_stake_address(ADDR).unwrap();
        let mock = Mock::new(
            info(vec![], Some("stake1udifferentaccount".to_owned())),
            AddressTotals { tx_count: 1 },
            Some(active_delegated()),
        );
        let report = run(&mock, ADDR).await.unwrap();
        assert!(report.contains(&format!("reward account: {derived}")));
        assert!(report.contains(
            "note: provider reported a different reward account \u{27ea}stake1udifferentaccount\u{27eb} \u{2014} ignored"
        ));
        assert!(report.contains("staking: delegated to \u{27ea}pool1abc\u{27eb}"));
        assert_eq!(
            mock.last_stake_queried
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .as_deref(),
            Some(derived.as_str())
        );
    }

    #[tokio::test]
    async fn lovelace_overflow_is_an_error_not_a_panic() {
        let max = u128::MAX.to_string();
        let mock = Mock::new(
            info(
                vec![amount("lovelace", &max), amount("lovelace", &max)],
                None,
            ),
            AddressTotals { tx_count: 1 },
            None,
        );
        assert!(matches!(
            run(&mock, ADDR).await,
            Err(ToolError::BadQuantity)
        ));
    }

    #[tokio::test]
    async fn malformed_lovelace_quantity_is_an_error_not_zero() {
        let mock = Mock::new(
            info(vec![amount("lovelace", "12,000")], None),
            AddressTotals { tx_count: 1 },
            None,
        );
        assert!(matches!(
            run(&mock, ADDR).await,
            Err(ToolError::BadQuantity)
        ));
    }

    #[tokio::test]
    async fn malformed_asset_quantity_renders_as_labeled_data() {
        let mock = Mock::new(
            info(vec![amount(PATATE_UNIT, "-5")], None),
            AddressTotals { tx_count: 1 },
            None,
        );
        let report = run(&mock, ADDR).await.unwrap();
        assert!(report.contains("qty unparsable \u{27ea}-5\u{27eb}"));
        assert!(!report.contains("qty 0 "));
    }

    #[tokio::test]
    async fn malformed_asset_unit_from_provider_is_labeled() {
        // A non-lovelace unit that is not a valid policy+name.
        let mock = Mock::new(
            info(vec![amount("deadbeef", "1")], None),
            AddressTotals { tx_count: 1 },
            None,
        );
        let report = run(&mock, ADDR).await.unwrap();
        assert!(report.contains("(malformed asset unit from provider)"));
    }

    fn dust_units(n: usize) -> Vec<Amount> {
        (0..n)
            .map(|i| {
                amount(
                    &format!("7eae28af2208be856f7a119668ae52a49b73725e326dc16579dcc373{i:04x}"),
                    "1",
                )
            })
            .collect()
    }

    #[tokio::test]
    async fn asset_listing_over_cap_truncates_with_notice() {
        let over = MAX_ASSETS_LISTED.saturating_add(1);
        let mock = Mock::new(
            info(dust_units(over), None),
            AddressTotals { tx_count: 1 },
            None,
        );
        let report = run(&mock, ADDR).await.unwrap();
        assert!(report.contains(&format!("native assets: {over}")));
        assert!(report.contains("and 1 more (capped)"));
        assert_eq!(report.matches("- name").count(), MAX_ASSETS_LISTED);
    }

    #[tokio::test]
    async fn asset_listing_at_exactly_cap_has_no_capped_notice() {
        // Boundary: exactly the cap must list all and add no "(capped)".
        let mock = Mock::new(
            info(dust_units(MAX_ASSETS_LISTED), None),
            AddressTotals { tx_count: 1 },
            None,
        );
        let report = run(&mock, ADDR).await.unwrap();
        assert!(report.contains(&format!("native assets: {MAX_ASSETS_LISTED}")));
        assert!(!report.contains("(capped)"));
        assert_eq!(report.matches("- name").count(), MAX_ASSETS_LISTED);
    }

    #[tokio::test]
    async fn stake_address_input_reports_account_directly() {
        // A stake-address input must fetch account state directly and not
        // issue a payment-address holdings fetch (which a provider rejects).
        let mock = Mock::new(
            info(vec![], None),
            AddressTotals { tx_count: 0 },
            Some(active_delegated()),
        );
        let report = run(&mock, STAKE_ADDR).await.unwrap();
        assert!(report.contains("kind: mainnet stake (reward) address, key-controlled"));
        assert!(report.contains("staking: delegated to \u{27ea}pool1abc\u{27eb}"));
        assert!(!report.contains("balance:"));
        // Exactly one provider call: account_info, with the input itself.
        assert_eq!(mock.calls(), 1);
        assert_eq!(
            mock.last_stake_queried
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .as_deref(),
            Some(STAKE_ADDR)
        );
    }

    #[tokio::test]
    async fn provider_reporting_no_reward_account_is_noted_as_none() {
        // Payment address has a derivable reward account, but the provider
        // reports none: the disagreement note renders the "(none)" arm.
        let mock = Mock::new(
            info(vec![], None),
            AddressTotals { tx_count: 1 },
            Some(active_delegated()),
        );
        let report = run(&mock, ADDR).await.unwrap();
        assert!(report.contains(
            "note: provider reported a different reward account (none) \u{2014} ignored"
        ));
    }

    #[tokio::test]
    async fn active_registered_but_not_delegated() {
        let mock = Mock::new(
            info(vec![], derive_stake_address(ADDR)),
            AddressTotals { tx_count: 1 },
            Some(AccountInfo {
                active: true,
                pool_id: None,
                controlled_amount: "1000000".to_owned(),
            }),
        );
        let report = run(&mock, ADDR).await.unwrap();
        assert!(report.contains("staking: registered, not delegated"));
        assert!(!report.contains("delegated to"));
    }

    #[tokio::test]
    async fn active_account_unparsable_controlled_amount_is_labeled_not_zero() {
        // The account-side of the asymmetric quantity policy: a non-numeric
        // controlled amount must render as labeled data, never a silent zero.
        let mock = Mock::new(
            info(vec![], derive_stake_address(ADDR)),
            AddressTotals { tx_count: 1 },
            Some(AccountInfo {
                active: true,
                pool_id: Some("pool1abc".to_owned()),
                controlled_amount: "not-a-number".to_owned(),
            }),
        );
        let report = run(&mock, ADDR).await.unwrap();
        assert!(report.contains("controlled total: unparsable \u{27ea}not-a-number\u{27eb}"));
        assert!(!report.contains("controlled total: 0.000000"));
    }

    #[test]
    fn describe_kind_covers_every_variant() {
        use cardano_mcp_decode::address::{AddressKind, AddressReport, NetworkKind};
        let payment = |payment_is_script, has_stake_part, stake_is_script, stake_is_pointer| {
            describe_kind(&AddressReport {
                network: NetworkKind::Mainnet,
                kind: AddressKind::Payment {
                    payment_is_script,
                    has_stake_part,
                    stake_is_script,
                    stake_is_pointer,
                },
            })
        };
        assert_eq!(
            payment(false, true, false, false),
            "mainnet payment address, key-controlled, key-controlled staking part"
        );
        assert_eq!(
            payment(true, true, true, false),
            "mainnet payment address, script-controlled, script-controlled staking part"
        );
        assert_eq!(
            payment(false, false, false, false),
            "mainnet payment address, key-controlled, no staking part (enterprise address)"
        );
        assert_eq!(
            payment(false, true, false, true),
            "mainnet payment address, key-controlled, pointer staking part (no reward address)"
        );
        assert_eq!(
            describe_kind(&AddressReport {
                network: NetworkKind::Mainnet,
                kind: AddressKind::Stake { is_script: false },
            }),
            "mainnet stake (reward) address, key-controlled"
        );
        assert_eq!(
            describe_kind(&AddressReport {
                network: NetworkKind::Testnet,
                kind: AddressKind::Stake { is_script: true },
            }),
            "testnet stake (reward) address, script-controlled"
        );
        assert_eq!(
            describe_kind(&AddressReport {
                network: NetworkKind::Other,
                kind: AddressKind::Byron,
            }),
            "legacy Byron-era address"
        );
        // Pin the "unrecognized-network" label on a non-Byron kind (Byron
        // discards the network label).
        assert_eq!(
            describe_kind(&AddressReport {
                network: NetworkKind::Other,
                kind: AddressKind::Stake { is_script: false },
            }),
            "unrecognized-network stake (reward) address, key-controlled"
        );
    }

    #[tokio::test]
    async fn byron_address_input_renders_byron_kind() {
        let mock = Mock::new(info(vec![], None), AddressTotals { tx_count: 0 }, None);
        let report = run(&mock, BYRON_ADDR).await.unwrap();
        assert!(report.contains("kind: legacy Byron-era address"));
        // Byron has no stake part, so no staking section.
        assert!(!report.contains("staking:"));
    }

    #[tokio::test]
    async fn garbage_address_fails_before_any_provider_call() {
        let mock = Mock::new(info(vec![], None), AddressTotals { tx_count: 0 }, None);
        let result = run(&mock, "not-an-address").await;
        assert!(matches!(result, Err(ToolError::BadAddress(_))));
        // The classify gate runs before any fetch — nothing reached the
        // provider (and so nothing crafted reached a request path).
        assert_eq!(mock.calls(), 0);
    }
}
