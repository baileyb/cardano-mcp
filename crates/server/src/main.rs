//! `cardano-mcp` server binary.
//!
//! Scaffold-stage harness: a CLI entry point that exercises the tool
//! pipeline end to end (decode → provider → sanitize → render).
//! Planned: an MCP transport becomes the primary entry point.

#![forbid(unsafe_code)]

mod tools;

use anyhow::Context;
use cardano_mcp_provider::blockfrost::{ApiKey, Blockfrost};

const USAGE: &str = "usage: cardano-mcp inspect-address <ADDRESS>\n\
  env: BLOCKFROST_PROJECT_ID (required for hosted Blockfrost)\n\
       BLOCKFROST_BASE_URL   (default: hosted mainnet; point at Dolos to self-host)";

fn base_url() -> String {
    std::env::var("BLOCKFROST_BASE_URL")
        .unwrap_or_else(|_| "https://cardano-mainnet.blockfrost.io/api/v0".to_owned())
}

#[tokio::main(flavor = "current_thread")]
async fn main() -> anyhow::Result<()> {
    let mut args = std::env::args().skip(1);
    let command = args.next().unwrap_or_default();
    let address = args.next().unwrap_or_default();
    if command != "inspect-address" || address.is_empty() {
        println!("cardano-mcp {} (pre-release)", env!("CARGO_PKG_VERSION"));
        println!("{USAGE}");
        return Ok(());
    }

    let key = std::env::var("BLOCKFROST_PROJECT_ID").ok().map(ApiKey::new);
    let provider = Blockfrost::new(&base_url(), key).context("constructing provider client")?;
    let report = tools::inspect_address::run(&provider, &address)
        .await
        .context("inspect-address failed")?;
    print!("{report}");
    Ok(())
}
