//! `cardano-mcp` server binary.
//!
//! Default entry point: an MCP server over stdio. A one-shot
//! `inspect-address <ADDRESS>` subcommand runs the same tool from the CLI
//! for debugging.

#![forbid(unsafe_code)]

mod mcp;
mod tools;

use anyhow::Context;
use cardano_mcp_provider::blockfrost::{ApiKey, Blockfrost};

const USAGE: &str = "cardano-mcp — Cardano MCP server\n\
  (no args)                    run the MCP server over stdio\n\
  inspect-address <ADDRESS>    run the inspect_address tool once and print it\n\
  env: BLOCKFROST_PROJECT_ID   (required for hosted Blockfrost)\n\
       BLOCKFROST_BASE_URL     (default: hosted mainnet; point at Dolos to self-host)";

fn base_url() -> String {
    std::env::var("BLOCKFROST_BASE_URL")
        .unwrap_or_else(|_| "https://cardano-mainnet.blockfrost.io/api/v0".to_owned())
}

fn build_provider() -> anyhow::Result<Blockfrost> {
    let key = std::env::var("BLOCKFROST_PROJECT_ID").ok().map(ApiKey::new);
    Blockfrost::new(&base_url(), key).context("constructing provider client")
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let mut args = std::env::args().skip(1);
    match args.next().as_deref() {
        // MCP server mode: nothing may be written to stdout except protocol
        // frames, so this branch prints nothing.
        None => mcp::serve_stdio(build_provider()?).await,
        Some("inspect-address") => {
            let address = args.next().unwrap_or_default();
            if address.is_empty() {
                anyhow::bail!("inspect-address requires an address argument");
            }
            let report = tools::inspect_address::run(&build_provider()?, &address)
                .await
                .context("inspect-address failed")?;
            print!("{report}");
            Ok(())
        }
        Some(other) => {
            eprintln!("unknown command: {other}\n{USAGE}");
            std::process::exit(2);
        }
    }
}
