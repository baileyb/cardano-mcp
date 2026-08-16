//! Binary-level tests for the CLI subcommands. These exercise `main.rs`
//! branches that the in-process tests cannot reach. They run only commands
//! that exit immediately without reading stdin (the no-arg form starts the
//! stdio server and is intentionally not exercised here).

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    reason = "tests fail by panicking; that is their job"
)]

use std::io::{Read, Write};
use std::net::TcpListener;
use std::process::Command;

const BIN: &str = env!("CARGO_BIN_EXE_cardano-mcp");
const MAINNET_STAKE: &str = "stake1uyehkck0lajq8gr28t9uxnuvgcqrc6070x3k9r8048z8y5gh6ffgw";

/// One-shot local HTTP server that answers a single request with `body` as
/// a 200, then closes. Returns the base URL to set as `BLOCKFROST_BASE_URL`.
fn serve_once(body: &'static str) -> String {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap();
    let response = format!(
        "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
        body.len()
    );
    std::thread::spawn(move || {
        if let Ok((mut stream, _)) = listener.accept() {
            // Best-effort test I/O; the subprocess's output is the real check.
            let mut buf = [0u8; 1024];
            let _ = stream.read(&mut buf);
            let _ = stream.write_all(response.as_bytes());
            let _ = stream.flush();
        }
    });
    format!("http://{addr}")
}

#[test]
fn inspect_address_without_argument_fails_with_message() {
    let output = Command::new(BIN).arg("inspect-address").output().unwrap();
    assert!(!output.status.success());
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("requires an address argument"),
        "stderr was: {stderr}"
    );
}

#[test]
fn unknown_command_exits_two() {
    let output = Command::new(BIN).arg("bogus-command").output().unwrap();
    assert_eq!(output.status.code(), Some(2));
}

#[test]
fn inspect_address_success_prints_report() {
    // A stake address makes exactly one account_info request; a one-shot
    // local server answers it, exercising the CLI success branch end to end.
    let base_url =
        serve_once(r#"{"active":true,"pool_id":"pool1abc","controlled_amount":"1000000"}"#);
    let output = Command::new(BIN)
        .arg("inspect-address")
        .arg(MAINNET_STAKE)
        .env("BLOCKFROST_BASE_URL", base_url)
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        stdout.contains("staking: delegated to"),
        "stdout was: {stdout}"
    );
    assert!(
        stdout.contains("controlled total: 1.000000 ADA"),
        "stdout was: {stdout}"
    );
}
