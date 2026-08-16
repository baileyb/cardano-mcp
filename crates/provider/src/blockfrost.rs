//! Blockfrost-compatible HTTP backend.
//!
//! Works against hosted Blockfrost and against a self-hosted Dolos data
//! node (which serves the same API shape) by changing the base URL.

use crate::{AccountInfo, AddressInfo, AddressTotals, ChainProvider, ProviderError};
use reqwest::StatusCode;
use serde::de::DeserializeOwned;
use std::time::Duration;

/// Ceiling on response body size; larger responses are rejected rather
/// than parsed (asymmetric-resource defense, `THREAT_MODEL.md` F4).
pub const MAX_RESPONSE_BYTES: usize = 2 * 1024 * 1024;

const REQUEST_TIMEOUT: Duration = Duration::from_secs(15);

/// A project key for hosted Blockfrost. Wrapped so it can never appear in
/// debug output or logs.
pub struct ApiKey(String);

impl ApiKey {
    /// Wrap a key.
    #[must_use]
    pub fn new(key: String) -> Self {
        Self(key)
    }
}

impl core::fmt::Debug for ApiKey {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("ApiKey(redacted)")
    }
}

/// Blockfrost-compatible provider over HTTP.
#[derive(Debug)]
pub struct Blockfrost {
    client: reqwest::Client,
    base_url: String,
    key: Option<ApiKey>,
}

impl Blockfrost {
    /// Create a provider for `base_url` (a trailing slash is trimmed),
    /// optionally authenticated (hosted Blockfrost requires a key; Dolos
    /// does not).
    ///
    /// Redirects are never followed: a redirect from a chain-data API is
    /// treated as a protocol error. Following one would let a hostile
    /// provider steer server-originated requests to arbitrary hosts with
    /// the API key attached (`THREAT_MODEL.md` F3/F5).
    ///
    /// # Errors
    ///
    /// [`ProviderError::Construction`] when the HTTP client cannot be
    /// built.
    pub fn new(base_url: &str, key: Option<ApiKey>) -> Result<Self, ProviderError> {
        let client = reqwest::Client::builder()
            .timeout(REQUEST_TIMEOUT)
            .redirect(reqwest::redirect::Policy::none())
            .build()
            .map_err(ProviderError::Construction)?;
        Ok(Self {
            client,
            base_url: base_url.trim_end_matches('/').to_owned(),
            key,
        })
    }

    /// Fetch `/<collection>/<reference>` (optionally with a fixed
    /// `/<suffix>`), validating the caller-supplied `reference` against the
    /// safe charset before it is placed in the request path. Callers do not
    /// build path strings themselves — this is the single choke point where
    /// an identifier becomes a URL segment.
    async fn get_ref<T: DeserializeOwned>(
        &self,
        collection: &str,
        reference: &str,
        suffix: &str,
    ) -> Result<T, ProviderError> {
        if !is_safe_reference(reference) {
            return Err(ProviderError::InvalidReference);
        }
        self.get(&format!("/{collection}/{reference}{suffix}"))
            .await
    }

    async fn get<T: DeserializeOwned>(&self, path: &str) -> Result<T, ProviderError> {
        let url = format!("{}{path}", self.base_url);
        let mut request = self.client.get(url);
        if let Some(ApiKey(key)) = &self.key {
            request = request.header("project_id", key);
        }
        let mut response = request.send().await.map_err(ProviderError::Transport)?;
        match response.status() {
            StatusCode::NOT_FOUND => return Err(ProviderError::NotFound),
            StatusCode::UNAUTHORIZED | StatusCode::FORBIDDEN => {
                return Err(ProviderError::Unauthorized);
            }
            // Redirects are disabled at the client; any 3xx lands here as
            // a plain non-success status.
            status if !status.is_success() => {
                return Err(ProviderError::Status(status.as_u16()));
            }
            _ => {}
        }
        // Reject on the declared length first, then enforce the ceiling
        // while streaming — Content-Length is provider-controlled and
        // cannot be trusted to match the actual body.
        if let Some(declared) = response.content_length()
            && usize::try_from(declared).map_or(true, |d| d > MAX_RESPONSE_BYTES)
        {
            return Err(ProviderError::OversizedResponse(MAX_RESPONSE_BYTES));
        }
        let mut body: Vec<u8> = Vec::new();
        while let Some(chunk) = response.chunk().await.map_err(ProviderError::Transport)? {
            if body.len().saturating_add(chunk.len()) > MAX_RESPONSE_BYTES {
                return Err(ProviderError::OversizedResponse(MAX_RESPONSE_BYTES));
            }
            body.extend_from_slice(&chunk);
        }
        serde_json::from_slice(&body).map_err(|_| ProviderError::Malformed)
    }
}

/// True when every character of `reference` is safe to place in a URL path
/// segment: ASCII alphanumeric plus `_` (present in the `addr_test` and
/// `stake_test` bech32 prefixes). This excludes `/`, `?`, `#`, `.`, `@`,
/// `%`, and every other path/query metacharacter, and covers Cardano
/// bech32 (lowercase) and Byron base58 (mixed-case) identifiers.
fn is_safe_reference(reference: &str) -> bool {
    !reference.is_empty()
        && reference
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'_')
}

impl ChainProvider for Blockfrost {
    async fn address_info(&self, address: &str) -> Result<AddressInfo, ProviderError> {
        self.get_ref("addresses", address, "").await
    }

    async fn address_totals(&self, address: &str) -> Result<AddressTotals, ProviderError> {
        self.get_ref("addresses", address, "/total").await
    }

    async fn account_info(
        &self,
        stake_address: &str,
    ) -> Result<Option<AccountInfo>, ProviderError> {
        match self.get_ref("accounts", stake_address, "").await {
            Ok(info) => Ok(Some(info)),
            Err(ProviderError::NotFound) => Ok(None),
            Err(other) => Err(other),
        }
    }
}

#[cfg(test)]
#[allow(
    clippy::unwrap_used,
    reason = "tests fail by panicking; that is their job"
)]
mod tests {
    use super::*;
    use crate::ChainProvider;
    use std::io::{Read, Write};
    use std::net::TcpListener;

    type RequestLog = std::sync::Arc<std::sync::Mutex<Option<String>>>;

    /// Bind a local listener that answers exactly one request with the raw
    /// bytes `response`, then closes. Returns the base URL and a handle that
    /// captures the request's first line (method + path). No network, no
    /// external mock dependency.
    ///
    /// GET-only: it reads a single fixed 1 KiB buffer, so it must not be
    /// reused for a request that carries a body.
    fn serve_once(response: Vec<u8>) -> (String, RequestLog) {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        let log: RequestLog = std::sync::Arc::new(std::sync::Mutex::new(None));
        let log_writer = std::sync::Arc::clone(&log);
        std::thread::spawn(move || {
            if let Ok((mut stream, _)) = listener.accept() {
                let mut buf = [0u8; 1024];
                let n = stream.read(&mut buf).unwrap_or(0);
                let text = String::from_utf8_lossy(buf.get(..n).unwrap_or(&[]));
                let first_line = text.lines().next().unwrap_or("").to_owned();
                *log_writer
                    .lock()
                    .unwrap_or_else(std::sync::PoisonError::into_inner) = Some(first_line);
                // Response is written only after the request line is
                // captured, so a test that awaits the client sees the log set.
                let _ = stream.write_all(&response);
                let _ = stream.flush();
            }
        });
        (format!("http://{addr}"), log)
    }

    fn ok_body(json: &str) -> Vec<u8> {
        format!(
            "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{json}",
            json.len()
        )
        .into_bytes()
    }

    fn status_only(status_line: &str) -> Vec<u8> {
        format!("HTTP/1.1 {status_line}\r\nContent-Length: 0\r\nConnection: close\r\n\r\n")
            .into_bytes()
    }

    fn client_for(response: Vec<u8>) -> Blockfrost {
        let (url, _log) = serve_once(response);
        Blockfrost::new(&url, None).unwrap()
    }

    fn client_and_log(response: Vec<u8>) -> (Blockfrost, RequestLog) {
        let (url, log) = serve_once(response);
        (Blockfrost::new(&url, None).unwrap(), log)
    }

    fn logged_line(log: &RequestLog) -> String {
        log.lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .clone()
            .unwrap_or_default()
    }

    #[tokio::test]
    async fn address_info_parses_a_200() {
        let provider = client_for(ok_body(
            r#"{"amount":[{"unit":"lovelace","quantity":"5"}],"stake_address":null,"script":false}"#,
        ));
        let info = provider.address_info("addr1xyz").await.unwrap();
        assert_eq!(info.amount.len(), 1);
    }

    #[tokio::test]
    async fn status_404_maps_to_not_found() {
        let provider = client_for(status_only("404 Not Found"));
        assert!(matches!(
            provider.address_info("addr1xyz").await,
            Err(ProviderError::NotFound)
        ));
    }

    #[tokio::test]
    async fn status_403_maps_to_unauthorized() {
        let provider = client_for(status_only("403 Forbidden"));
        assert!(matches!(
            provider.address_info("addr1xyz").await,
            Err(ProviderError::Unauthorized)
        ));
    }

    #[tokio::test]
    async fn redirect_is_not_followed_and_surfaces_as_status() {
        // A 302 must become a Status error, not a followed request.
        let redirect = b"HTTP/1.1 302 Found\r\nLocation: http://169.254.169.254/\r\nContent-Length: 0\r\nConnection: close\r\n\r\n".to_vec();
        let provider = client_for(redirect);
        assert!(matches!(
            provider.address_info("addr1xyz").await,
            Err(ProviderError::Status(302))
        ));
    }

    #[tokio::test]
    async fn account_404_maps_to_ok_none() {
        let provider = client_for(status_only("404 Not Found"));
        assert_eq!(provider.account_info("stake1xyz").await.unwrap(), None);
    }

    #[tokio::test]
    async fn oversized_declared_length_is_rejected_before_reading() {
        let over = MAX_RESPONSE_BYTES + 1;
        let response =
            format!("HTTP/1.1 200 OK\r\nContent-Length: {over}\r\nConnection: close\r\n\r\n")
                .into_bytes();
        let provider = client_for(response);
        assert!(matches!(
            provider.address_info("addr1xyz").await,
            Err(ProviderError::OversizedResponse(_))
        ));
    }

    #[tokio::test]
    async fn oversized_streamed_body_without_length_is_capped() {
        // No Content-Length; body streamed past the ceiling — the running
        // cap must trip rather than the process buffering it all.
        let mut response = b"HTTP/1.1 200 OK\r\nConnection: close\r\n\r\n".to_vec();
        response.extend(std::iter::repeat_n(b'x', MAX_RESPONSE_BYTES + 1024));
        let provider = client_for(response);
        assert!(matches!(
            provider.address_info("addr1xyz").await,
            Err(ProviderError::OversizedResponse(_))
        ));
    }

    #[tokio::test]
    async fn unsafe_reference_is_rejected_before_any_request() {
        // Never reached by the server: rejected before the request is made.
        let provider = Blockfrost::new("http://127.0.0.1:1", None).unwrap();
        assert!(matches!(
            provider.address_info("addr1/../evil?x=1").await,
            Err(ProviderError::InvalidReference)
        ));
        assert!(matches!(
            provider.account_info("stake1#frag").await,
            Err(ProviderError::InvalidReference)
        ));
    }

    #[test]
    fn safe_reference_charset() {
        assert!(is_safe_reference("addr1qxyz"));
        assert!(is_safe_reference("stake_test1uq"));
        assert!(is_safe_reference("DdzFF58ByronBase58"));
        assert!(!is_safe_reference("has/slash"));
        assert!(!is_safe_reference("has?query"));
        assert!(!is_safe_reference("has.dot"));
        assert!(!is_safe_reference(""));
    }

    #[test]
    fn base_url_trailing_slash_is_trimmed() {
        let provider = Blockfrost::new("http://example/api/", None).unwrap();
        assert_eq!(provider.base_url, "http://example/api");
    }

    #[tokio::test]
    async fn address_info_requests_the_addresses_collection() {
        let (provider, log) = client_and_log(ok_body(
            r#"{"amount":[],"stake_address":null,"script":false}"#,
        ));
        let _ = provider.address_info("addr1xyz").await;
        assert!(
            logged_line(&log).starts_with("GET /addresses/addr1xyz "),
            "was: {}",
            logged_line(&log)
        );
    }

    #[tokio::test]
    async fn address_totals_requests_the_total_suffix() {
        let (provider, log) = client_and_log(ok_body(r#"{"tx_count":3}"#));
        let _ = provider.address_totals("addr1xyz").await;
        assert!(
            logged_line(&log).starts_with("GET /addresses/addr1xyz/total "),
            "was: {}",
            logged_line(&log)
        );
    }

    #[tokio::test]
    async fn account_info_requests_the_accounts_collection() {
        let (provider, log) = client_and_log(ok_body(
            r#"{"active":true,"pool_id":null,"controlled_amount":"0"}"#,
        ));
        let _ = provider.account_info("stake1xyz").await;
        assert!(
            logged_line(&log).starts_with("GET /accounts/stake1xyz "),
            "was: {}",
            logged_line(&log)
        );
    }

    #[tokio::test]
    async fn body_exactly_at_cap_is_accepted() {
        // Boundary: a body of exactly MAX_RESPONSE_BYTES must be accepted
        // (JSON allows trailing whitespace, so we pad a valid body to size).
        let core = r#"{"amount":[],"stake_address":null,"script":false}"#;
        let pad = MAX_RESPONSE_BYTES - core.len();
        let mut body = core.to_owned();
        body.push_str(&" ".repeat(pad));
        assert_eq!(body.len(), MAX_RESPONSE_BYTES);
        let response = format!(
            "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
            body.len()
        )
        .into_bytes();
        let provider = client_for(response);
        let info = provider.address_info("addr1xyz").await.unwrap();
        assert!(info.amount.is_empty());
    }

    #[tokio::test]
    async fn transport_error_display_leaks_no_url() {
        // A connection failure must not surface the configured base URL or
        // request path (which reqwest's own Display would append), since
        // this string may reach an MCP client / model.
        let provider = Blockfrost::new("http://127.0.0.1:1/secret-internal-host", None).unwrap();
        let err = provider.address_info("addr1xyz").await.unwrap_err();
        assert!(matches!(err, ProviderError::Transport(_)));
        let shown = err.to_string();
        assert!(!shown.contains("http"), "leaked url: {shown}");
        assert!(!shown.contains("127.0.0.1"), "leaked host: {shown}");
        assert!(
            !shown.contains("secret-internal-host"),
            "leaked path: {shown}"
        );
    }

    #[test]
    fn construction_error_display_leaks_no_url() {
        // The Construction variant redacts the same way as Transport: its
        // Display is a fixed string, never the wrapped reqwest error.
        let reqwest_err = reqwest::Client::new()
            .get("http://[not-a-valid-host/secret")
            .build()
            .unwrap_err();
        let err = ProviderError::Construction(reqwest_err);
        // The fixed Display (no `{0}`) cannot contain the wrapped error.
        assert_eq!(err.to_string(), "provider client construction failed");
    }
}
