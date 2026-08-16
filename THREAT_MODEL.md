# Threat Model

This document explains what `cardano-mcp` defends against, how, and — just as
important — what it explicitly does not defend against. It complements
[ARCHITECTURE.md](ARCHITECTURE.md) (how the system is built) and
[SECURITY.md](SECURITY.md) (how to report problems). Last substantive review:
2026-08.

## System summary

`cardano-mcp` is a read-only MCP server: it fetches Cardano chain data from a
Blockfrost-compatible provider, decodes it (Pallas/CBOR), and returns
sanitized, human-readable answers to MCP clients over stdio (local) or
streamable HTTP (self-hosted). The default build holds no keys and cannot
sign, spend, or write anything anywhere.

## Position in the "lethal trifecta"

Agent-security risk requires three legs together: (1) access to private
data, (2) exposure to untrusted content, (3) an exfiltration channel. A
read-only server over *public* chain data supplies only leg (2): it is a
conduit for untrusted content, but holds no private data and provides no
side-effecting tools an attacker could exfiltrate through.

The consequence, stated honestly: **this server cannot make an agent safe; it
can only refuse to make an agent less safe.** If a downstream agent combines
our output with private data and a write-capable tool from elsewhere, hostile
on-chain content could still steer it. Our commitments are to (a) never
amplify hostile content, (b) make untrusted data legible *as data*, and
(c) never grow an exfiltration or side-effect channel in the default build.
Breaking the trifecta is the host's job; not contributing legs to it is ours.

## Assets

| Asset | Where | Notes |
| --- | --- | --- |
| Provider API key | Env var / deployment secret | Only secret in the default build. Must never appear in logs, errors, or tool output |
| Host network position | Wherever the server runs | An SSRF-capable server is a beachhead into its network; see F3 |
| Downstream agent context | The consuming LLM | Shared asset: we sanitize what enters it, we cannot control what the model does |
| Service availability | The server process | Panics on untrusted input are DoS vulnerabilities |
| Release integrity | crates.io / GHCR / GitHub releases | Users must be able to verify artifacts came from this repo's CI |

Signing keys are deliberately **not** on this list: the default artifact
contains no signing capability at all (compile-time feature exclusion). A
future transaction-building build will get its own threat-model section
before it ships.

## Trust levels

| Source | Trust | Rationale |
| --- | --- | --- |
| On-chain data (metadata, asset names, datums, governance content) | **Hostile** | Anyone can write it for pennies; it is authored input aimed at whoever decodes it |
| Off-chain documents referenced from chain (pool metadata JSON, governance anchors, NFT media URLs) | **Hostile, and fetching is itself dangerous** | URLs are attacker-controlled; the on-chain hash gates display integrity, not the act of fetching |
| Data provider (Blockfrost/Dolos API) | **Semi-trusted** | Responses are unsigned JSON; a compromised provider can fabricate anything. See provider tiers below |
| MCP client | **Semi-trusted** | May send malformed/abusive requests; gets only read-only answers |
| Dependencies / CI | **Supply chain** | Managed by pinning, auditing, attestation (F6) |

## Attack surfaces and defenses

### F1. Prompt injection via chain content

**The attack.** Cardano offers cheap, attacker-friendly text channels that
flow straight into an LLM's context via any naive decoder:

- **Transaction messages (CIP-20, label 674)** — arbitrary prose attached to
  any transaction; the cheapest injection primitive. The CIP's own security
  section anticipates abuse and pushes sanitization onto decoders.
- **Asset names** — up to 32 arbitrary bytes, *not* required to be valid
  UTF-8, not unique across policies. Room for unicode homoglyphs, zero-width
  characters, RTL overrides, ANSI escapes, and script tags (the EtherDelta
  token-name XSS is the canonical precedent in a neighboring ecosystem).
- **NFT/token metadata (CIP-25/68)** — attacker-authored names,
  descriptions, and URLs; CIP-25 metadata is additionally spoofable by
  design (latest-mint-wins) and mutable under CIP-68.
- **Governance metadata** — proposal rationales and DRep statements are
  long-form attacker-authored documents.
- **Airdrop dust** — unsolicited tokens whose entire purpose is carrying
  phishing text/links to whoever renders them.

**Defenses (the sanitize boundary — every output path, no exceptions):**

- Strip or make visible all control characters and ANSI escape sequences
  (escape-sequence smuggling into terminals/contexts is a demonstrated MCP
  attack class).
- Normalize unicode; strip zero-width and bidirectional-override characters;
  render non-UTF-8 asset names as hex, never as lossy text.
- **Delimit**: every chain-sourced string is emitted inside explicit
  data markers, so hostile text arrives quoted as data, not as prose.
- **Defang URLs**: URLs found in chain data are presented as
  non-actionable text (per CIP-20's own recommendation), never as links,
  and never fetched (F3).
- **Never let names claim identity**: token legitimacy is policy-ID based;
  responses carry the policy ID and CIP-14 fingerprint alongside any
  human-readable name, with the name explicitly labeled as unverified
  attacker-writable data.
- **Structured output**: tools return typed `structuredContent` with strict
  schemas rather than free-text blobs, so hosts can post-process and pass
  minimal fields to the model.
- Per-field length caps and a per-response size budget (context flooding is
  an attack).

**Honest limit:** delimiting and sanitization raise the bar; they do not
make injection impossible. No known server-side technique reliably prevents
a determined injection from influencing a model. See the trifecta section.

### F2. Malicious CBOR (parser attacks)

**The attack.** Plutus datums are arbitrary attacker-controlled CBOR. The
known live risk class for Rust CBOR decoding is **recursion-depth stack
overflow**: a ~16 KB payload of nested arrays can drive a recursive decoder
thousands of frames deep and abort the process (stack overflow does not
unwind — it kills). Sibling ecosystems patched exactly this in 2026
(cbor2 CVE-2026-26209, go-ipld-prime CVE-2026-42328). Indefinite-length
items and non-canonical encodings add further edge cases. Protocol limits
(16 KiB transactions, 64-byte metadatum strings) bound *validated on-chain*
data, but a decoder must never assume its input was validated upstream.

**Defenses:**

- Input size caps before decoding begins.
- Explicit recursion-depth bounds around Plutus-data decoding (the
  underlying library recurses without its own depth guard — this is our
  responsibility, enforced and tested here).
- Decode untrusted payloads on a bounded-stack worker so a pathological
  input fails the request, not the process.
- Panic policy: `unwrap`/`expect`/indexing lints denied in decoder and
  server code; a reachable panic on untrusted input is treated as a
  reportable DoS vulnerability (see SECURITY.md scope).
- Continuous fuzzing (`cargo-fuzz`) of decode paths with hostile corpora:
  deep nesting, indefinite-length chunks, oversized declared lengths,
  non-canonical encodings.

### F3. SSRF via off-chain references

**The attack.** Chain data is full of URLs the protocol *expects* consumers
to fetch: stake-pool metadata JSON, governance anchors (CIP-100/108/119),
NFT images. Every one is attacker/operator-controlled. A server that fetches
them can be steered at cloud metadata endpoints (`169.254.169.254`),
loopback services, and private ranges — turning a chain decoder into a probe
inside whatever network hosts it. The on-chain content hash is no defense:
the request fires before any hash can be checked. Notably, the ecosystem's
reference implementations bound response sizes but do **not** block private
address ranges — this surface is real and under-defended ecosystem-wide.

**Defenses:**

- **Default: the server performs no off-chain URL fetching at all.** URLs
  are returned defanged, as data, with their on-chain hashes, for the
  client to handle according to its own policy. You cannot be an SSRF
  vector if you never make the request.
- If a fetch capability ships later, it will be a non-default feature
  hardened as a unit: HTTPS-only scheme allowlist, self-resolved DNS with
  every resolved address validated against private/link-local/loopback/
  mapped ranges, DNS pinning between validation and connection, redirects
  re-validated per hop, streaming size caps independent of Content-Length,
  decompression-bomb guards, strict content-type allowlist, and short
  timeouts — with its own threat-model section before release.

### F4. Transport and protocol attacks

**The attack.** HTTP-mode MCP servers have an established 2025–26 incident
history: DNS rebinding against loopback-bound servers (this SDK class
included: rmcp < 1.4.0, CVE-2026-42559), session hijacking against stateful
transports, header/body desync through gateways, and token passthrough
misuse.

**Defenses:**

- stdio is the default transport; it exposes no network surface.
- rmcp **≥ 1.4.0** required (Host-header validation / rebinding fix).
- **Origin validation** on all HTTP requests with 403 on mismatch — the
  current MCP spec makes this a MUST; where the SDK does not yet enforce
  it, this server does so itself in middleware. Strict CORS allowlist,
  never `*`.
- Default bind is `127.0.0.1`; binding wider requires explicit
  configuration and is documented as requiring a fronting proxy with TLS
  and authentication.
- Sessions are never used for authentication; the targeted protocol
  revision (2026-07-28) removes sessions entirely, and older-revision
  session IDs are ignored rather than honored.
- Bearer/API-token authentication for any network-exposed deployment;
  tokens are audience-specific — no token passthrough.
- Error hygiene: no stack traces, paths, or configuration in responses.
- Request-level resource limits: concurrency caps, timeouts, response size
  budgets.

### F5. Provider trust (the data can lie)

**The attack.** Blockfrost-compatible responses are unsigned JSON. A
compromised or malicious provider can fabricate balances, omit or invent
transactions, and misreport governance state — undetectably, in the general
case. This is a Cardano-structural limit, not an implementation gap: block
headers commit to no ledger state, so **no proof of a balance or UTxO set
against the chain exists today** for anything short of recomputing the
ledger. Freshness (that you're seeing the current tip) is likewise never
provable from data alone.

**Defenses (a documented ladder, not a false guarantee):**

1. **Hosted provider** (default bootstrap): zero chain-level integrity;
   output is treated and labeled as *provider-attested*.
2. **Self-hosted Dolos**: syncs from real network peers and recomputes
   ledger state locally; bootstrap history is verified against
   Mithril's stake-based certificates. Removes the API-operator from the
   trust equation; the live tail still assumes honest upstream peers (no
   consensus validation).
3. **Full node upstream of Dolos**: full validation, for operators who
   want it.

What the server itself does: verifies what is self-verifiable (transaction
CBOR re-hashed against its claimed hash), and keeps the provider behind one
narrow interface so deployments can climb the ladder by configuration.

### F6. Supply chain and release integrity

**The attack.** Malicious or compromised dependencies; tampered CI; artifact
substitution after release. The MCP ecosystem has already seen its first
in-the-wild backdoored server package; "trust me" is not a posture.

**Defenses:**

- `#![forbid(unsafe_code)]` (compiler-enforced, not policy).
- `cargo-deny` in CI, fail-closed: advisories, licenses, duplicate bans,
  source allowlist. Scheduled advisory re-checks between pushes.
- Committed `Cargo.lock`; CI builds `--locked`; `cargo install --locked`
  documented.
- GitHub Actions pinned to commit SHAs; workflow static analysis (zizmor)
  in CI; minimal token permissions; immutable releases enabled.
- Release artifacts carry native build-provenance attestations
  (`gh attestation verify`-able); binaries built with `cargo auditable` so
  the shipped artifact embeds its own scannable dependency tree; container
  images are distroless, non-root, read-only-rootfs.
- crates.io publishing via Trusted Publishing (OIDC), no long-lived
  registry tokens.

## Explicit non-goals and accepted risks

Stated so users can make informed decisions, and so reports against these
are answerable:

1. **We do not claim to defeat prompt injection.** We claim not to amplify
   it. Model-level robustness is the host's and model vendor's problem.
2. **We cannot prove chain state below a full node.** Provider tiers are a
   trust ladder, not a proof system; no balance/UTxO proofs exist on
   Cardano today. Deployments choose their rung.
3. **Scam content exists on-chain and will appear in output** — sanitized,
   delimited, and labeled, but present. We surface reality; we do not
   moderate it.
4. **Wallet-/signer-class vulnerabilities are out of scope** because the
   capability is absent: the 2026 Cardano wallet incidents (deterministic-
   nonce signing flaws) involve operations this build cannot perform.
5. **The stdio launcher is trusted.** Whoever can start the process can
   configure it; local machine compromise is out of scope.
6. **Availability under sustained volumetric DoS** is a deployment concern
   (rate-limiting proxy, container limits); the server defends against
   *asymmetric* resource attacks (small input, large cost), not raw flood.

## Review triggers

This document is re-reviewed when any of the following change: a new tool
touches a new chain data type; any off-chain fetch capability is proposed;
the transaction-building feature approaches release; the MCP spec revises
transport security; rmcp ships security-relevant changes; or a report
arrives that contradicts an assumption above.
