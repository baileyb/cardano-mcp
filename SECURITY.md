# Security Policy

## Reporting a vulnerability

**Please use [GitHub Private Vulnerability Reporting](https://github.com/baileyb/cardano-mcp/security/advisories/new)**
(the "Report a vulnerability" button on this repository's Security tab). This
keeps the report confidential, gives us a private workspace to develop a fix,
and lets a CVE be issued through GitHub when the advisory is published.

If you cannot use GitHub, email the maintainer at the address listed on the
maintainer's GitHub profile with `[cardano-mcp security]` in the subject.

Please include: an affected version or commit, a reproduction (input bytes or
a transaction/asset identifier that triggers the issue), and the impact you
believe it has. If any part of your report was generated with AI assistance,
say so — reports are read by a human and vague machine-generated reports slow
everyone down.

**What to expect:** acknowledgement within 5 business days; an assessment and
fix plan within 14 days for confirmed issues; a coordinated fix targeted
within 90 days. This is a solo-maintained project — there is no 24/7 on-call.
If an issue is being actively exploited, we may publish an advisory before a
complete fix exists.

Confirmed vulnerabilities are published as a GitHub Security Advisory and,
once the crate is on crates.io, as a [RustSec](https://rustsec.org) advisory
so `cargo audit`/`cargo deny` alert downstream users. Reporters are credited
unless they ask not to be. There is currently no bug bounty.

## Supported versions

Pre-1.0: only the **latest release** receives security fixes. From 1.0, the
latest minor of the current major will be supported; this policy will be
updated then.

## Scope

**In scope** (please report):

- Panics, crashes, or unbounded resource consumption triggered by untrusted
  input — on-chain data (CBOR, metadata, asset names), provider responses,
  or MCP requests. A reachable panic on attacker-controlled input is a
  denial-of-service vulnerability, not a bug.
- Any path where chain-sourced content bypasses the output sanitization
  boundary (unstripped control/ANSI sequences, unbounded output, content
  escaping its data framing).
- Server-side request forgery: any way to make the server issue a network
  request to an attacker-chosen destination.
- Secret exposure: the provider API key appearing in logs, errors, or tool
  output.
- Transport security gaps in the HTTP mode (missing Origin/Host validation,
  auth bypass) — for the planned streamable-HTTP transport; the current
  server is stdio-only.
- Supply-chain issues in our release pipeline or published artifacts.

**Out of scope:**

- Prompt-injection *robustness of downstream models*. This server sanitizes
  and delimits attacker-authored on-chain content, but no server can
  guarantee a model ignores hostile instructions; see the shared-
  responsibility statement in [THREAT_MODEL.md](THREAT_MODEL.md).
- Fabricated data from a compromised or malicious data provider, beyond the
  provider-trust tiers documented in the threat model (provider responses
  are unsigned; Cardano has no light-client balance proofs today).
- Vulnerabilities in MCP clients, agents, or other software consuming this
  server's output.
- Social engineering, and scam content that merely *exists* on-chain (we
  surface it as untrusted data; we cannot remove it).

## Posture summary

The full analysis lives in [THREAT_MODEL.md](THREAT_MODEL.md). Highlights:

- Read-only by default: the default build contains no signing or spending
  code (compile-time exclusion, not configuration).
- All chain-sourced content is treated as attacker-controlled and passes
  through a mandatory sanitization boundary before leaving the server.
- No off-chain URL fetching by default: URLs found in chain data (pool
  metadata, governance anchors, NFT media) are returned defanged as data,
  never fetched.
- `#![forbid(unsafe_code)]`; `cargo-deny` in CI; GitHub Actions pinned by
  commit SHA; releases built with provenance attestations and embedded
  dependency data (`cargo auditable`).
