# cardano-mcp — Claude Code instructions

## This repo is PUBLIC

Everything committed here is public the moment it lands. Act accordingly:

- **Docs describe the artifact, never the owner.** No personal plans, use
  cases, strategy, schedules, or downstream projects. Where an illustration
  is needed, use generic examples ("a scheduled agent", "a monitoring job").
  Initiative planning lives in a private planning hub, not here — do not
  copy plan content into this repo.
- **No personal or infrastructure details.** No private hostnames, cluster
  names, wallet addresses, holdings, or file paths from the owner's machines.
- **No secrets, ever.** Config via env; `.env` is gitignored; a committed
  `.env.example` documents shape only. If a secret touches git history, stop
  and say so — do not quietly fix.
- **Never disparage other community projects** in docs, comments, or commit
  messages.

## Security posture (non-negotiable)

- Chain data is attacker-controlled input. Every chain-sourced value passes
  through the sanitize boundary (size/depth ceilings, control-character
  stripping, data delimiting) before leaving the server. No exceptions, no
  shortcuts "for now".
- `#![forbid(unsafe_code)]` stays. `cargo-deny` failures are fixed, not
  allowlisted casually.
- Capability absence: transaction building/signing is compile-time
  feature-gated, off by default. Never move that boundary to runtime config.
- GitHub Actions are pinned by commit SHA, not tags.

## Architecture invariants (see ARCHITECTURE.md)

- `tools/` may do I/O but never parses chain data; `decode/` parses but does
  no I/O; `sanitize/` is the only exit path for chain-sourced content.
- Tools are task-shaped: they answer questions, they do not mirror provider
  endpoints. A tool that merely re-exposes an endpoint gets cut.
- The `ChainProvider` trait stays narrow — only what tools need.
- The server is stateless; consumers are MCP clients, never components.

## Documentation rules

Docs in this repo are a product surface. The standard is: tight, direct,
true at HEAD. These rules are enforced by CI (Vale + markdownlint + lychee +
typos, fail-closed) and by the `docs-review` skill.

- **Every document answers a registered question.** The registry below is
  the closed set. Creating a doc means adding a row and stating its
  question; a doc whose question can't be stated gets deleted, not
  improved.
- **One home per fact.** A fact lives in exactly one document; everywhere
  else links to it. Duplication is a defect (duplicates diverge).
- **Describe the artifact as it exists at HEAD.** Aspirations are marked
  `Planned:` or live in issues — never stated as fact.
- **No marketing adjectives, no weasel words.** The banned list is
  `.vale/styles/CardanoMcp/*.yml` — versioned, PR-able, enforced. If
  something is fast, show the number; no number, no claim.
- **One term per concept** (terminology table below). Renaming a term
  updates every use in the same commit.
- **Code examples are tested claims**: Rust examples run as doctests;
  shell examples are marked tested or untested.
- **Docs move with code**: a change that invalidates a doc updates that
  doc in the same commit.
- **Per-release verification**: before a release ships, every registered
  doc is re-read against the code and its `Last verified:` stamp updated.
  An unstamped or stale doc blocks the release.
- Before writing any doc, state the question it answers; if you can't,
  don't write it. Before merging, apply the two-question test: who reads
  this, and what do they do differently afterward?

### Document registry

| Document | Question it answers |
| --- | --- |
| `README.md` | What is this, and how do I run it in five minutes? |
| `ARCHITECTURE.md` | How is the system built, and why this shape? |
| `SECURITY.md` | How do I report a vulnerability, and what is in scope? |
| `THREAT_MODEL.md` | What does this defend against, and what does it explicitly not? |
| `CONTRIBUTING.md` | How do I contribute a change that will be accepted? |
| `CODE_OF_CONDUCT.md` | What behavior is expected in project spaces? |
| `CLAUDE.md` | What rules govern work in this repo? |

### Terminology

| Term | Meaning | Never |
| --- | --- | --- |
| provider | The chain-data backend behind the `ChainProvider` trait | backend, upstream service, data source |
| tool | An MCP tool exposed by this server | endpoint, command, function |
| sanitize boundary | The single output path for chain-sourced content | sanitizer, filter layer |
| Tier 1 / Tier 2 | Read-only capability set / feature-gated tx building | phase, level |

## Workflow

- **Never commit or push in this repo without an explicit instruction from
  the user in the current session.** Make changes in the working tree and
  present them for review; committing is always the user's call. A general
  "commit" instruction in another repo does not carry over to this one.

## Rust standards

Lint policy lives in `[workspace.lints]` in Cargo.toml — versioned and
reviewed like code, never ad-hoc CI flags. The rules:

- Toolchain: stable, pinned in `rust-toolchain.toml`. MSRV declared as
  `rust-version` in Cargo.toml, tested in CI, bumped only in minor releases.
- `#![forbid(unsafe_code)]` at every crate root. Not `deny` — `forbid`.
- Warnings are errors (`rust.warnings = "deny"`); `clippy::all` denied;
  `clippy::pedantic` warned and triaged, not silenced wholesale.
- In decoder and server code additionally denied: `unwrap_used`,
  `expect_used`, `panic`, `indexing_slicing`, `arithmetic_side_effects`.
  A justified exception is `#[allow]` with a `reason = "..."` stating why
  the panic is unreachable — reviewable, greppable, rare.
- No `as` casts in decode paths; use `TryFrom` and handle the error.
- Errors: `thiserror` typed errors in library code; `anyhow` only at the
  binary edge. Error strings never contain secret material. No silently
  discarded `Result` (`let _ =` requires a comment).
- Every public item documented (`missing_docs` denied in library code).
  Comments state contracts and constraints, not restatements of the code.
- Tests: decoders get fuzz targets and golden fixtures before merge;
  renderers are golden-tested; round-trip invariants get property tests.
- `cargo fmt` default profile, CI-enforced.
- New dependency = one-line justification in the commit message adding it.

## Architectural enforcement

The boundaries in ARCHITECTURE.md are enforced by the dependency graph, not
by discipline:

- Code that parses chain data lives in a crate whose Cargo.toml contains no
  I/O dependencies (no HTTP client, no async runtime, no filesystem crates).
  "Decode does no I/O" is then compile-time-checkable: the capability is
  absent, mirroring the Tier 2 approach.
- The sanitize boundary is its own crate; tool output types are constructed
  only through it (constructors private outside the boundary).
- CI asserts a per-crate dependency allowlist, so an I/O crate cannot creep
  into the decode crate unnoticed.
- Any change to crate boundaries or the dependency-allowlist requires an
  ADR in the planning hub before the change lands.

## Conventions

- Conventional commits (`feat:`, `fix:`, `docs:`, ...).
- License is Apache-2.0; keep it that way.
