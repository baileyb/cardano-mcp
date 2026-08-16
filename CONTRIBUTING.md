# Contributing

Contributions are welcome. This project holds itself to unusually strict,
fully documented standards — read this page before opening a pull request
and the machines will mostly stay out of your way.

## Ground rules

1. **The standards are in [CLAUDE.md](CLAUDE.md)** — documentation rules,
   Rust standards, security posture, and architecture invariants. They are
   enforced by fail-closed CI (prose lint, markdown mechanics, links,
   spelling; Rust lints once code exists). A red build is a real answer,
   not a formality.
2. **Security-relevant changes** must keep [THREAT_MODEL.md](THREAT_MODEL.md)
   true. If your change invalidates a statement there, update the document
   in the same pull request ("docs move with code").
3. **Sign off your commits (DCO).** Add `Signed-off-by: Your Name
   <email>` (`git commit -s`), certifying the
   [Developer Certificate of Origin](https://developercertificate.org/) —
   that you have the right to submit the work under this project's license.
   There is no CLA and there will not be one.
4. **Disclose AI assistance.** If any part of a pull request or issue was
   generated with AI tooling, say so in the description. AI-assisted work
   is acceptable; undisclosed and unreviewed generation is not. A human —
   you — must understand and stand behind every line you submit.
5. **Vulnerabilities are not issues or pull requests** — use the process in
   [SECURITY.md](SECURITY.md).
6. Be someone worth collaborating with: [CODE_OF_CONDUCT.md](CODE_OF_CONDUCT.md).

## Local checks before you push

`scripts/preflight.sh` runs every CI check locally — if it passes, CI
passes. Enable it as a pre-push hook once per clone:

```sh
git config core.hooksPath .githooks
```

The script names any missing tool and its install command. Bypassing with
`git push --no-verify` is for emergencies; CI will still hold the line.

## Practical notes

- Small, focused pull requests review faster than large ones.
- A new dependency needs a one-line justification in the commit that adds
  it.
- New documents need a registered question in CLAUDE.md's document
  registry; prose must pass the Vale styles in `.vale/styles/`.
- This is a solo-maintained project: review may take days, not hours.
