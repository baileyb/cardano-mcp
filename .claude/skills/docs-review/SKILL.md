---
name: docs-review
description: >
  Audit this repo's Markdown against the documentation rules in CLAUDE.md.
  Use when writing or editing any .md file, when the user asks for a "slop
  check" or "docs review", and as the mandatory pre-release verification
  pass. Reports violations with file:line and proposed fixes; blocks on
  error-level findings.
---

# Docs Review

Enforce the documentation rules from `CLAUDE.md` (Documentation rules
section). Three modes; pick by context.

## Mode 1: Diff audit (default when docs changed)

For each changed `.md` file:

1. **Registry check** — is the file in the CLAUDE.md document registry? If
   new: does the change add its registry row with a stated question? Missing
   registration = error.
2. **Mechanical pass** — run the same tools CI runs, locally if available:
   `vale <files>`, `markdownlint-cli2 <files>`. Report anything CI would
   reject.
3. **Slop pass** — judge each changed paragraph against:
   - Answers the doc's registered question? Off-question content = cut or
     relocate.
   - Falsifiable or actionable? Sentences that are neither = cut.
   - True at HEAD? Aspirational content unmarked as `Planned:` = error.
   - Duplicates a fact whose home is another doc? = replace with a link.
   - Terminology table respected? = fix in place.
4. **Leak sweep** — this is a public repo. Grep changed files for owner
   infrastructure and identity markers (private hostnames, mirror/org
   names, personal names, cluster references) and for owner plans or
   downstream use cases stated as fact. Any hit = error; owner-operational
   content moves to the gitignored `CLAUDE.local.md`.
5. **Two-question test** on any new document: who reads this, and what do
   they do differently afterward? No concrete answer = recommend deletion,
   and say so plainly.

## Mode 2: Full audit ("slop check")

Mode 1's checks applied to every registered document, plus:

- Registry ↔ filesystem consistency (docs with no row; rows with no doc).
- Cross-document duplication sweep: same fact stated in two places.
- Dead internal links.

## Mode 3: Release verification (mandatory per release)

For every registered document:

1. Re-read it fully against the code at the release commit.
2. Fix anything no longer true; flag anything that needs a decision.
3. Update the document's `Last verified:` stamp to today.
4. A doc that cannot be verified (its subject is in flux) blocks the
   release — say so rather than stamping it anyway.

## Report format

```text
DOCS REVIEW — <mode>
Errors (block):
  <file>:<line> — <rule> — <finding> — <proposed fix>
Warnings (judgment):
  ...
Verdict: PASS / BLOCK (n errors)
```

Never soften an error to a warning to make a review pass. If a rule itself
seems wrong, say so explicitly and propose changing the rule (`.vale/styles/`
or CLAUDE.md) in a separate commit — rules change by decision, not by
exception.
