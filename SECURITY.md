# Security Policy

## Reporting a vulnerability

Email **security@slidphilabs.com** with:

- What you found and where (file, line, or command).
- Steps to reproduce, if you have them.
- Your assessment of impact (what an attacker could do with it).

Expect an acknowledgement within **3 business days**. We will keep
you informed of progress and credit you in the fix announcement
unless you ask not to be named. Please give us a reasonable window to
fix before public disclosure — **90 days** is our default.

PGP for the security mailbox: *not yet published; plain email for
now.* (We will not pretend to offer encrypted reporting before the
key exists.)

## Scope

In scope:

- The transparency-log implementation (`crates/ctlog/`) — Merkle
  construction, root computation, inclusion-proof generation.
- The publisher (`crates/publisher/`) — submission validation,
  signature checks, rotation-entry handling, the 500/run cap, dedupe.
- `verify.sh` — receipt and inclusion verification, key-timeline
  handling.
- The release-signing workflow template
  (`.github/workflows/cosign-template.yml`) once installed in the
  cuni repo.
- Key-handling procedures in `docs/KEY-ROTATION.md`.

## What does NOT qualify

- **Receipt content disputes.** If a logged receipt's *claim* is
  false, that's a CuNi correctness issue, not a log-security issue.
  The log proves a statement was made and signed, not that it was
  true (see README "What the log proves — and what it does NOT").
  Report those to the CuNi project.
- **The bootstrap TEST key being "untrusted."** It is labeled TEST
  on purpose. That is a documented design state, not a finding.
- Missing hardening that is already on the roadmap (Phase 2: Rider
  identity, hosted API) — check the README first.

## Response expectations

- Acknowledgement: within 3 business days.
- Triage decision (valid / not valid / needs more info): within
  10 business days of acknowledgement.
- Fix or mitigation for confirmed issues: target 30 days for high
  severity, 90 days otherwise; critical issues (silent log rewrite
  undetectable by `verify.sh`) get same-day response.
- We will not take legal action against good-faith researchers who
  follow this policy.

## A note on the threat model

The log's core security property is *detectability of tampering*,
not *prevention*: a compromised log operator can sign anything, but
cannot do so silently — published roots in git make rewrites visible
to anyone holding a copy. Reports that break this detectability
property are the highest priority.
