# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

*Nothing yet.*

## [0.1.0] - 2026-10-09

Initial release: an append-only, Merkle-rooted (RFC 6962) transparency
log for CuNi v0.10.0 Ed25519-signed exactness receipts.

### Added

- `crates/ctlog/` — Merkle tree implementation and root computation
  (builder A).
- `crates/publisher/` — hourly publisher: validates submissions,
  verifies Ed25519 signatures, dedupes, appends valid receipts,
  publishes hourly Merkle roots (builder B; roots are git-committed,
  not separately signed in v0.1.0).
- `log/` — the append-only receipt store.
- `submissions/pending/` — public submission inbox (PR or local).
- `keys/` — log signing keys; ships with the **bootstrap TEST key**
  only. The production root key ceremony has not happened.
- `verify.sh` — verifies a receipt's signature and its Merkle
  inclusion proof against published roots. No account required.
- `fixtures/` — example receipt and related fixtures.
- `.github/` workflows for the publisher (builder B).
- Documentation (builder C, this release):
  - `README.md` — including the mandatory honest-boundaries section
    ("What the log proves — and what it does NOT").
  - `docs/KEY-ROTATION.md` — rotation policy; spec v0.1,
    implementation deferred (rotation entries currently rejected by
    the publisher).
  - `docs/RELEASE-SIGNING.md` — cosign/Sigstore keyless release
    signing plan for CuNi; planned, not yet applied.
  - `.github/workflows/cosign-template.yml` — reusable workflow
    template, install target `ceedot-rock/cuni`, not active here.
  - `SECURITY.md`, `LICENSE` (Apache-2.0, Corey Tasz / Slid Phi Labs),
    this CHANGELOG.

### Honest-boundaries recap for v0.1.0

- The log proves **existence + self-consistency**, not authority and
  not truth (see README).
- The signing key is a **TEST key**; no production ceremony yet.
- Key-rotation entries are **specified, not implemented**.
- Release signing is **planned, not applied**.
- Rider identity logging and a hosted API are **Phase 2**, out of
  scope.

[0.1.0]: https://github.com/ceedot-rock/cuni-transparency/releases/tag/v0.1.0
