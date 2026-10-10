# CuNi Transparency Log

An append-only, Merkle-rooted (RFC 6962) public transparency log for
[CuNi](https://github.com/ceedot-rock/cuni) v0.10.0 **exactness receipts** — signed statements that a given
CuNi program produced a given output on a given input, exactly. It
works like Certificate Transparency (CT): every receipt is publicly
logged under a Merkle tree root that is itself published (here, in
git), so anyone can verify that a receipt existed at a time and that
the log has never been silently rewritten.

Receipts are Ed25519-signed by their *issuer's own* key. The log
accepts any receipt whose signature verifies against the public key
stated inside the receipt.

Produce receipts with the [CuNi compiler](https://github.com/ceedot-rock/cuni)
(`cuni check --json --sign <keyfile>`), or try exactness with no install
in [CuNi Studio](https://cuni-studio.fly.dev/).

## What the log proves — and what it does NOT

This section is the honest boundary of the project. Read it before
relying on the log for anything.

**The log proves:**

- A receipt **existed** at a given time (its position in the log is
  anchored by an hourly Merkle root committed to public git history —
  v0.1.0 tree-heads are timestamped by the git commit, not separately
  signed; see "What it does NOT prove").
- The receipt was **signed by the key it claims** (every logged
  receipt passed an Ed25519 signature check at submission time).
- The log is **self-consistent** (append-only Merkle structure; a
  rewritten history breaks the published roots, and anyone can detect
  it with `verify.sh`).
- A receipt has **not been retroactively removed** once its root was
  published — removal would break inclusion proofs.

**The log does NOT prove:**

- That the receipt's **claim is true** — the log proves a statement
  was *made*, not that it was *correct*.
- That the stated key **belongs to who it says** — there is no
  identity binding in v0.1 (Rider identity logging is planned as
  Phase 2).
- That the code that produced the receipt was **honest** — a
  compromised or lying signer produces valid, logged, false receipts.
- That the CuNi program itself was correct — receipt *content*
  disputes are CuNi's domain, not the log's.
- That the log operator never equivocated — v0.1.0 tree-heads are
  **not separately signed**; rewriting published history is detectable
  (it breaks published roots and the public git log), but defending
  against split-view attacks needs out-of-band root comparison, which
  is future work alongside tree-head signing.

In short: **existence + self-consistency, not authority and not
truth.**

## Quickstart

### Verify a receipt

No account or setup needed:

```sh
./verify.sh receipt.json
```

`verify.sh` checks three things: (1) the receipt's Ed25519 signature
verifies against the public key stated in the receipt; (2) the receipt
is included in the log (Merkle inclusion proof against a published
root); (3) the root's signature verifies against the log's current
signing key.

### Submit a receipt

Two ways:

1. **Pull request (normal path):** drop the receipt file into
   `submissions/pending/` and open a PR. The publisher runs hourly,
   validates the submission, appends valid receipts to the log, and
   publishes a new Merkle root.
2. **Local / batch path:** place the file under
   `submissions/pending/` in a local clone for the publisher to pick
   up on its next run.

Submissions are validated, not trusted: a receipt whose signature
fails to verify is rejected, never logged.

## Log layout

```
cuni-transparency/
├── log/                # the append-only receipt store: leaves/, proofs/, roots/
├── submissions/pending/# inbox — receipts awaiting validation
├── keys/               # log signing keys (pubkeys; bootstrap TEST key)
├── crates/             # Rust: Merkle tree + publisher crates
├── verify.sh           # receipt + inclusion verification, no account needed
└── docs/               # key rotation, release signing, design notes
```

*Exact directory names and crate contents are builder A/B territory;
this layout is the intended shape as of v0.1.0.*

## Submission rules

- **Schema:** a receipt is a JSON document containing the CuNi
  program identifier (`path` + `source_hash`), the exact output hash
  (`stdout_hash`), the exactness statement, the pinned compiler version
  (`cuni_version`), the signer public key (Ed25519, hex), and the
  signature (Ed25519, hex) over the receipt body. See
  `fixtures/sample-receipt.json` for the canonical shape.
- **Signature must verify:** the publisher checks the Ed25519
  signature against the receipt's *stated* public key before logging.
  Invalid signatures are rejected with the file left in place for
  auditability — nothing invalid ever enters `log/`.
- **Dedupe:** byte-identical resubmissions are accepted once; the
  second copy is dropped (no duplicate log entries).
- **500/run cap:** the publisher processes at most 500 submissions
  per hourly run; overflow waits for the next run, oldest first.

## Key status

- The log's current signing key is a **bootstrap TEST key**. It exists
  to make the pipeline real and verifiable during development; it
  carries no authority.
- The **production root key ceremony has not happened.** Until it
  does, nothing in this log should be treated as an authoritative
  record of anything. The ceremony will be announced in the CHANGELOG
  and in `docs/KEY-ROTATION.md` when scheduled.

## Key rotation

Rotation is a first-class log event: a rotation is published as a
log entry of type `key-rotation`, signed with the *previous* key,
naming the previous and next public keys and the reason. The full
policy — cadence, compromise procedure, and the normative MUST list
for implementers — is in
[`docs/KEY-ROTATION.md`](docs/KEY-ROTATION.md).

## Release signing

CuNi release artifacts (tarballs, `CHECKSUMS.txt`) are being moved to
**keyless Sigstore/cosign signing via GitHub OIDC** — the plan,
workflow template, and exact user-side verification commands are in
[`docs/RELEASE-SIGNING.md`](docs/RELEASE-SIGNING.md). **Planned for
the next CuNi release; not yet applied.**

## Phase 2 (planned)

- **Rider identity logging:** binding logged receipts to Rider
  signed-agent identities, so "who it says it is" stops being the
  hole in the honest-boundaries section above. Explicitly **out of
  scope for v0.1**.
- **Hosted API:** a read API over the log (inclusion proofs by
  receipt hash, root history). Also out of scope for v0.1 — the
  log is git-backed and everything is verifiable from a clone.

## FAQ

**Q: If anyone can log a receipt, what stops someone logging lies?**

Nothing — and that's by design. The log is a *public record of
claims*, not a truth oracle. A false receipt signed by a real key is
logged exactly like a true one, and anyone can point at it forever.
The value is accountability: statements can't be quietly retracted,
and a signer who issues false receipts leaves permanent evidence.

**Q: Why is the bootstrap key a TEST key?**

Because a production signing key deserves a real ceremony — key
generation on controlled hardware, published fingerprints, witnesses
— and that hasn't happened yet. Shipping a pretend-authoritative key
would be dishonest; labeling the current key TEST is the honest
default. The ceremony will be announced when scheduled.

**Q: Do I need an account to verify a receipt?**

No. Clone the repo, run `./verify.sh receipt.json`. Verification
needs only the repo contents and a shell with standard tooling.

**Q: What's the difference between this and signing a receipt myself?**

Signing proves *who said it*. Logging proves *when it was said* and
*that it can't be unsaid* — the receipt is committed to a
tamper-evident history anchored by published hourly roots. A
signature alone can be shown selectively; a logged signature cannot
be hidden after the fact.

**Q: The log accepts receipts from any key — isn't that a spam vector?**

Partially mitigated: invalid-signature receipts are rejected, exact
duplicates are dropped, and the 500-per-run cap bounds ingestion.
Sybil resistance (cost or identity per submission) is a Phase 2
question, tied to Rider identity.

## Related

- [CuNi](https://github.com/ceedot-rock/cuni) — the exact multi-target
  language whose signed exactness receipts this log records.
- [CuNi Studio](https://cuni-studio.fly.dev/) — hosted playground;
  run the exactness gate in the browser.
- [Agent-Rider](https://github.com/ceedot-rock/Agent-Rider) — the agent
  network; binding logged receipts to Rider signed-agent identities is
  Phase 2 (planned).

## License

Apache-2.0 — see [LICENSE](LICENSE).
Copyright 2026 Corey Tasz / Slid Phi Labs.
