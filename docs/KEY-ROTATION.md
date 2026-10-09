# Key Rotation Policy

**Spec version:** v0.1 (key rotation entries are specified here;
implementation in `verify.sh` and the publisher is deferred — see
"Implementation status" below.)

The log's signing key is the root of trust for the published
tree-heads. It must be replaceable without breaking the chain, and a
replacement must be auditable: anyone must be able to see *which* key
replaced *which*, *when*, and *why* — all inside the log itself.

> **Status note (v0.1.0):** tree-heads are not yet separately signed —
> roots are committed to public git history, which provides the current
> timestamping. This policy specifies the intended mechanism for when
> tree-head signing lands; until then, rotation entries are specified
> but not implemented (see "Implementation status").

## Rotation as a log entry

A key rotation is itself a log entry, with this exact JSON shape:

```json
{
  "type": "key-rotation",
  "prev_pubkey": "<base64 Ed25519 public key, 32 bytes>",
  "next_pubkey": "<base64 Ed25519 public key, 32 bytes>",
  "reason": "scheduled | compromise | ceremony | other",
  "note": "optional human-readable detail",
  "prev_signature": "<base64 Ed25519 signature>"
}
```

`prev_signature` is an Ed25519 signature over the canonical encoding
of the rotation statement — the JSON object above with `type`,
`prev_pubkey`, `next_pubkey`, `reason`, and `note` fields, serialized
deterministically (canonical JSON: keys sorted, no whitespace), —
made with the **previous** key (`prev_pubkey`).

## Normative MUST list (implementers)

1. The publisher MUST reject any rotation entry whose
   `prev_signature` does not verify against `prev_pubkey`.
2. The publisher MUST reject a rotation whose `prev_pubkey` is not
   the log's currently active signing key at the time of processing.
3. The publisher MUST reject a rotation whose `next_pubkey` equals
   `prev_pubkey` (no-op rotations are meaningless).
4. The publisher MUST append valid rotation entries to the log in the
   same append-only stream as receipts — a rotation is a leaf like
   any other, distinguished by `"type": "key-rotation"`.
5. `verify.sh` MUST recognize `key-rotation` entries and validate them
   per rules 1–3 when auditing the key history.
6. After processing a rotation, the publisher MUST use `next_pubkey`
   as the active key for all subsequent tree-head signatures, and MUST
   record the rotation height (leaf index) alongside the new key in
   `keys/` so verifiers can reconstruct the full key timeline.
7. A verifier checking a tree-head signed before the rotation height
   MUST use `prev_pubkey`; a tree-head at or after it MUST use
   `next_pubkey`. (Tree-heads are signed by the key active at the
   height of the head.)
8. The publisher MUST NOT accept a rotation submitted in
   `submissions/pending/` by an arbitrary party: rotations are
   operator-issued. (Implementation detail: rotations bypass the
   public inbox and are committed by the log operator directly.)

## Implementation status

**Spec v0.1; implementation deferred.** As of v0.1.0, neither the
publisher nor `verify.sh` implements rotation-entry handling: entries
with `"type": "key-rotation"` are **rejected by the publisher** (logged
nowhere, flagged for operator review). Rotation support is required
before the production root key ceremony — the ceremony's first act is
a rotation from the bootstrap TEST key to the production key, and it
must validate end-to-end under this spec first.

## Rotation cadence

- **Scheduled rotation:** at least annually. Annual rotation bounds
  the blast radius of a silent key compromise and keeps the rotation
  machinery exercised.
- **On compromise:** immediately, following the compromise procedure
  below.
- **Ceremony transitions:** bootstrap TEST key → production key (the
  first rotation), and any future ceremony-driven replacement.

A rotation that is *scheduled* must be announced in the CHANGELOG and
in `keys/` (a `rotation-scheduled.json` notice) at least 7 days before
it takes effect, so verifiers can prepare.

## Compromise procedure

If the active signing key is believed compromised:

1. **Freeze:** stop the publisher from signing new tree-heads
   immediately. No new roots are published under a suspected key.
2. **Rotate:** generate a fresh keypair on controlled hardware,
   publish a `key-rotation` entry with `"reason": "compromise"`
   signed by the OLD key if it is still available (this preserves the
   unbroken chain). If the old key is unavailable or untrustworthy,
   the rotation is operator-announced out-of-band (CHANGELOG entry,
   signed statement in this repo) with `"reason": "compromise"` and
   the chain resumes from the new key with a documented gap.
3. **Audit:** all tree-heads signed after the earliest suspected
   compromise time are re-verified; any receipt whose only anchor is
   a tree-head signed during the suspect window is flagged.
4. **Disclose:** a public incident note in the CHANGELOG describing
   what happened, what was affected, and what was done. No silent
   rotations — ever.

## Key storage guidance

- Production keys live on controlled hardware (HSM or offline
  machine), never in the repo, never in CI.
- Only *public* keys are committed to `keys/`.
- The bootstrap TEST key in `keys/` is explicitly labeled TEST and
  carries no authority (see README "Key status").
