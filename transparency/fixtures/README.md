# fixtures/

## sample-receipt.json — provenance (honest)

This is a **real** CuNi v0.10.0 signed receipt, not hand-crafted.

- Produced 2026-10-09 with the repo's own compiler:
  `cuni-repo/target/debug/cuni check --only py --json --sign <keyfile> /tmp/fixture.cuni`
  (the release binary in `target/release/` was stale — built 2026-10-05,
  predating the `--json` flag — so the freshly built debug binary was used;
  both are built from the same v0.10.0 source).
- The `.cuni` source is the trivial two-liner in `/tmp/fixture.cuni`
  (`def add(a,b)... say(add(2,40))`); the gate ran the single `py` seat:
  `exact: true`, `exactness: PASS (1 native seats)`.
- The `--sign` keyfile held the 32 raw secret bytes of this repo's
  **bootstrap TEST key** (`.bootstrap-key`); `signer_pubkey` in the
  receipt matches `keys/bootstrap-pubkey.hex` exactly.
- Signature byte-exactness was verified independently: stripping the
  trailing signature block as text and verifying with Python
  `cryptography` against the reconstructed unsigned bytes succeeds,
  proving the reconstruction equals what `cuni` actually signed.

Use it as the happy-path input for `verify.sh` and the publisher tests.
Do not treat it as endorsed by any authority — per the log's trust
model it proves only existence and self-consistency.

## sample-receipt-2.json / sample-receipt-3.json

Same provenance as above (same key, same method), different programs:

- `-2`: `def mul(a,b)... say(mul(6, 7))`, `--only py`, PASS.
- `-3`: `say(40 + 2)`, `--only py`, PASS.

`-2` is used to build multi-leaf test logs; `-3` is the canonical
"valid signature, never logged" receipt for `NOT_IN_LOG` tests.
