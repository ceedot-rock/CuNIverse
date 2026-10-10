# keys/

- `bootstrap-pubkey.hex` — Ed25519 public key (hex, 32 bytes) of the
  **BOOTSTRAP / TEST** log key. Generated 2026-10-09 on a lab VM with
  Python `cryptography`; it has no ceremony behind it and must never be
  treated as a production root of trust.
- The matching private key lives in `.bootstrap-key` at the repo root
  (gitignored, mode 600). It is used only to sign test fixtures.
  **Never commit it.**

The production root key gets a proper key ceremony later. The rotation
policy lives in `docs/` (KEY-ROTATION.md); its implementation in the
publisher and `verify.sh` is deferred.
