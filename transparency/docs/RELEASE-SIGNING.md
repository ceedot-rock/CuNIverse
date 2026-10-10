# Release Signing Plan (cosign / Sigstore)

> **HONEST HEADER: Planned for the next CuNi release — not yet
> applied.** The workflow template below is ready to install in
> `ceedot-rock/cuni` (see
> [.github/workflows/cosign-template.yml](../.github/workflows/cosign-template.yml)
> in this repo). No CuNi release artifact has been cosign-signed to
> date.

## Goal

Every CuNi release artifact ships with a Sigstore-signed attestation
so a user can verify: *this tarball was built by the cuni repo's
release workflow, not repackaged by a stranger.* Keyless signing via
GitHub OIDC means there is no long-lived private key to steal — the
workflow mints a short-lived signing certificate bound to the repo
identity at release time.

## What gets signed

On every GitHub release publish in `ceedot-rock/cuni`:

- Each release tarball/zip (e.g. `cuni-0.10.0-x86_64-unknown-linux-gnu.tar.gz`)
- `CHECKSUMS.txt` (SHA-256 of every artifact, generated in the same job)
- Optionally: the source tarball (`.crate` / sdist equivalent)

The signed artifacts are:

- `<artifact>.sig` — the cosign signature (bundle format)
- `<artifact>.pem` / certificate chain embedded in the bundle

All of these are uploaded as release assets alongside the artifacts
themselves.

## Signing commands (run in CI)

```sh
# Install cosign (pinned version)
go install github.com/sigstore/cosign/v2/cmd/cosign@v2.2.4

# Sign each artifact, keyless, via the workflow's OIDC identity
cosign sign-blob \
  --yes \
  --bundle "${artifact}.sigstore.json" \
  "${artifact}"
```

`--yes` is safe here because OIDC keyless flow needs no key password;
it just suppresses the interactive confirmation. The bundle
(`.sigstore.json`) contains the signature, the short-lived
certificate, and the Rekor transparency entry — everything a verifier
needs, no separate `.pem` juggling.

## Verification commands (run by the user)

A user who downloaded `cuni-0.10.0-x86_64-unknown-linux-gnu.tar.gz`
and its `.sigstore.json` bundle verifies with:

```sh
cosign verify-blob \
  --bundle cuni-0.10.0-x86_64-unknown-linux-gnu.tar.gz.sigstore.json \
  --certificate-identity \
    "https://github.com/ceedot-rock/cuni/.github/workflows/release.yml@refs/tags/v0.10.0" \
  --certificate-oidc-issuer "https://token.actions.githubusercontent.com" \
  cuni-0.10.0-x86_64-unknown-linux-gnu.tar.gz
```

What this checks:

1. The signature over the artifact is valid.
2. The signing certificate was issued to the **exact workflow
   identity** `https://github.com/ceedot-rock/cuni/.github/workflows/release.yml`
   at the **exact tag** `v0.10.0` (change the tag per release).
3. The certificate came from GitHub's OIDC issuer
   (`https://token.actions.githubusercontent.com`), not a forged one.
4. The signature is recorded in the public Rekor transparency log.

Then check the checksum file covers the artifact:

```sh
sha256sum -c CHECKSUMS.txt
```

(Verifying `CHECKSUMS.txt`'s own bundle first, with the same
`verify-blob` command, closes the loop.)

## Relationship to this repo

The transparency log (`cuni-transparency`) records *receipts* —
statements about CuNi runs. Cosign release signing records
*provenance* — statements about CuNi builds. They are complementary:

- A logged receipt says "this exact output came from this exact input."
- A cosign bundle says "this release artifact came from this repo's
  release workflow."

Neither proves the code is correct. Both prove statements can't be
quietly rewritten after the fact.

## Rollout checklist (for the cuni repo)

- [ ] Install `.github/workflows/cosign-template.yml` from this repo
      into `ceedot-rock/cuni/.github/workflows/`
- [ ] Set the pinned cosign version in the template
- [ ] Confirm the release job has `permissions: id-token: write`
- [ ] Dry-run on a pre-release tag; verify bundles with the user
      commands above
- [ ] Update the cuni README with the verification commands
- [ ] First signed release: announce in this repo's CHANGELOG
