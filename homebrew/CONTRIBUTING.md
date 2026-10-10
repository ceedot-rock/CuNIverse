# Contributing to homebrew-cuni

This is a Homebrew tap for CuNi. Contributions are formula fixes and version
bumps — small, verifiable, and mechanical.

## Ground rules

- **One formula per file** in `Formula/`, named `<name>.rb` matching the class name.
- **Bumps track upstream tags.** When the CuNi project cuts a release (e.g.
  `v0.1.11` on github.com/ceedot-rock/cuni), the formula `url` should point at
  that tagged tarball and `sha256` must be the 64-hex digest of the tarball —
  verified locally with `shasum -a 256`, never copied from memory or guessed.
- **Keep the draft honest.** If a formula is not yet ready for the public tap,
  say so in a comment at the top, as `Formula/cuni.rb` does today.
- **Test before you open a PR.** `ruby -c Formula/*.rb`, and ideally
  `brew install --build-from-source Formula/<name>.rb` plus `brew test <name>`.

## What makes a good pull request

1. One or two sentences on why the change matters (new version, fixed URL, corrected sha256).
2. How the sha256 was verified.
3. The formula checklist in the PR template, filled in.

Bugs with installing or upgrading belong in Issues; security problems go
through SECURITY.md, never a public issue.
