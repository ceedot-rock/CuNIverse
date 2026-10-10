# CuNIverse

One law, four organs: **the same output on every target, or refuse.**

| Organ | Path | What it is |
|---|---|---|
| Compiler | `/` (root) | CuNi proper: `.cuni` in, byte-identical output across 53 catalog entries or REFUSE. `cuni check`, `cuni run`, `cuni audit`, chain emitters. Start at [README.md](README.md). |
| Transparency | `transparency/` | Append-only Merkle log (RFC 6962) anchoring signed exactness receipts in git. Proves existence + self-consistency, not truth. |
| Exactness | `exactness/` | The EXACT-or-REFUSE skill: `submit(source)` builds and runs every local seat, returns fingerprints or a diff. |
| Tap | `homebrew/` | The Homebrew tap: `brew install ceedot-rock/cuni/cuni`. |

## Provenance

This monorepo was fused from four repos with full history preserved
(merge commits, not squashes):

- `cuni` → root (branch `master`)
- `cuni-transparency` → `transparency/` (was `main`)
- `cuni-exactness` → `exactness/` (was `main`)
- `homebrew-cuni` → `homebrew/` (was `main`)

One tag caveat: `v0.1.0` existed in three source repos; here it resolves
to cuni's. All commits remain reachable through the merge parents.

Forget trust. Prove.
