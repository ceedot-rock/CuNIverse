#!/usr/bin/env bash
# Native compiler required by tests/proof_crosschain.rs. No solc-js substitute.
set -euo pipefail

if [[ "$(uname -s)" != Linux || "$(uname -m)" != x86_64 ]]; then
  echo "This CI installer requires Linux x86_64." >&2
  exit 1
fi

version="0.8.28"
build="solc-linux-amd64-v${version}+commit.7893614a"
# Official linux-amd64/list.json at https://binaries.soliditylang.org/
sha256="9a0fb7e0db2c0641dbae1c5cc645dc686820c83af516226abb1c0a2f76636f25"
install_dir="${SOLC_INSTALL_DIR:-${RUNNER_TEMP:-${TMPDIR:-/tmp}}/cuni-solc-${version}}"
mkdir -p "$install_dir"
download="$(mktemp "$install_dir/solc.download.XXXXXX")"
trap 'rm -f "$download"' EXIT

curl --fail --location --show-error --silent --retry 3 \
  --connect-timeout 15 --max-time 120 \
  "https://binaries.soliditylang.org/linux-amd64/${build}" \
  --output "$download"
printf '%s  %s\n' "$sha256" "$download" | sha256sum --check --strict
chmod 0755 "$download"
"$download" --version | grep -F "Version: ${version}+commit.7893614a"
mv "$download" "$install_dir/solc"

# Subsequent Actions steps (and child processes) must resolve native solc.
if [[ -n "${GITHUB_PATH:-}" ]]; then
  printf '%s\n' "$install_dir" >> "$GITHUB_PATH"
fi
printf 'Installed solc %s in %s\n' "$version" "$install_dir"
