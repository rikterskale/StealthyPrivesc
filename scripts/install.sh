#!/usr/bin/env bash
set -euo pipefail

repo="${STEALTHY_REPO:-rikterskale/StealthyPrivesc}"
version="${STEALTHY_VERSION:-latest}"
install_dir="${STEALTHY_INSTALL_DIR:-$HOME/.local/bin}"
mkdir -p "$install_dir"

if [ "${version}" = "latest" ]; then
  tag="$(curl -fsSL "https://api.github.com/repos/${repo}/releases/latest" | sed -n 's/.*"tag_name": "\([^"]*\)".*/\1/p' | head -n1)"
else
  tag="$version"
fi
[ -n "$tag" ] || { echo "Unable to resolve a release tag" >&2; exit 1; }

asset="stealthy-linux-x86_64.tar.gz"
base="https://github.com/${repo}/releases/download/${tag}"
tmp="$(mktemp -d)"
trap 'rm -rf "$tmp"' EXIT
curl -fsSL "${base}/${asset}" -o "$tmp/$asset"
curl -fsSL "${base}/SHA256SUMS" -o "$tmp/SHA256SUMS"
command -v gh >/dev/null 2>&1 || { echo "GitHub CLI (gh) is required to verify release provenance" >&2; exit 1; }
gh attestation verify "$tmp/$asset" --repo "$repo" \
  --signer-workflow "$repo/.github/workflows/release.yml"
(cd "$tmp" && grep " $asset$" SHA256SUMS | sha256sum -c -)
tar -xzf "$tmp/$asset" -C "$tmp"
install -m 0755 "$tmp/stealthy" "$install_dir/stealthy"
echo "Installed stealthy ${tag} to ${install_dir}/stealthy"
