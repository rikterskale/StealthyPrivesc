#!/usr/bin/env bash
set -euo pipefail

repo="${STEALTHY_REPO:-rikterskale/StealthyPrivesc}"
version="${STEALTHY_VERSION:-latest}"
install_dir="${STEALTHY_INSTALL_DIR:-$HOME/.local/bin}"
dry_run=0
while [ "$#" -gt 0 ]; do
  case "$1" in
    --dry-run) dry_run=1 ;;
    *) echo "Unknown option: $1" >&2; exit 2 ;;
  esac
  shift
done

if [ "$dry_run" -eq 1 ]; then
  echo "Would install stealthy ${version} from ${repo}"
  echo "Binary destination: ${install_dir}/stealthy"
  echo "Kit destination: ${STEALTHY_KIT_DIR:-${XDG_DATA_HOME:-$HOME/.local/share}/stealthy/${version}}"
  echo "Validation: SHA256SUMS plus GitHub artifact attestation"
  exit 0
fi

if [ "$version" = "latest" ]; then
  tag="$(curl -fsSL "https://api.github.com/repos/${repo}/releases/latest" | sed -n 's/.*"tag_name": "\([^"]*\)".*/\1/p' | head -n1)"
else
  tag="$version"
fi
[ -n "$tag" ] || { echo "Unable to resolve a release tag" >&2; exit 1; }

case "$(uname -m)" in
  x86_64|amd64) release_arch="x86_64" ;;
  aarch64|arm64) release_arch="aarch64" ;;
  *) echo "Unsupported Linux architecture: $(uname -m)" >&2; exit 1 ;;
esac

asset="stealthy-linux-${release_arch}.tar.gz"
base="https://github.com/${repo}/releases/download/${tag}"
kit_dir="${STEALTHY_KIT_DIR:-${XDG_DATA_HOME:-$HOME/.local/share}/stealthy/${tag}}"
[ "$install_dir" != "/" ] && [ "$kit_dir" != "/" ] || { echo "Refusing to install into /" >&2; exit 1; }

tmp="$(mktemp -d)"
trap 'rm -rf "$tmp"' EXIT
curl -fsSL "${base}/${asset}" -o "$tmp/$asset"
curl -fsSL "${base}/SHA256SUMS" -o "$tmp/RELEASE-SHA256SUMS"

expected="$(awk -v name="$asset" '$2 == name { print $1 }' "$tmp/RELEASE-SHA256SUMS")"
[[ "$expected" =~ ^[[:xdigit:]]{64}$ ]] || { echo "Release checksum for $asset is missing or invalid" >&2; exit 1; }
printf '%s  %s\n' "$expected" "$asset" | (cd "$tmp" && sha256sum -c -)

command -v gh >/dev/null 2>&1 || { echo "GitHub CLI (gh) is required to verify release provenance" >&2; exit 1; }
gh attestation verify "$tmp/$asset" --repo "$repo" \
  --signer-workflow "$repo/.github/workflows/release.yml"

mkdir -p "$tmp/kit"
tar -xzf "$tmp/$asset" -C "$tmp/kit"
test -f "$tmp/kit/stealthy"
test -f "$tmp/kit/RELEASE-MANIFEST.json"
test -f "$tmp/kit/SHA256SUMS"
(cd "$tmp/kit" && sha256sum -c SHA256SUMS)

mkdir -p "$install_dir" "$kit_dir"
cp -a "$tmp/kit/." "$kit_dir/"
install -m 0755 "$tmp/kit/stealthy" "$install_dir/stealthy"
echo "Installed stealthy ${tag} binary to ${install_dir}/stealthy"
echo "Installed verified delivery kit to ${kit_dir}"
echo "Rollback: remove ${install_dir}/stealthy and ${kit_dir} after recording the installed version"
