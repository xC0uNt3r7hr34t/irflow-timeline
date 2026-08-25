#!/bin/bash
# bundle-hayabusa.sh — Download Hayabusa binary + rules for bundling into the app
#
# Usage: ./scripts/bundle-hayabusa.sh [version]
#   version: Hayabusa release tag (default: latest)
#
# Downloads the Hayabusa binary + full rules directory into ./hayabusa/ for
# electron-builder to pick up via extraResources. Run before `npm run dist`.
#
# macOS: builds a UNIVERSAL (arm64 + x86_64) binary via `lipo`. The app ships an
# `arch: ["universal"]` mac target, and @electron/universal cannot merge a single-
# arch Mach-O that appears identically in both the x64 and arm64 sub-builds — it
# errors out. A fat binary also means Hayabusa runs natively on Intel Macs, not just
# under Rosetta. Other platforms bundle the single host-arch binary.

set -euo pipefail

VERSION="${1:-latest}"
DEST_DIR="$(cd "$(dirname "$0")/.." && pwd)/hayabusa"
PLATFORM="$(uname -s)"
ARCH="$(uname -m)"

# Get release info
if [ "$VERSION" = "latest" ]; then
  RELEASE_URL="https://api.github.com/repos/Yamato-Security/hayabusa/releases/latest"
else
  RELEASE_URL="https://api.github.com/repos/Yamato-Security/hayabusa/releases/tags/$VERSION"
fi

# Use the GitHub token when present (CI). Unauthenticated API requests are rate-limited
# to 60/hr per IP, and on shared GitHub Actions runner IPs that limit is routinely
# exhausted — the throttled response is a JSON error body with no 'tag_name', which used
# to fail here with a cryptic Python KeyError. An Actions GITHUB_TOKEN raises the limit
# to 1000/hr. Only the API metadata call is authenticated; asset downloads use the
# public browser_download_url and need no auth.
GH_API_ARGS=(-sL -H "Accept: application/vnd.github+json")
GH_TOKEN_VALUE="${GH_TOKEN:-${GITHUB_TOKEN:-}}"
if [ -n "$GH_TOKEN_VALUE" ]; then
  GH_API_ARGS+=(-H "Authorization: Bearer $GH_TOKEN_VALUE")
  echo "==> Using authenticated GitHub API requests"
fi

echo "==> Fetching release info from $RELEASE_URL"
RELEASE_JSON=$(curl "${GH_API_ARGS[@]}" "$RELEASE_URL")
TAG=$(printf '%s' "$RELEASE_JSON" | python3 -c "import json,sys; d=json.load(sys.stdin); print(d.get('tag_name','') if isinstance(d, dict) else '')" 2>/dev/null || true)
if [ -z "$TAG" ]; then
  echo "ERROR: GitHub release API did not return a tag_name (rate-limited or error response)."
  echo "       First 500 bytes of the response:"
  printf '%s\n' "$RELEASE_JSON" | head -c 500; echo
  exit 1
fi
echo "==> Release: $TAG"

# Portable SHA-256 helper (shasum on macOS, sha256sum on most Linux)
sha256_of() {
  if command -v shasum >/dev/null 2>&1; then shasum -a 256 "$1" | awk '{print $1}'
  elif command -v sha256sum >/dev/null 2>&1; then sha256sum "$1" | awk '{print $1}'
  else echo ""; fi
}

# asset_url_digest <pattern> → "url<TAB>digest" for the first matching .zip asset
asset_url_digest() {
  local pattern="$1"
  echo "$RELEASE_JSON" | python3 -c "
import json, sys
data = json.load(sys.stdin)
for a in data['assets']:
    if '$pattern' in a['name'] and a['name'].endswith('.zip') and 'live-response' not in a['name'] and 'all-platforms' not in a['name']:
        print(a['browser_download_url'] + '\t' + (a.get('digest') or ''))
        break
"
}

# download_verify_extract <pattern> <extract_dir> — fetch the matching asset zip,
# verify its published SHA-256, and unzip into <extract_dir> (recreated fresh).
download_verify_extract() {
  local pattern="$1" outdir="$2"
  local info url digest name zip expected actual
  info=$(asset_url_digest "$pattern")
  url=$(printf '%s' "$info" | cut -f1)
  digest=$(printf '%s' "$info" | cut -f2)
  if [ -z "$url" ]; then echo "ERROR: No asset found for pattern '$pattern'"; exit 1; fi
  name=$(basename "$url")
  rm -rf "$outdir"; mkdir -p "$outdir"
  zip="$outdir/$name"
  echo "==> Downloading $name"
  curl -L -o "$zip" "$url"
  echo "==> Downloaded $(du -h "$zip" | cut -f1)"
  if [ -n "$digest" ]; then
    expected="${digest#sha256:}"
    actual="$(sha256_of "$zip")"
    if [ -z "$actual" ]; then echo "ERROR: no SHA-256 tool (shasum/sha256sum) to verify $name"; rm -f "$zip"; exit 1; fi
    if [ "$expected" != "$actual" ]; then
      echo "ERROR: SHA-256 mismatch for $name — refusing to bundle a corrupted/tampered binary"
      echo "  expected: $expected"
      echo "  actual:   $actual"
      rm -f "$zip"; exit 1
    fi
    echo "==> SHA-256 verified: $actual"
  else
    echo "==> WARNING: GitHub published no SHA-256 digest for $name; skipping integrity verification"
  fi
  unzip -o "$zip" -d "$outdir" > /dev/null
  rm -f "$zip"
}

# find_binary <dir> → path to the (versioned or plain) hayabusa binary in <dir>
find_binary() {
  find "$1" -maxdepth 1 -name "hayabusa*" -type f ! -name "*.zip" ! -name "*.txt" ! -name "*.md" ! -name "*.yaml" ! -name "*.css" ! -name "*.png" ! -name "*.jpg" -size +1M | head -1
}

rm -rf "$DEST_DIR"
mkdir -p "$DEST_DIR"

if [ "$PLATFORM" = "Darwin" ]; then
  echo "==> Building UNIVERSAL macOS Hayabusa (arm64 + x86_64) via lipo"
  # arm64 zip populates DEST_DIR with the binary + rules/config; the x64 zip goes to
  # a temp dir — we only need its binary to lipo into a fat universal binary.
  download_verify_extract "mac-aarch64" "$DEST_DIR"
  ARM_BIN="$(find_binary "$DEST_DIR")"
  X64_DIR="$(mktemp -d)"
  download_verify_extract "mac-x64" "$X64_DIR"
  X64_BIN="$(find_binary "$X64_DIR")"
  if [ -z "$ARM_BIN" ] || [ -z "$X64_BIN" ]; then
    echo "ERROR: could not locate both macOS arch binaries (arm64='$ARM_BIN' x64='$X64_BIN')"
    exit 1
  fi
  FINAL_BIN="$DEST_DIR/hayabusa"
  # lipo to a temp name first so it never reads and writes the same path.
  lipo -create "$ARM_BIN" "$X64_BIN" -output "$DEST_DIR/.hayabusa.universal"
  rm -f "$ARM_BIN"
  mv "$DEST_DIR/.hayabusa.universal" "$FINAL_BIN"
  rm -rf "$X64_DIR"
  echo "==> lipo universal binary archs: $(lipo -archs "$FINAL_BIN")"
else
  case "$PLATFORM-$ARCH" in
    Linux-x86_64)   PATTERN="lin-x64-gnu" ;;
    Linux-aarch64)  PATTERN="lin-aarch64-gnu" ;;
    MINGW*|MSYS*)   if [ "$ARCH" = "x86_64" ]; then PATTERN="win-x64"; else PATTERN="win-aarch64"; fi ;;
    *) echo "Unsupported platform: $PLATFORM/$ARCH"; exit 1 ;;
  esac
  echo "==> Bundling Hayabusa for $PLATFORM/$ARCH ($PATTERN)"
  download_verify_extract "$PATTERN" "$DEST_DIR"
  if [ "$PLATFORM" = "MINGW64_NT" ] || [ "$PLATFORM" = "MSYS_NT" ]; then BIN_NAME="hayabusa.exe"; else BIN_NAME="hayabusa"; fi
  FOUND_BIN="$(find_binary "$DEST_DIR")"
  FINAL_BIN="$DEST_DIR/$BIN_NAME"
  if [ -n "$FOUND_BIN" ] && [ "$FOUND_BIN" != "$FINAL_BIN" ]; then mv "$FOUND_BIN" "$FINAL_BIN"; fi
fi

chmod +x "$FINAL_BIN"

# Write version file for the app to read
echo "$TAG" > "$DEST_DIR/.hayabusa-version"

# Apply IRFlow default tuning so bundled installs suppress known noisy rules
# unless the analyst explicitly enables noisy rules.
CONFIG_DIR="$DEST_DIR/rules/config"
NOISY_RULES="$CONFIG_DIR/noisy_rules.txt"
NOTPETYA_RULE_ID="d372ec1b-8c88-6601-d01f-30886bc7ccc4"
mkdir -p "$CONFIG_DIR"
touch "$NOISY_RULES"
if ! grep -qi "^$NOTPETYA_RULE_ID" "$NOISY_RULES"; then
  echo "$NOTPETYA_RULE_ID # NotPetya Ransomware Activity - noisy in broad enterprise hunts" >> "$NOISY_RULES"
  echo "==> Applied IRFlow default noisy rule tuning: NotPetya Ransomware Activity"
fi

# Verify
echo "==> Verifying..."
"$FINAL_BIN" help 2>/dev/null | head -1

echo ""
echo "==> Hayabusa $TAG bundled into $DEST_DIR"
echo "==> Contents:"
du -sh "$DEST_DIR"
ls -la "$DEST_DIR"
echo ""
echo "==> Ready for electron-builder (extraResources)"
