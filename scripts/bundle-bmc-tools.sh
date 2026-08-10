#!/bin/bash
# bundle-bmc-tools.sh — Download bmc-tools for bundling into the app
#
# Usage: ./scripts/bundle-bmc-tools.sh [git-ref]
#   git-ref: branch, tag, or commit to fetch (default: master)
#
# Downloads ANSSI-FR bmc-tools into ./tools/bmc-tools/ for electron-builder.

set -euo pipefail

REF="${1:-${BMC_TOOLS_REF:-master}}"
REPO_URL="${BMC_TOOLS_REPO_URL:-https://github.com/anssi-fr/bmc-tools.git}"
ROOT_DIR="$(cd "$(dirname "$0")/.." && pwd)"
DEST_DIR="$ROOT_DIR/tools/bmc-tools"
TMP_DIR="$(mktemp -d)"

cleanup() {
  rm -rf "$TMP_DIR"
}
trap cleanup EXIT

echo "==> Bundling bmc-tools from $REPO_URL ($REF)"

git clone --depth 1 "$REPO_URL" "$TMP_DIR/bmc-tools" > /dev/null
cd "$TMP_DIR/bmc-tools"

if [ "$REF" != "master" ] && [ "$REF" != "HEAD" ]; then
  git fetch --depth 1 origin "$REF" > /dev/null 2>&1 || true
  git checkout --detach FETCH_HEAD > /dev/null 2>&1 || git checkout "$REF" > /dev/null
fi

COMMIT="$(git rev-parse HEAD)"
VERSION_LINE="$(grep -E '^[0-9]{2}/[0-9]{2}/[0-9]{4}[[:space:]]+[0-9.]+' README.md | head -1 | awk '{print $2}')"

if [ ! -f "bmc-tools.py" ]; then
  echo "ERROR: bmc-tools.py was not found in $REPO_URL at $COMMIT"
  exit 1
fi

rm -rf "$DEST_DIR"
mkdir -p "$DEST_DIR"
cp bmc-tools.py "$DEST_DIR/bmc-tools.py"
cp README.md "$DEST_DIR/README.md"
cp LICENCE.txt "$DEST_DIR/LICENCE.txt"
chmod +x "$DEST_DIR/bmc-tools.py"

{
  echo "{"
  echo "  \"repo\": \"$REPO_URL\","
  echo "  \"ref\": \"$REF\","
  echo "  \"commit\": \"$COMMIT\","
  echo "  \"version\": \"${VERSION_LINE:-unknown}\","
  echo "  \"bundledAt\": \"$(date -u +"%Y-%m-%dT%H:%M:%SZ")\""
  echo "}"
} > "$DEST_DIR/.bmc-tools-source.json"
echo "${VERSION_LINE:-unknown}" > "$DEST_DIR/.bmc-tools-version"

echo "==> Verifying bmc-tools..."
python3 "$DEST_DIR/bmc-tools.py" -h > /dev/null

echo ""
echo "==> bmc-tools ${VERSION_LINE:-unknown} bundled into $DEST_DIR"
echo "==> Commit: $COMMIT"
du -sh "$DEST_DIR"
ls -la "$DEST_DIR"
echo ""
echo "==> Ready for electron-builder (extraResources)"
