#!/bin/sh
# Download the community WhatsMyName list (600+ sites).
# Usage: scripts/update-sites.sh [output-file]   (default: data/wmn-data.json)
# rectool uses it via: rectool -sites data/wmn-data.json
# install.sh already places a copy where rectool finds it automatically.
set -eu
out="${1:-data/wmn-data.json}"
mkdir -p "$(dirname "$out")"
curl -fsSL https://raw.githubusercontent.com/WebBreacher/WhatsMyName/main/wmn-data.json -o "$out"
grep -q '"sites"' "$out" || { echo "unexpected download content" >&2; exit 1; }
echo "saved $out"
