#!/usr/bin/env bash
# Сборка расширения: extension/dist/{firefox,chromium} + extension/dist/pass2fa-firefox.xpi (неподписанный)
set -euo pipefail
cd "$(dirname "$0")/../extension"
rm -rf dist && mkdir -p dist
for b in firefox chromium; do
  mkdir -p "dist/$b"
  cp -r src/* "dist/$b/"
  cp "manifest.$b.json" "dist/$b/manifest.json"
done
(cd dist/firefox && zip -qr -X ../pass2fa-firefox.xpi .)
echo "готово: $(pwd)/dist"
