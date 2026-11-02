#!/usr/bin/env bash
# Иконка exe для Windows: assets/pass2fa.svg → assets/pass2fa.ico → assets/pass2fa.res (линкуется build.rs при MSVC).
# Нужно один раз при смене иконки; результат лежит в git, на Windows ничего не требуется.
# Зависимости: rsvg-convert (librsvg), python3-pillow, llvm-rc.
set -euo pipefail
cd "$(dirname "$0")/../assets"
tmp=$(mktemp -d); trap 'rm -rf "$tmp"' EXIT
sizes=(16 20 24 32 40 48 64 128 256)
for s in "${sizes[@]}"; do rsvg-convert -w "$s" -h "$s" pass2fa.svg -o "$tmp/$s.png"; done
python3 - "$tmp" "${sizes[@]}" <<'PY'
import sys
from PIL import Image
d, sizes = sys.argv[1], [int(s) for s in sys.argv[2:]]
imgs = [Image.open(f"{d}/{s}.png").convert("RGBA") for s in sizes]
imgs[-1].save("pass2fa.ico", format="ICO", sizes=[(s, s) for s in sizes], append_images=imgs[:-1], bitmap_format="bmp")
PY
printf '1 ICON "pass2fa.ico"\n' > "$tmp/pass2fa.rc"
cp pass2fa.ico "$tmp/"
llvm-rc /nologo /fo pass2fa.res "$tmp/pass2fa.rc"
echo "готово: $(pwd)/pass2fa.ico, $(pwd)/pass2fa.res"
