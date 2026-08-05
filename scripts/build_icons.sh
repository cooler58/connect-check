#!/usr/bin/env bash
# Пересборка AppIcon.icns / connect-check.ico / icon_rgba.h из connect-check-1024.png
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
SRC="$ROOT/gui/icons/connect-check-1024.png"
OUT="$ROOT/gui/icons"
test -f "$SRC"

ICONSET="$ROOT/build/AppIcon.iconset"
rm -rf "$ICONSET"
mkdir -p "$ICONSET" "$ROOT/build"

sips -z 16 16   "$SRC" --out "$ICONSET/icon_16x16.png" >/dev/null
sips -z 32 32   "$SRC" --out "$ICONSET/icon_16x16@2x.png" >/dev/null
sips -z 32 32   "$SRC" --out "$ICONSET/icon_32x32.png" >/dev/null
sips -z 64 64   "$SRC" --out "$ICONSET/icon_32x32@2x.png" >/dev/null
sips -z 128 128 "$SRC" --out "$ICONSET/icon_128x128.png" >/dev/null
sips -z 256 256 "$SRC" --out "$ICONSET/icon_128x128@2x.png" >/dev/null
sips -z 256 256 "$SRC" --out "$ICONSET/icon_256x256.png" >/dev/null
sips -z 512 512 "$SRC" --out "$ICONSET/icon_256x256@2x.png" >/dev/null
sips -z 512 512 "$SRC" --out "$ICONSET/icon_512x512.png" >/dev/null
sips -z 1024 1024 "$SRC" --out "$ICONSET/icon_512x512@2x.png" >/dev/null
iconutil -c icns "$ICONSET" -o "$OUT/AppIcon.icns"

# ICO (PNG-in-ICO)
python3 - "$SRC" "$OUT/connect-check.ico" <<'PY'
import struct, subprocess, sys, pathlib, tempfile, os
src, dest = sys.argv[1], sys.argv[2]
sizes = [16, 32, 48, 64, 128, 256]
pngs = []
with tempfile.TemporaryDirectory() as td:
    for s in sizes:
        out = os.path.join(td, f"{s}.png")
        subprocess.check_call(["sips", "-z", str(s), str(s), src, "--out", out],
                              stdout=subprocess.DEVNULL)
        pngs.append((s, pathlib.Path(out).read_bytes()))
buf = bytearray()
buf += struct.pack("<HHH", 0, 1, len(pngs))
offset = 6 + 16 * len(pngs)
entries = []
for s, data in pngs:
    w = 0 if s >= 256 else s
    h = 0 if s >= 256 else s
    entries.append((w, h, len(data), offset, data))
    offset += len(data)
for w, h, size, off, _ in entries:
    buf += struct.pack("<BBBBHHII", w, h, 0, 0, 1, 32, size, off)
for *_, data in entries:
    buf += data
pathlib.Path(dest).write_bytes(buf)
print("ico", dest, len(buf))
PY

sips -z 64 64 "$SRC" --out "$OUT/connect-check-64.png" >/dev/null
python3 - "$OUT/connect-check-64.png" "$OUT/icon_rgba.h" <<'PY'
import struct, zlib, sys, pathlib
data = pathlib.Path(sys.argv[1]).read_bytes()
pos = 8
width = height = bit_depth = color_type = None
idat = b""
while pos < len(data):
    length = struct.unpack(">I", data[pos:pos+4])[0]
    ctype = data[pos+4:pos+8]
    chunk = data[pos+8:pos+8+length]
    pos += 12 + length
    if ctype == b"IHDR":
        width, height, bit_depth, color_type = struct.unpack(">IIBB", chunk[:10])
    elif ctype == b"IDAT":
        idat += chunk
    elif ctype == b"IEND":
        break
raw = zlib.decompress(idat)
bpp = 4 if color_type == 6 else 3
stride = width * bpp
pixels = bytearray()
i = 0
for y in range(height):
    filt = raw[i]; i += 1
    row = bytearray(raw[i:i+stride]); i += stride
    if filt == 1:
        for x in range(bpp, stride):
            row[x] = (row[x] + row[x - bpp]) & 255
    elif filt == 2:
        prev = pixels[(y - 1) * stride : y * stride] if y else bytes(stride)
        for x in range(stride):
            row[x] = (row[x] + prev[x]) & 255
    elif filt == 3:
        prev = pixels[(y - 1) * stride : y * stride] if y else bytes(stride)
        for x in range(stride):
            left = row[x - bpp] if x >= bpp else 0
            row[x] = (row[x] + ((left + prev[x]) // 2)) & 255
    elif filt == 4:
        prev = pixels[(y - 1) * stride : y * stride] if y else bytes(stride)
        for x in range(stride):
            a = row[x - bpp] if x >= bpp else 0
            b = prev[x]
            c = prev[x - bpp] if x >= bpp else 0
            p = a + b - c
            pa, pb, pc = abs(p - a), abs(p - b), abs(p - c)
            pr = a if pa <= pb and pa <= pc else (b if pb <= pc else c)
            row[x] = (row[x] + pr) & 255
    pixels.extend(row)
if bpp == 3:
    rgba = bytearray()
    for j in range(0, len(pixels), 3):
        rgba.extend(pixels[j : j + 3]); rgba.append(255)
    pixels = rgba
out = pathlib.Path(sys.argv[2])
with out.open("w") as f:
    f.write("/* auto-generated RGBA window icon — scripts/build_icons.sh */\n")
    f.write(f"#define CC_ICON_W {width}\n#define CC_ICON_H {height}\n")
    f.write(f"static const unsigned char cc_icon_rgba[{width * height * 4}] = {{\n")
    for j in range(0, len(pixels), 12):
        chunk = pixels[j : j + 12]
        f.write("  " + ", ".join(f"0x{b:02x}" for b in chunk) + ",\n")
    f.write("};\n")
print("rgba", out, out.stat().st_size)
PY

echo "OK → $OUT/AppIcon.icns $OUT/connect-check.ico $OUT/icon_rgba.h"
