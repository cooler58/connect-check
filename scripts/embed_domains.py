#!/usr/bin/env python3
"""Generate top_domains_embed.h from wordlists/top_domains.txt."""
from pathlib import Path
import sys

def main() -> int:
    root = Path(__file__).resolve().parents[1]
    src = Path(sys.argv[1]) if len(sys.argv) > 1 else root / "wordlists" / "top_domains.txt"
    dst = Path(sys.argv[2]) if len(sys.argv) > 2 else root / "top_domains_embed.h"

    lines = []
    for raw in src.read_text(encoding="utf-8", errors="ignore").splitlines():
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        if len(line) >= 128:
            continue
        if any(c for c in line if not (c.isalnum() or c in ".-")):
            continue
        lines.append(line)

    with dst.open("w", encoding="utf-8") as out:
        out.write("/* auto-generated from wordlists/top_domains.txt — do not edit */\n")
        out.write("#ifndef TOP_DOMAINS_EMBED_H\n#define TOP_DOMAINS_EMBED_H\n\n")
        out.write(f"static const int EMBEDDED_DOMAIN_COUNT = {len(lines)};\n")
        out.write("static const char EMBEDDED_DOMAINS_BLOB[] =\n")
        for d in lines:
            esc = d.replace("\\", "\\\\").replace('"', '\\"')
            out.write(f'    "{esc}\\n"\n')
        out.write(";\n\n#endif\n")
    print(f"embed {len(lines)} domains -> {dst}")
    return 0

if __name__ == "__main__":
    raise SystemExit(main())
