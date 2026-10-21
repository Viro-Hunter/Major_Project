#!/usr/bin/env python3
"""Export Story mode as ONE self-contained HTML file (no server, no install): docs/story.html

    python scripts/build_story.py && python scripts/export_story_html.py

Double-click the file to present offline. Fonts load from Google Fonts when online and fall back to system fonts.
"""
from __future__ import annotations

import json
import re
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
DASH = ROOT / "dashboard"
OUT = ROOT / "docs" / "story.html"


def main() -> int:
    subprocess.run(["npx", "vite", "build"], cwd=DASH, check=True, capture_output=True)
    dist = DASH / "dist"
    html = (dist / "index.html").read_text()
    js = "".join(p.read_text() for p in sorted((dist / "assets").glob("*.js")))
    css = "".join(p.read_text() for p in sorted((dist / "assets").glob("*.css")))
    data = (DASH / "public" / "story_data.json").read_text()
    stix = (DASH / "public" / "story_stix_bundle.json").read_text()
    # Only a literal "</script" can end an inline script early; escape just that (JSON strings and JS
    # string literals read "<\/script" identically; blanket "</" escaping breaks regex literals).
    safe = lambda s: re.sub(r"</(script)", r"<\\/\1", s, flags=re.IGNORECASE)  # noqa: E731
    html = re.sub(r'<script type="module"[^>]*src="[^"]+"></script>', "", html)
    html = re.sub(r'<link rel="stylesheet"[^>]*href="/assets/[^"]+">', "", html)
    html = html.replace('content="width=device-width, initial-scale=1"', 'content="width=device-width, initial-scale=1, viewport-fit=cover"')
    head = (f"<style>html,body{{margin:0;background:#0b1120;color-scheme:dark;}}{css}</style>\n"
            f"<script>window.__STORY_DATA__={safe(data)};window.__STORY_STIX__={safe(stix)};</script>")
    html = html.replace("</head>", head + "\n</head>").replace("<title>Cyber Intelligence GraphRAG</title>",
                                                               "<title>Cyber Intelligence GraphRAG — Story</title>")
    html = html.replace("</body>", f'<script type="module">{safe(js)}</script>\n</body>')
    OUT.parent.mkdir(parents=True, exist_ok=True)
    OUT.write_text(html)
    print(f"{OUT.relative_to(ROOT)}: {OUT.stat().st_size / 1e6:.2f} MB, insider {json.loads(data)['case']['user']}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
