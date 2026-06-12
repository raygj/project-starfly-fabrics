#!/usr/bin/env bash
# Copy docs/ into Starlight content trees and rewrite internal links to absolute URLs.
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
DOCS="$ROOT/docs"
SITE="$ROOT/docs-site"

while IFS= read -r -d '' f; do
  rel="${f#"$DOCS"/}"
  [[ "$rel" == "README.md" ]] && continue
  mkdir -p "$SITE/src/content/docs/docs/$(dirname "$rel")"
  cp "$f" "$SITE/src/content/docs/docs/$rel"
  mkdir -p "$SITE/src/content/docs/1.0/docs/$(dirname "$rel")"
  cp "$f" "$SITE/src/content/docs/1.0/docs/$rel"
done < <(find "$DOCS" -name '*.md' -print0)

cp "$DOCS/VOICE.md" "$SITE/src/content/docs/docs/voice.md"
cp "$DOCS/VOICE.md" "$SITE/src/content/docs/1.0/docs/voice.md"
rm -rf "$SITE/src/content/docs/docs/screenshots" "$SITE/src/content/docs/1.0/docs/screenshots"

python3 "$SITE/scripts/absolutize-doc-links.py" || exit 1

python3 - "$SITE" <<'PY'
import re
import sys
from pathlib import Path

site = Path(sys.argv[1])
v10 = site / "src/content/docs/1.0/docs"
for path in v10.rglob("*.md"):
    rel = path.relative_to(v10).as_posix()
    if rel == "ecosystem/index.md":
        slug = "1.0/docs/ecosystem"
    elif rel.endswith("/index.md"):
        slug = f"1.0/docs/{rel[:-9]}"
    else:
        slug = f"1.0/docs/{rel[:-3]}"
    text = path.read_text()
    if re.search(r"^slug:", text, re.M):
        text = re.sub(r"^slug:.*\n", f"slug: {slug}\n", text, count=1, flags=re.M)
    else:
        text = re.sub(
            r"(---\n(?:title:.*\n)(?:description:.*\n))",
            rf"\1slug: {slug}\n",
            text,
            count=1,
        )
    path.write_text(text)
PY
