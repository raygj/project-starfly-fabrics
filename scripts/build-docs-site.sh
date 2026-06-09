#!/usr/bin/env bash
# Generate static doc viewer pages under public/docs/
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
TEMPLATE='$ROOT/public/docs/_page.template.html'

PAGE_DOC=(
  "getting-started:getting-started"
  "glossary:glossary"
  "concepts/trust-domains:concepts/trust-domains"
  "concepts/exchange:concepts/exchange"
  "concepts/revocation:concepts/revocation"
  "integrators/token-exchange:integrators/token-exchange"
  "integrators/mcp:integrators/mcp"
)

read -r -d '' PAGE_HTML << 'EOF' || true
<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>Docs — Starfly</title>
  <link rel="stylesheet" href="/docs/assets/doc.css">
  <script src="https://cdn.jsdelivr.net/npm/marked/marked.min.js"></script>
</head>
<body data-doc="__DOC__">
  <header>
    <div class="logo"><a href="/">Starfly</a> / <a href="/docs/">Docs</a></div>
    <nav>
      <a href="/play">Playground</a>
      <a href="https://github.com/raygj/project-starfly-fabrics">GitHub</a>
    </nav>
  </header>
  <div class="layout">
    <aside class="sidebar" id="sidebar"></aside>
    <article id="content"><p class="loading">Loading…</p></article>
  </div>
  <script src="/docs/assets/doc.js"></script>
</body>
</html>
EOF

mkdir -p "$ROOT/public/docs/content/concepts" "$ROOT/public/docs/content/integrators"
cp "$ROOT/docs/getting-started.md" "$ROOT/docs/glossary.md" "$ROOT/public/docs/content/"
cp "$ROOT/docs/concepts/"*.md "$ROOT/public/docs/content/concepts/"
cp "$ROOT/docs/integrators/"*.md "$ROOT/public/docs/content/integrators/"

for entry in "${PAGE_DOC[@]}"; do
  path="${entry%%:*}"
  doc="${entry##*:}"
  dir="$ROOT/public/docs/$path"
  mkdir -p "$dir"
  echo "${PAGE_HTML//__DOC__/$doc}" > "$dir/index.html"
done

echo "built ${#PAGE_DOC[@]} doc pages under public/docs/"
