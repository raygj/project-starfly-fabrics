#!/usr/bin/env python3
"""Rewrite internal doc links to root-absolute paths for Starlight.

Browser-relative links (../voice/, dashboard/, etc.) break under nested URLs.
This script resolves each link against the page slug and emits /{prefix}/...
"""
from __future__ import annotations

import re
import sys
from pathlib import Path

LINK_RE = re.compile(r'\]\((?!https?://|mailto:)([^)]+)\)')


def resolve_link(current_slug: str, target: str) -> str:
    if target.startswith('/'):
        return target

    anchor = ''
    if '#' in target:
        path_part, anchor = target.split('#', 1)
        anchor = '#' + anchor
    else:
        path_part = target

    trailing = path_part.endswith('/')
    segments = current_slug.split('/')

    for part in path_part.rstrip('/').split('/'):
        if part == '..':
            if segments:
                segments.pop()
        elif part == '.':
            pass
        elif part:
            segments.append(part)

    resolved = '/' + '/'.join(segments)
    if trailing or not path_part.rstrip('/'):
        resolved += '/'
    return resolved + anchor


def absolutize_file(path: Path, url_prefix: str, slug_prefix: str) -> bool:
    text = path.read_text()
    rel = path.relative_to(path.parents[2])  # docs/... under content root
    # slug from file path under docs/ or 1.0/docs/
    parts = path.parts
    if '1.0' in parts:
        idx = parts.index('1.0')
        slug = '/'.join(parts[idx:]).replace('.md', '').replace('.mdx', '')
    else:
        idx = parts.index('docs')
        slug = '/'.join(parts[idx:]).replace('.md', '').replace('.mdx', '')

    changed = False

    def repl(m: re.Match[str]) -> str:
        nonlocal changed
        target = m.group(1)
        if target.startswith('/'):
            return m.group(0)
        resolved = resolve_link(slug, target)
        # Map docs/... slug to URL prefix
        if resolved.startswith('/docs/'):
            resolved = url_prefix + resolved[len('/docs') :]
        elif resolved.startswith('/1.0/docs/'):
            resolved = url_prefix + resolved[len('/1.0/docs') :]
        if resolved != target:
            changed = True
        return f"]({resolved})"

    new_text = LINK_RE.sub(repl, text)
    if changed:
        path.write_text(new_text)
    return changed


def main() -> int:
    content_root = Path(__file__).resolve().parents[1] / 'src/content/docs'
    targets = [
        (content_root / 'docs', '/docs', 'docs'),
        (content_root / '1.0/docs', '/1.0/docs', '1.0/docs'),
    ]
    count = 0
    for root, url_prefix, _ in targets:
        if not root.exists():
            continue
        for path in sorted(root.rglob('*')):
            if path.suffix not in {'.md', '.mdx'}:
                continue
            if absolutize_file(path, url_prefix, _):
                print(path.relative_to(content_root))
                count += 1
    print(f'absolutized {count} files', file=sys.stderr)
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
