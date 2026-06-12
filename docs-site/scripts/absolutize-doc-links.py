#!/usr/bin/env python3
"""Rewrite internal doc links to root-absolute paths for Starlight.

Browser-relative links break under nested URLs (/ecosystem/foo/../voice →
/integrators/voice). This script resolves each link against the page slug and
emits /docs/... or /1.0/docs/... URLs.
"""
from __future__ import annotations

import re
import sys
from pathlib import Path

LINK_RE = re.compile(r'\]\((?!https?://|mailto:)([^)]+)\)')

# Top-level doc sections — bare links are relative to docs root, not current page.
ROOT_SECTIONS = frozenset({
    'concepts', 'integrators', 'ecosystem', 'glossary', 'getting-started', 'voice',
})

# Never absolutize — not Starlight pages.
SKIP_PREFIXES = ('sandbox', 'screenshots', '../sandbox', '../../sandbox')


def content_slug(path: Path, content_root: Path) -> str:
    rel = path.relative_to(content_root).with_suffix('').as_posix()
    if rel.endswith('/index') or rel == 'index':
        rel = rel[:-6] if rel.endswith('/index') else ''
    versioned = '1.0' in content_root.parts
    prefix = '1.0/docs' if versioned else 'docs'
    return f'{prefix}/{rel}'.rstrip('/') if rel else prefix


def link_base_slug(path: Path, content_root: Path) -> str:
    """Directory slug for relative link resolution (exclude page filename)."""
    slug = content_slug(path, content_root)
    if path.name == 'index.md':
        return slug
    parts = slug.split('/')
    return '/'.join(parts[:-1]) if len(parts) > 1 else slug


def resolve_link(slug: str, target: str) -> str:
    if target.startswith('/'):
        return target

    anchor = ''
    if '#' in target:
        path_part, anchor = target.split('#', 1)
        anchor = '#' + anchor
    else:
        path_part = target

    trailing = path_part.endswith('/')
    raw = path_part.rstrip('/')

    if not raw:
        segments = slug.split('/')
    else:
        first = raw.split('/')[0]
        if first in ROOT_SECTIONS and not raw.startswith('../'):
            segments = slug.split('/')[:2] if slug.startswith('1.0/') else ['docs']
            for part in raw.split('/'):
                if part and part != '.':
                    segments.append(part)
        else:
            segments = slug.split('/')
            for part in raw.split('/'):
                if part == '..':
                    if segments:
                        segments.pop()
                elif part == '.':
                    pass
                elif part:
                    segments.append(part)

    resolved = '/' + '/'.join(segments)
    if trailing or not raw:
        resolved += '/'
    return resolved + anchor


def should_skip(target: str) -> bool:
    path = target.split('#')[0]
    return any(path == p or path.startswith(p + '/') for p in SKIP_PREFIXES)


def absolutize_file(path: Path, content_root: Path) -> bool:
    base = link_base_slug(path, content_root)
    text = path.read_text()
    changed = False

    def repl(m: re.Match[str]) -> str:
        nonlocal changed
        target = m.group(1)
        if should_skip(target):
            return m.group(0)
        resolved = resolve_link(base, target)
        if resolved != target:
            changed = True
        return f']({resolved})'

    new_text = LINK_RE.sub(repl, text)
    if changed:
        path.write_text(new_text)
    return changed


def validate(content_root: Path) -> list[str]:
    errors: list[str] = []
    for path in sorted(content_root.rglob('*')):
        if path.suffix not in {'.md', '.mdx'}:
            continue
        text = path.read_text()
        if '/docs/docs/' in text:
            errors.append(f'{path}: contains /docs/docs/')
        if re.search(r'/docs/concepts/(?:ecosystem|integrators|getting-started|voice)/', text):
            errors.append(f'{path}: mis-resolved concepts-relative link')
        if re.search(r'/1\.0/docs/concepts/(?:ecosystem|integrators|getting-started|voice)/', text):
            errors.append(f'{path}: mis-resolved concepts-relative link')
        if re.search(r'\]\(\.\./', text):
            errors.append(f'{path}: contains unresolved relative link')
        if re.search(r'\]\((?:integrators|concepts|ecosystem|glossary|voice|getting-started)/', text):
            errors.append(f'{path}: contains bare section link')
    return errors


def main() -> int:
    site_root = Path(__file__).resolve().parents[1] / 'src/content/docs'
    targets = [
        site_root / 'docs',
        site_root / '1.0/docs',
    ]
    count = 0
    for root in targets:
        if not root.exists():
            continue
        for path in sorted(root.rglob('*')):
            if path.suffix not in {'.md', '.mdx'}:
                continue
            if absolutize_file(path, root):
                print(path.relative_to(site_root))
                count += 1

    errors: list[str] = []
    for root in targets:
        errors.extend(validate(root))

    print(f'absolutized {count} files', file=sys.stderr)
    if errors:
        print('link validation failed:', file=sys.stderr)
        for e in errors:
            print(f'  {e}', file=sys.stderr)
        return 1
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
