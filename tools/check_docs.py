#!/usr/bin/env python3
"""Validate repository Markdown JSON examples and relative file links."""
import json
from pathlib import Path
import re
from urllib.parse import unquote, urlsplit

root = Path(__file__).resolve().parents[1]
json_count = 0
link_count = 0
for document in root.glob("*.md"):
    content = document.read_text(encoding="utf-8")
    for match in re.finditer(r"(?ms)^(?:```|~~~)json\s*\n(.*?)^(?:```|~~~)\s*$", content):
        json.loads(match.group(1))
        json_count += 1
    for target in re.findall(r"(?<!!)\[[^\]]+\]\(([^\s)]+)\)", content):
        parts = urlsplit(target.strip("<>"))
        if parts.scheme or parts.netloc or not parts.path:
            continue
        path = document.parent / unquote(parts.path)
        if not path.exists():
            raise SystemExit(f"Broken local link in {document.name}: {target}")
        link_count += 1
fixtures = list((root / "tests" / "fixtures").glob("*.json"))
for fixture in fixtures:
    json.loads(fixture.read_text(encoding="utf-8"))
print(f"Passed: {json_count} JSON examples, {link_count} local file links, {len(fixtures)} provider fixtures.")
