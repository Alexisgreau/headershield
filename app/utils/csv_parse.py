from __future__ import annotations

import csv
from io import StringIO


def parse_urls_from_text(text: str) -> list[str]:
    urls: list[str] = []
    for line in text.splitlines():
        line = line.strip()
        if not line:
            continue
        urls.append(line)
    return urls


def parse_urls_from_csv(content: str) -> list[str]:
    f = StringIO(content)
    reader = csv.reader(f)
    urls: list[str] = []
    for row in reader:
        if not row:
            continue
        # use first column or column named 'url'
        if len(row) == 1:
            urls.append(row[0])
        else:
            # try header-aware
            urls.append(row[0])
    return urls
