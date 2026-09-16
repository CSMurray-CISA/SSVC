#!/usr/bin/env python3
"""Discover Oracle CPU/CSPU advisories and cache their official CSAF documents."""

from __future__ import annotations

import json
import re
import time
from datetime import datetime, timezone
from html.parser import HTMLParser
from pathlib import Path
from urllib.parse import urljoin, urlparse
from urllib.request import Request, urlopen

INDEX_URL = "https://www.oracle.com/security-alerts/"
ROOT = Path(__file__).resolve().parents[1]
OUT = ROOT / "oracle-data"
MAX_RELEASES = 12
MONTHS = {name.lower(): number for number, name in enumerate(
    ("", "jan", "feb", "mar", "apr", "may", "jun", "jul", "aug", "sep", "oct", "nov", "dec")
) if name}
ADVISORY_RE = re.compile(r"^(cpu|cspu)(jan|feb|mar|apr|may|jun|jul|aug|sep|oct|nov|dec)(20\d{2})\.html$", re.I)


class LinkParser(HTMLParser):
    def __init__(self) -> None:
        super().__init__()
        self.links: list[tuple[str, str]] = []
        self._href: str | None = None
        self._text: list[str] = []

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        if tag.lower() == "a":
            self._href = dict(attrs).get("href")
            self._text = []

    def handle_data(self, data: str) -> None:
        if self._href is not None:
            self._text.append(data)

    def handle_endtag(self, tag: str) -> None:
        if tag.lower() == "a" and self._href is not None:
            self.links.append((self._href, " ".join("".join(self._text).split())))
            self._href = None
            self._text = []


def fetch(url: str, attempts: int = 3) -> bytes:
    error: Exception | None = None
    for attempt in range(attempts):
        try:
            req = Request(url, headers={"User-Agent": "Oracle-SSVC-Dashboard/1.0"})
            with urlopen(req, timeout=90) as response:
                return response.read()
        except Exception as exc:  # pragma: no cover - network behavior
            error = exc
            if attempt + 1 < attempts:
                time.sleep(2 ** attempt)
    raise RuntimeError(f"Failed to download {url}: {error}")


def links(html: bytes) -> list[tuple[str, str]]:
    parser = LinkParser()
    parser.feed(html.decode("utf-8", errors="replace"))
    return parser.links


def advisory_key(url: str) -> tuple[int, int, int]:
    match = ADVISORY_RE.match(Path(urlparse(url).path).name)
    if not match:
        return (0, 0, 0)
    kind, month, year = match.groups()
    return (int(year), MONTHS[month.lower()], 1 if kind.lower() == "cspu" else 0)


def discover_advisories(index_html: bytes) -> list[tuple[str, str]]:
    found: dict[str, str] = {}
    for href, title in links(index_html):
        absolute = urljoin(INDEX_URL, href)
        if ADVISORY_RE.match(Path(urlparse(absolute).path).name):
            found[absolute] = title
    return sorted(found.items(), key=lambda item: advisory_key(item[0]), reverse=True)[:MAX_RELEASES]


def find_csaf(advisory_url: str, advisory_html: bytes) -> str | None:
    for href, _ in links(advisory_html):
        absolute = urljoin(advisory_url, href)
        if re.search(r"csaf\.json(?:$|[?#])", absolute, re.I):
            return absolute
    return None


def release_record(advisory_url: str, fallback_title: str, csaf_url: str, doc: dict) -> dict:
    tracking = doc.get("document", {}).get("tracking", {})
    release_id = tracking.get("id") or Path(urlparse(advisory_url).path).stem
    title = doc.get("document", {}).get("title") or fallback_title or release_id
    title = re.sub(r"\s+-\s+Oracle CSAF\s*$", "", title)
    return {
        "id": release_id,
        "title": title,
        "release_date": tracking.get("initial_release_date", ""),
        "updated": tracking.get("current_release_date", ""),
        "advisory_url": advisory_url,
        "csaf_url": csaf_url,
        "data": f"oracle-data/{release_id}.json",
    }


def main() -> None:
    OUT.mkdir(parents=True, exist_ok=True)
    advisories = discover_advisories(fetch(INDEX_URL))
    if not advisories:
        raise RuntimeError("No Oracle CPU or CSPU advisory links were discovered")

    releases: list[dict] = []
    errors: list[str] = []
    for advisory_url, title in advisories:
        try:
            advisory_html = fetch(advisory_url)
            csaf_url = find_csaf(advisory_url, advisory_html)
            if not csaf_url:
                errors.append(f"No CSAF link: {advisory_url}")
                continue
            doc = json.loads(fetch(csaf_url))
            record = release_record(advisory_url, title, csaf_url, doc)
            (OUT / f"{record['id']}.json").write_text(
                json.dumps(doc, separators=(",", ":"), ensure_ascii=False), encoding="utf-8"
            )
            releases.append(record)
        except Exception as exc:
            errors.append(f"{advisory_url}: {exc}")

    if not releases:
        raise RuntimeError("No Oracle CSAF documents were downloaded: " + "; ".join(errors))
    releases.sort(key=lambda item: item.get("release_date", ""), reverse=True)
    manifest = {
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "source": INDEX_URL,
        "releases": releases,
        "warnings": errors,
    }
    (OUT / "releases.json").write_text(json.dumps(manifest, indent=2) + "\n", encoding="utf-8")
    print(f"Updated {len(releases)} Oracle releases ({len(errors)} warnings).")


if __name__ == "__main__":
    main()
