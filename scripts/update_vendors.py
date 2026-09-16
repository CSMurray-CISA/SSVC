#!/usr/bin/env python3
"""Refresh normalized vulnerability data for public vendor advisory sites."""

from __future__ import annotations

import calendar
import json
import re
import time
import xml.etree.ElementTree as ET
from collections import defaultdict
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import urljoin, urlparse

import requests
from bs4 import BeautifulSoup, Tag

ROOT = Path(__file__).resolve().parents[1]
OUT = ROOT / "vendor-data"
MAX_RELEASES = 12
CVE_RE = re.compile(r"CVE-\d{4}-\d{4,7}", re.I)
VECTOR_RE = re.compile(r"CVSS:[234]\.\d/[^\s<>()]+", re.I)
SCORE_RE = re.compile(r"(?<!\d)(10\.0|[0-9](?:\.\d)?)(?!\d)")
SESSION = requests.Session()
SESSION.headers.update({"User-Agent": "Multi-Vendor-SSVC-Dashboard/2.0 (+GitHub Pages data refresh)"})

VENDORS = {
    "adobe": ("Adobe", "https://helpx.adobe.com/security/security-bulletin.html"),
    "apple": ("Apple", "https://support.apple.com/en-us/100100"),
    "cisco": ("Cisco", "https://sec.cloudapps.cisco.com/security/center/publicationListing.x"),
    "fortinet": ("Fortinet", "https://www.fortiguard.com/psirt"),
    "mediatek": ("MediaTek", "https://www.mediatek.com/product-security-bulletin"),
    "mozilla": ("Mozilla", "https://www.mozilla.org/en-US/security/advisories/"),
    "qualcomm": ("Qualcomm", "https://docs.qualcomm.com/securitybulletin/"),
    "solarwinds": ("SolarWinds", "https://www.solarwinds.com/trust-center/security-advisories"),
}


def fetch(url: str, *, json_data: bool = False):
    last = None
    for attempt in range(3):
        try:
            response = SESSION.get(url, timeout=90)
            response.raise_for_status()
            return response.json() if json_data else response.text
        except Exception as exc:
            last = exc
            if attempt < 2:
                time.sleep(2**attempt)
    raise RuntimeError(f"Failed to download {url}: {last}")


def soup(url: str) -> BeautifulSoup:
    return BeautifulSoup(fetch(url), "html.parser")


def clean(value) -> str:
    return " ".join(str(value or "").replace("\xa0", " ").split())


def slug(url: str) -> str:
    value = Path(urlparse(url).path.rstrip("/")).name or "latest"
    return re.sub(r"[^a-z0-9._-]+", "-", value.lower()).strip("-")[:120]


def severity(value: str, score: str = "") -> str:
    raw = clean(value).upper()
    if "CRITICAL" in raw:
        return "CRITICAL"
    if "HIGH" in raw:
        return "HIGH"
    if "MODERATE" in raw or "MEDIUM" in raw:
        return "MEDIUM"
    if "LOW" in raw:
        return "LOW"
    try:
        number = float(score)
        return "CRITICAL" if number >= 9 else "HIGH" if number >= 7 else "MEDIUM" if number >= 4 else "LOW"
    except (TypeError, ValueError):
        return "UNKNOWN"


def make_record(cve: str, *, description: str = "", vector: str = "", score: str = "",
                sev: str = "", product: str = "", component: str = "", details: dict | None = None) -> dict:
    score_value = clean(score)
    return {
        "cve": cve.upper(),
        "description": clean(description),
        "vector": clean(vector).rstrip(".,;"),
        "cvss": score_value,
        "severity": severity(sev, score_value),
        "product": clean(product),
        "component": clean(component),
        "exploitation": "none",
        "details": details or {},
    }


def page_title(doc: BeautifulSoup, fallback: str) -> str:
    h1 = doc.find("h1")
    return clean(h1.get_text(" ", strip=True) if h1 else (doc.title.string if doc.title else fallback))


def page_date(doc: BeautifulSoup) -> str:
    text = clean(doc.get_text(" ", strip=True))
    patterns = (
        r"(?:Released|Announced|Published|Date Published|First Published)[: ]+([A-Z][a-z]+ \d{1,2},? \d{4})",
        r"(?:Released|Published)[: ]+(\d{4}-\d{2}-\d{2})",
        r"(?:Published|Release date)[: ]+(\d{1,2} [A-Z][a-z]+ \d{4})",
        r"(\d{2}/\d{2}/\d{4})",
    )
    for pattern in patterns:
        match = re.search(pattern, text, re.I)
        if match:
            return match.group(1)
    return ""


def link_list(doc: BeautifulSoup, base: str, pattern: re.Pattern, limit: int = MAX_RELEASES * 3) -> list[tuple[str, str]]:
    seen, output = set(), []
    for anchor in doc.find_all("a", href=True):
        url = urljoin(base, anchor["href"])
        if url in seen or not pattern.search(url):
            continue
        seen.add(url)
        output.append((url, clean(anchor.get_text(" ", strip=True)) or slug(url)))
        if len(output) >= limit:
            break
    return output


def generic_table_records(doc: BeautifulSoup, title: str) -> list[dict]:
    output, seen = [], set()
    for row in doc.find_all("tr"):
        cells = [clean(cell.get_text(" ", strip=True)) for cell in row.find_all(["th", "td"])]
        blob = " | ".join(cells)
        cves = CVE_RE.findall(blob)
        if not cves:
            continue
        vector_match = VECTOR_RE.search(blob)
        vector = vector_match.group(0) if vector_match else ""
        score = ""
        if vector:
            before = blob[:vector_match.start()]
            scores = SCORE_RE.findall(before)
            score = scores[-1] if scores else ""
        sev = next((word for word in ("Critical", "High", "Medium", "Moderate", "Low") if word.lower() in blob.lower()), "")
        description = " — ".join(x for x in cells[:2] if x and not CVE_RE.fullmatch(x)) or title
        for cve in cves:
            key = cve.upper()
            if key in seen:
                continue
            seen.add(key)
            output.append(make_record(cve, description=description, vector=vector, score=score, sev=sev, product=title,
                                      details={"source_row": cells}))
    return output


def generic_cve_records(doc: BeautifulSoup, title: str) -> list[dict]:
    text = clean(doc.get_text(" ", strip=True))
    output = []
    for cve in dict.fromkeys(x.upper() for x in CVE_RE.findall(text)):
        position = text.upper().find(cve)
        nearby = text[max(0, position - 300):position + 700]
        vector_match = VECTOR_RE.search(nearby)
        vector = vector_match.group(0) if vector_match else ""
        output.append(make_record(cve, description=nearby[:500], vector=vector, product=title))
    return output


def parse_adobe(url: str) -> dict:
    doc = soup(url)
    title = page_title(doc, "Adobe Security Bulletin")
    records = generic_table_records(doc, title) or generic_cve_records(doc, title)
    page_text = clean(doc.get_text(" ", strip=True)).lower()
    if "aware of" in page_text and "exploited in the wild" in page_text and "not aware" not in page_text:
        for item in records:
            item["exploitation"] = "active"
    return normalized("adobe", title, url, page_date(doc), records)


def following_block(heading: Tag) -> str:
    chunks = []
    for sibling in heading.next_siblings:
        if isinstance(sibling, Tag) and sibling.name == heading.name:
            break
        if isinstance(sibling, Tag):
            chunks.append(clean(sibling.get_text(" ", strip=True)))
    return clean(" ".join(chunks))


def parse_apple(url: str) -> dict:
    doc = soup(url)
    title = page_title(doc, "Apple Security Update")
    records = []
    for heading in doc.find_all("h3"):
        block = following_block(heading)
        impact = re.search(r"Impact:\s*(.*?)(?:Description:|CVE-)", block, re.I)
        description = impact.group(1) if impact else block[:500]
        for cve in dict.fromkeys(CVE_RE.findall(block)):
            records.append(make_record(cve, description=description, product=title,
                                       component=heading.get_text(" ", strip=True), details={"vendor_text": block}))
    return normalized("apple", title, url, page_date(doc), records)


def csaf_records(data: dict, product: str) -> list[dict]:
    output = []
    for vuln in data.get("vulnerabilities", []):
        cve = vuln.get("cve")
        if not cve:
            continue
        scores = []
        for score_set in vuln.get("scores", []):
            for key in ("cvss_v4", "cvss_v3", "cvss_v2"):
                if score_set.get(key):
                    scores.append(score_set[key])
        score = sorted(scores, key=lambda x: (float(x.get("version", 0) or 0), float(x.get("baseScore", 0) or 0)), reverse=True)
        top = score[0] if score else {}
        notes = vuln.get("notes", [])
        description = next((n.get("text", "") for n in notes if n.get("category") in ("description", "summary")), "")
        output.append(make_record(cve, description=description, vector=top.get("vectorString", ""),
                                  score=str(top.get("baseScore", "")), sev=top.get("baseSeverity", ""),
                                  product=product, details={"notes": notes, "remediations": vuln.get("remediations", [])}))
    return output


def parse_cisco(url: str) -> dict:
    doc = soup(url)
    title = page_title(doc, "Cisco Security Advisory")
    csaf_url = next((urljoin(url, a["href"]) for a in doc.find_all("a", href=True)
                     if "/csaf/" in a["href"].lower() and a["href"].lower().endswith(".json")), None)
    records = csaf_records(fetch(csaf_url, json_data=True), title) if csaf_url else generic_table_records(doc, title)
    return normalized("cisco", title, url, page_date(doc), records)


def parse_fortinet(url: str) -> dict:
    doc = soup(url)
    title = page_title(doc, "Fortinet PSIRT Advisory")
    return normalized("fortinet", title, url, page_date(doc), generic_table_records(doc, title) or generic_cve_records(doc, title))


def parse_mediatek(url: str) -> dict:
    doc = soup(url)
    title = page_title(doc, "MediaTek Security Bulletin")
    rows = []
    for tr in doc.find_all("tr"):
        cells = [clean(x.get_text(" ", strip=True)) for x in tr.find_all(["th", "td"])]
        if len(cells) >= 2:
            rows.append((cells[0].rstrip(":"), " | ".join(cells[1:])))
    records, current = [], None
    for label, value in rows:
        if label.upper() == "CVE" and CVE_RE.search(value):
            if current:
                records.append(current)
            current = make_record(CVE_RE.search(value).group(0), product="MediaTek chipsets", details={})
        elif current:
            current["details"][label] = value
            if label.lower() == "description": current["description"] = value
            elif label.lower() == "severity": current["severity"] = severity(value)
            elif label.lower() == "subcomponent": current["component"] = value
            elif label.lower() == "affected chipsets": current["product"] = value
    if current:
        records.append(current)
    return normalized("mediatek", title, url, page_date(doc), records)


def parse_mozilla(url: str) -> dict:
    doc = soup(url)
    title = page_title(doc, "Mozilla Security Advisory")
    records = []
    for heading in doc.find_all(["h3", "h4"]):
        heading_text = clean(heading.get_text(" ", strip=True))
        cves = CVE_RE.findall(heading_text)
        if not cves:
            continue
        block = following_block(heading)
        impact = re.search(r"Impact\s+(critical|high|moderate|medium|low)", block, re.I)
        for cve in cves:
            records.append(make_record(cve, description=block[:800], sev=impact.group(1) if impact else "",
                                       product=title, details={"vendor_text": block}))
    return normalized("mozilla", title, url, page_date(doc), records)


def parse_qualcomm(url: str) -> dict:
    doc = soup(url)
    title = page_title(doc, "Qualcomm Security Bulletin")
    return normalized("qualcomm", title, url, page_date(doc), generic_table_records(doc, title) or generic_cve_records(doc, title))


def parse_solarwinds(url: str) -> dict:
    doc = soup(url)
    title = page_title(doc, "SolarWinds Security Advisory")
    text = clean(doc.get_text(" ", strip=True))
    sev_match = re.search(r"Severity\s+(Critical|High|Medium|Low|N/A)", text, re.I)
    records = generic_table_records(doc, title) or [make_record(cve, description=title,
              sev=sev_match.group(1) if sev_match else "", product=title, details={"vendor_text": text[:1500]})
              for cve in dict.fromkeys(CVE_RE.findall(text))]
    return normalized("solarwinds", title, url, page_date(doc), records)


PARSERS = {"adobe": parse_adobe, "apple": parse_apple, "cisco": parse_cisco, "fortinet": parse_fortinet,
           "mediatek": parse_mediatek, "mozilla": parse_mozilla, "qualcomm": parse_qualcomm,
           "solarwinds": parse_solarwinds}


def normalized(vendor: str, title: str, url: str, release_date: str, records: list[dict]) -> dict:
    unique = {item["cve"]: item for item in records if item.get("cve")}
    return {"vendor": VENDORS[vendor][0], "vendor_id": vendor, "title": title, "source_url": url,
            "release_date": release_date, "vulnerabilities": list(unique.values())}


def rss_links(url: str) -> list[tuple[str, str]]:
    doc = ET.fromstring(fetch(url))
    output = []
    for item in doc.findall(".//item")[:MAX_RELEASES * 3]:
        link = clean(item.findtext("link", ""))
        title = clean(item.findtext("title", "")) or slug(link)
        if link:
            output.append((link, title))
    return output


def month_urls(template: str, count: int = MAX_RELEASES) -> list[tuple[str, str]]:
    now = datetime.now(timezone.utc)
    output = []
    year, month = now.year, now.month
    for _ in range(count + 8):
        name = calendar.month_name[month]
        output.append((template.format(month=name.lower(), Month=name, year=year), f"{name} {year}"))
        month -= 1
        if month == 0:
            month, year = 12, year - 1
    return output


def discover(vendor: str) -> list[tuple[str, str]]:
    if vendor == "adobe":
        return link_list(soup(VENDORS[vendor][1]), VENDORS[vendor][1], re.compile(r"/security/products/.+/aps[ab]\d{2}-\d+\.html", re.I))
    if vendor == "apple":
        return link_list(soup(VENDORS[vendor][1]), VENDORS[vendor][1], re.compile(r"support\.apple\.com/(?:[a-z-]+/)?\d{5,}", re.I))
    if vendor == "cisco":
        return rss_links("https://sec.cloudapps.cisco.com/security/center/psirtrss10/CiscoSecurityAdvisory.xml")
    if vendor == "fortinet":
        return rss_links("https://filestore.fortinet.com/fortiguard/rss/ir.xml")
    if vendor == "mediatek":
        return month_urls("https://www.mediatek.com/product-security-bulletin/{Month}-{year}")
    if vendor == "mozilla":
        return link_list(soup(VENDORS[vendor][1]), VENDORS[vendor][1], re.compile(r"/security/advisories/mfsa\d{4}-\d+/?$", re.I))
    if vendor == "qualcomm":
        return month_urls("https://docs.qualcomm.com/securitybulletin/{month}-{year}-bulletin.html")
    if vendor == "solarwinds":
        return link_list(soup(VENDORS[vendor][1]), VENDORS[vendor][1], re.compile(r"/trust-center/security-advisories/.+", re.I))
    return []


def load_kev() -> dict[str, dict]:
    data = fetch("https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json", json_data=True)
    return {item["cveID"].upper(): item for item in data.get("vulnerabilities", [])}


def enrich_kev(doc: dict, kev: dict[str, dict]) -> None:
    for item in doc.get("vulnerabilities", []):
        match = kev.get(item["cve"])
        if match:
            item["exploitation"] = "active"
            item["kev"] = match


def write_vendor(vendor: str, kev: dict[str, dict], warnings: list[str]) -> list[dict]:
    directory = OUT / vendor
    directory.mkdir(parents=True, exist_ok=True)
    releases = []
    for url, fallback_title in discover(vendor):
        if len(releases) >= MAX_RELEASES:
            break
        try:
            doc = PARSERS[vendor](url)
            if not doc["vulnerabilities"]:
                raise RuntimeError("no CVE records found")
            enrich_kev(doc, kev)
            file_id = slug(url) + ".json"
            (directory / file_id).write_text(json.dumps(doc, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
            releases.append({"id": file_id[:-5], "title": doc["title"] or fallback_title,
                             "release_date": doc["release_date"], "advisory_url": url,
                             "data": f"vendor-data/{vendor}/{file_id}", "count": len(doc["vulnerabilities"])})
        except Exception as exc:
            warnings.append(f"{VENDORS[vendor][0]} {url}: {exc}")
    if not releases:
        raise RuntimeError(f"No usable {VENDORS[vendor][0]} advisories were parsed; existing data was preserved")
    manifest = {"generated_at": datetime.now(timezone.utc).isoformat(), "vendor": VENDORS[vendor][0],
                "source": VENDORS[vendor][1], "releases": releases, "warnings": [x for x in warnings if x.startswith(VENDORS[vendor][0])]}
    (directory / "releases.json").write_text(json.dumps(manifest, indent=2) + "\n", encoding="utf-8")
    return releases


def build_exploited(kev: dict[str, dict]) -> None:
    merged: dict[str, dict] = {}
    documents = []
    for path in OUT.glob("*/*.json"):
        if path.name == "releases.json":
            continue
        try:
            documents.append(json.loads(path.read_text(encoding="utf-8")))
        except Exception:
            continue
    for path in (ROOT / "oracle-data").glob("*.json"):
        if path.name == "releases.json":
            continue
        try:
            raw = json.loads(path.read_text(encoding="utf-8"))
            title = raw.get("document", {}).get("title", "Oracle Security Advisory")
            refs = raw.get("document", {}).get("references", [])
            url = next((x.get("url") for x in refs if "html" in x.get("summary", "").lower()), "https://www.oracle.com/security-alerts/")
            oracle_doc = {"vendor": "Oracle", "vendor_id": "oracle", "title": title, "source_url": url,
                          "release_date": raw.get("document", {}).get("tracking", {}).get("initial_release_date", ""),
                          "vulnerabilities": csaf_records(raw, "Oracle")}
            enrich_kev(oracle_doc, kev)
            documents.append(oracle_doc)
        except Exception:
            continue
    for doc in documents:
        for item in doc.get("vulnerabilities", []):
            if item.get("exploitation") != "active":
                continue
            cve = item["cve"]
            if cve not in merged:
                merged[cve] = dict(item)
                merged[cve]["vendors"] = []
                merged[cve]["sources"] = []
            current = merged[cve]
            if not current.get("vector") and item.get("vector"):
                for field in ("vector", "cvss", "severity", "description", "product", "component"):
                    current[field] = item.get(field, current.get(field, ""))
            if doc.get("vendor") not in current["vendors"]:
                current["vendors"].append(doc.get("vendor"))
            source = {"vendor": doc.get("vendor"), "title": doc.get("title"), "url": doc.get("source_url")}
            if source not in current["sources"]:
                current["sources"].append(source)
    output = {"vendor": "Exploited", "vendor_id": "exploited", "title": "CISA Known Exploited Vulnerabilities found in vendor advisories",
              "source_url": "https://www.cisa.gov/known-exploited-vulnerabilities-catalog", "release_date": "",
              "vulnerabilities": sorted(merged.values(), key=lambda x: x.get("kev", {}).get("dateAdded", ""), reverse=True)}
    (OUT / "exploited.json").write_text(json.dumps(output, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")


def main() -> None:
    OUT.mkdir(parents=True, exist_ok=True)
    warnings: list[str] = []
    kev = load_kev()
    summary = {}
    for vendor in VENDORS:
        try:
            summary[vendor] = len(write_vendor(vendor, kev, warnings))
        except Exception as exc:
            warnings.append(f"{VENDORS[vendor][0]} discovery: {exc}")
            summary[vendor] = 0
    build_exploited(kev)
    (OUT / "status.json").write_text(json.dumps({"generated_at": datetime.now(timezone.utc).isoformat(),
        "vendors": summary, "warnings": warnings}, indent=2) + "\n", encoding="utf-8")
    print("Updated vendor data: " + ", ".join(f"{name}={count}" for name, count in summary.items()))
    if warnings:
        print(f"Completed with {len(warnings)} warnings")


if __name__ == "__main__":
    main()
