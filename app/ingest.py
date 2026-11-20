"""Ingest free, public threat-intelligence sources into SQLite.

Design notes
------------
* Everything streams to disk / row-by-row: peak RSS stays flat even for
  the multi-megabyte KEV and EPSS payloads.
* Every source is independent and failure-tolerant: one dead feed never
  blocks the rest, and the outcome is recorded in ``ingest_log``.
* No scraping of paywalled or auth-gated content.
"""
from __future__ import annotations

import csv
import gzip
import io
import ipaddress
import json
import os
import re
import sys
import xml.etree.ElementTree as ET
import zipfile
from datetime import datetime, timezone
from email.utils import parsedate_to_datetime
from pathlib import Path
from urllib.parse import urlsplit

import httpx

from . import db

UA = "VulnDeck/1.0 (+https://vulndeck-uat.azmirilias.com; security research aggregator)"
TIMEOUT = httpx.Timeout(60.0, connect=15.0)

KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
EPSS_URL = "https://epss.empiricalsecurity.com/epss_scores-current.csv.gz"

FEEDS = [
    ("CISA Advisories", "https://www.cisa.gov/cybersecurity-advisories/all.xml", "Government"),
    ("CISA KEV Catalog", "https://www.cisa.gov/news.xml", "Government"),
    ("Unit 42", "https://unit42.paloaltonetworks.com/feed/", "Vendor research"),
    ("Cisco Talos", "https://blog.talosintelligence.com/rss/", "Vendor research"),
    ("Securelist", "https://securelist.com/feed/", "Vendor research"),
    ("WeLiveSecurity", "https://www.welivesecurity.com/en/rss/feed/", "Vendor research"),
    ("The DFIR Report", "https://thedfirreport.com/feed/", "DFIR"),
    ("SANS ISC", "https://isc.sans.edu/rssfeed.xml", "Blue team"),
    ("Krebs on Security", "https://krebsonsecurity.com/feed/", "Investigations"),
    ("Recorded Future", "https://www.recordedfuture.com/feed", "Threat intel"),
    ("DailyDarkWeb", "https://dailydarkweb.net/feed/", "Reported breach claims · headlines and links only"),
    ("CERT-FR", "https://www.cert.ssi.gouv.fr/feed/", "Government"),
    ("NCSC UK", "https://www.ncsc.gov.uk/api/1/services/v1/report-rss-feed.xml", "Government"),
    ("Full Disclosure", "https://seclists.org/rss/fulldisclosure.rss", "Disclosure"),
]

TMP = Path(
    os.environ.get("VULNDECK_TMPDIR")
    or os.environ.get("TMPDIR")
    or str(Path.home() / ".cache" / "vulndeck")
)
TMP.mkdir(parents=True, exist_ok=True)


def is_safe_http_url(value: str) -> bool:
    try:
        parsed = urlsplit((value or "").strip())
        return parsed.scheme.lower() in {"http", "https"} and bool(parsed.hostname) and not parsed.username and not parsed.password
    except (TypeError, ValueError):
        return False


def _json_refs(values) -> str:
    refs = values if isinstance(values, (list, tuple)) else [values]
    return json.dumps([ref for ref in refs if isinstance(ref, str) and is_safe_http_url(ref)][:50])


def _now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def _upsert(conn, table: str, cols: list[str], rows: list[tuple], key: str = "cve_id") -> int:
    if not rows:
        return 0
    placeholders = ",".join("?" * len(cols))
    updates = ",".join(f"{c}=excluded.{c}" for c in cols if c != key)
    sql = (
        f"INSERT INTO {table}({','.join(cols)}) VALUES({placeholders}) "
        f"ON CONFLICT({key}) DO UPDATE SET {updates}"
    )
    conn.executemany(sql, rows)
    return len(rows)


# --------------------------------------------------------------------------- KEV
def ingest_kev(client: httpx.Client) -> int:
    r = client.get(KEV_URL)
    r.raise_for_status()
    payload = r.json()
    rows = []
    for v in payload.get("vulnerabilities", []):
        rows.append(
            (
                v.get("cveID", "").strip(),
                v.get("vendorProject", "Unknown"),
                v.get("product", "Unknown"),
                v.get("vulnerabilityName", ""),
                v.get("dateAdded", ""),
                v.get("shortDescription", ""),
                v.get("requiredAction", ""),
                v.get("dueDate", ""),
                v.get("knownRansomwareCampaignUse", "Unknown"),
                v.get("notes", ""),
            )
        )
    with db.WRITE_LOCK, db.connect(write=True) as conn:
        n = _upsert(
            conn,
            "kev",
            ["cve_id", "vendor", "product", "name", "date_added", "short_desc",
             "required_action", "due_date", "ransomware_use", "notes"],
            rows,
        )
        conn.execute(
            "INSERT INTO meta(key,value) VALUES('kev_catalog_version',?) "
            "ON CONFLICT(key) DO UPDATE SET value=excluded.value",
            (str(payload.get("catalogVersion", "")),),
        )
    return n


# -------------------------------------------------------------------------- EPSS
def ingest_epss(client: httpx.Client) -> int:
    raw = TMP / "epss.csv.gz"
    with client.stream("GET", EPSS_URL) as r:
        r.raise_for_status()
        with open(raw, "wb") as fh:
            for chunk in r.iter_bytes(1 << 16):
                fh.write(chunk)

    rows = []
    with gzip.open(raw, "rt", encoding="utf-8", errors="replace") as fh:
        for line in fh:
            if line.startswith("#") or line.startswith("cve,"):
                continue
            parts = line.rstrip("\n").split(",")
            if len(parts) < 3:
                continue
            try:
                rows.append((parts[0], float(parts[1]), float(parts[2]), _now()[:10]))
            except ValueError:
                continue
    raw.unlink(missing_ok=True)

    with db.WRITE_LOCK, db.connect(write=True) as conn:
        conn.executemany(
            "INSERT INTO epss(cve_id,score,percentile,updated) VALUES(?,?,?,?) "
            "ON CONFLICT(cve_id) DO UPDATE SET score=excluded.score,"
            "percentile=excluded.percentile,updated=excluded.updated",
            rows,
        )
    return len(rows)


# --------------------------------------------------------------- advisories (OSV)
# GitHub's /advisories REST endpoint paginates unreliably for anonymous callers and
# is capped at 60 req/h, so advisories come from the authoritative OSV bulk exports
# instead: no key, no rate limit, one zip per ecosystem.
OSV_ZIP = "https://osv-vulnerabilities.storage.googleapis.com/{eco}/all.zip"
OSV_DEFAULT_ECOSYSTEMS = ["PyPI", "Go", "Maven", "crates.io", "NuGet", "RubyGems", "Packagist"]
# npm's export is ~210 MB; enable with VULNDECK_OSV_NPM=1 on a weekly timer.
if os.environ.get("VULNDECK_OSV_NPM") == "1":
    OSV_DEFAULT_ECOSYSTEMS.append("npm")

SEV_RANK = {"CRITICAL": "critical", "HIGH": "high", "MODERATE": "moderate", "MEDIUM": "medium", "LOW": "low"}

_CVSS3 = {
    "AV": {"N": 0.85, "A": 0.62, "L": 0.55, "P": 0.2},
    "AC": {"L": 0.77, "H": 0.44},
    "UI": {"N": 0.85, "R": 0.62},
    "C": {"H": 0.56, "L": 0.22, "N": 0.0},
    "I": {"H": 0.56, "L": 0.22, "N": 0.0},
    "A": {"H": 0.56, "L": 0.22, "N": 0.0},
    "PR": {"U": {"N": 0.85, "L": 0.62, "H": 0.27}, "C": {"N": 0.85, "L": 0.68, "H": 0.5}},
}


def _roundup(value: float) -> float:
    import math

    int_input = round(value * 100000)
    if int_input % 10000 == 0:
        return int_input / 100000.0
    return (math.floor(int_input / 10000) + 1) / 10.0


def cvss3_base(vector: str) -> float | None:
    """Base score from a CVSS v3.x vector — OSV often ships vectors without scores."""
    if "CVSS:3" not in vector:
        return None
    m = dict(p.split(":", 1) for p in vector.split("/")[1:] if ":" in p)
    try:
        scope = m["S"]
        iss = 1 - (
            (1 - _CVSS3["C"][m["C"]]) * (1 - _CVSS3["I"][m["I"]]) * (1 - _CVSS3["A"][m["A"]])
        )
        if scope == "C":
            impact = 7.52 * (iss - 0.029) - 3.25 * (iss - 0.02) ** 15
        else:
            impact = 6.42 * iss
        exploitability = (
            8.22
            * _CVSS3["AV"][m["AV"]]
            * _CVSS3["AC"][m["AC"]]
            * _CVSS3["PR"][scope][m["PR"]]
            * _CVSS3["UI"][m["UI"]]
        )
        if impact <= 0:
            return 0.0
        raw = min((impact + exploitability) * (1.08 if scope == "C" else 1.0), 10)
        return _roundup(raw)
    except KeyError:
        return None



def _osv_row(v: dict, eco: str) -> tuple | None:
    vid = v.get("id")
    if not vid:
        return None
    cve = next((a for a in v.get("aliases", []) if a.startswith("CVE-")), "")
    spec = v.get("database_specific") or {}
    sev = SEV_RANK.get(str(spec.get("severity", "")).upper(), "")
    cvss = None
    for s in v.get("severity") or []:
        score = str(s.get("score", ""))
        if score.startswith("CVSS:"):
            cvss = cvss or cvss3_base(score)
            continue
        try:
            cvss = float(score)
        except ValueError:
            continue
    if cvss is not None and not sev:
        sev = "critical" if cvss >= 9 else "high" if cvss >= 7 else "moderate" if cvss >= 4 else "low"
    affected = v.get("affected") or [{}]
    eco_name = (affected[0].get("package") or {}).get("ecosystem") or eco
    return (
        vid,
        cve,
        (v.get("summary") or v.get("details", "")[:200] or vid)[:400],
        sev,
        cvss,
        (v.get("published") or "")[:19],
        (v.get("modified") or "")[:19],
        eco_name,
        "osv",
        f"https://osv.dev/vulnerability/{vid}",
    )


def ingest_osv(client: httpx.Client, ecosystems: list[str] | None = None) -> int:
    total = 0
    for eco in ecosystems or OSV_DEFAULT_ECOSYSTEMS:
        path = TMP / f"osv-{eco.replace('.', '_')}.zip"
        try:
            with client.stream("GET", OSV_ZIP.format(eco=eco)) as r:
                r.raise_for_status()
                with open(path, "wb") as fh:
                    for chunk in r.iter_bytes(1 << 16):
                        fh.write(chunk)
            batch: list[tuple] = []
            with zipfile.ZipFile(path) as zf:
                for name in zf.namelist():
                    if not name.endswith(".json"):
                        continue
                    try:
                        row = _osv_row(json.loads(zf.read(name)), eco)
                    except (json.JSONDecodeError, KeyError):
                        continue
                    if row:
                        batch.append(row)
                    if len(batch) >= 2000:
                        total += _flush_advisories(batch)
                        batch = []
            total += _flush_advisories(batch)
            db.log_ingest(f"osv:{eco}", total, "ok", f"{path.stat().st_size // 1024} KB")
        except Exception as exc:  # noqa: BLE001
            db.log_ingest(f"osv:{eco}", 0, "error", f"{type(exc).__name__}: {exc}"[:200])
            print(f"   osv:{eco} failed: {exc}", flush=True)
        finally:
            path.unlink(missing_ok=True)
    return total


def _flush_advisories(batch: list[tuple]) -> int:
    if not batch:
        return 0
    with db.WRITE_LOCK, db.connect(write=True) as conn:
        return _upsert(
            conn,
            "advisory",
            ["id", "cve_id", "summary", "severity", "cvss", "published", "updated",
             "ecosystem", "source", "url"],
            batch,
            key="id",
        )


# ---------------------------------------------------------------------- RSS/Atom
def _text(node, tag: str) -> str:
    el = node.find(tag)
    return (el.text or "").strip() if el is not None and el.text else ""


def ingest_feeds(client: httpx.Client) -> int:
    rows = []
    for name, url, category in FEEDS:
        try:
            r = client.get(url, headers={"Accept": "application/rss+xml, application/xml;q=0.9, */*;q=0.5"})
            if r.status_code != 200 or not r.content:
                db.log_ingest(name, 0, "skip", f"HTTP {r.status_code}")
                continue
            root = ET.fromstring(r.content)
        except Exception as exc:  # noqa: BLE001 - feed quality varies wildly
            db.log_ingest(name, 0, "error", f"{type(exc).__name__}: {exc}"[:200])
            continue

        items = root.findall(".//item") or root.findall(
            ".//{http://www.w3.org/2005/Atom}entry"
        )
        for it in items[:25]:
            link = _text(it, "link") or _text(it, "{http://www.w3.org/2005/Atom}link")
            if not link:
                lk = it.find("{http://www.w3.org/2005/Atom}link")
                link = lk.get("href", "") if lk is not None else ""
            title = _text(it, "title") or _text(it, "{http://www.w3.org/2005/Atom}title")
            pub = (
                _text(it, "pubDate")
                or _text(it, "{http://www.w3.org/2005/Atom}updated")
                or _text(it, "{http://purl.org/dc/elements/1.1/}date")
            )
            desc = _text(it, "description") or _text(it, "{http://www.w3.org/2005/Atom}summary")
            if not (link and title and is_safe_http_url(link)):
                continue
            rows.append((link[:500], name, title[:300], _parse_date(pub), _strip_html(desc)[:600], category))
        db.log_ingest(name, len(items[:25]), "ok", url)

    with db.WRITE_LOCK, db.connect(write=True) as conn:
        conn.executemany(
            "INSERT INTO article(link,source,title,published,summary,category) "
            "VALUES(?,?,?,?,?,?) ON CONFLICT(link) DO UPDATE SET "
            "title=excluded.title, summary=excluded.summary, published=excluded.published, "
            "ai_summary=CASE WHEN article.title IS NOT excluded.title "
            "OR article.summary IS NOT excluded.summary THEN NULL ELSE article.ai_summary END",
            rows,
        )
    return len(rows)


def _strip_html(s: str) -> str:
    out, depth = [], 0
    for ch in s:
        if ch == "<":
            depth += 1
        elif ch == ">":
            depth = max(0, depth - 1)
        elif depth == 0:
            out.append(ch)
    return " ".join("".join(out).split())


# ----------------------------------------------------------------- ransomware (RSS)
def ingest_ransomware(client: httpx.Client) -> int:
    r = client.get("https://www.ransomware.live/rss.xml")
    r.raise_for_status()
    root = ET.fromstring(r.content)
    rows = []
    for it in root.findall(".//item"):
        title = _text(it, "title")
        link = _text(it, "link")
        pub = _text(it, "pubDate")
        desc = _text(it, "description")
        group, victim = "", title
        if " has just published a new victim : " in title:
            left, right = title.split(" has just published a new victim : ", 1)
            group = left.replace("🏴‍☠️", "").strip()
            victim = right.strip()
        sector = None
        if desc.startswith("["):
            sector = desc.split("]", 1)[0].strip("[]").strip() or None
        if not is_safe_http_url(link):
            link = ""
        key = link or (group + "|" + victim)
        rows.append((key[:500], group[:120], victim[:300], _parse_date(pub), sector, None, link[:500], "ransomware.live"))
    with db.WRITE_LOCK, db.connect(write=True) as conn:
        n = _upsert(conn, "ransomware",
                    ["id", "group_name", "victim", "discovered", "sector", "country", "url", "source"],
                    rows, key="id")
    return n


def _parse_date(value: str) -> str:
    value = (value or "").strip()
    if not value:
        return ""
    parsed = None
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        try:
            parsed = parsedate_to_datetime(value)
        except (TypeError, ValueError, OverflowError):
            for fmt in ("%a, %d %b %Y", "%Y-%m-%d"):
                try:
                    parsed = datetime.strptime(value, fmt)
                    break
                except ValueError:
                    continue
    if parsed is None:
        return value[:10]
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return parsed.astimezone(timezone.utc).date().isoformat()


# -------------------------------------------------------------------- breaches (HIBP)
def ingest_breaches(client: httpx.Client) -> int:
    r = client.get("https://haveibeenpwned.com/api/v3/breaches")
    r.raise_for_status()
    data = r.json()
    rows = []
    for b in data:
        rows.append((
            b.get("Name", ""),
            b.get("Title", ""),
            b.get("Domain", ""),
            b.get("BreachDate", ""),
            (b.get("AddedDate") or "")[:19],
            b.get("PwnCount"),
            _strip_html(b.get("Description", ""))[:500],
            ", ".join(b.get("DataClasses") or []),
            b.get("LogoPath", ""),
        ))
    with db.WRITE_LOCK, db.connect(write=True) as conn:
        conn.executemany(
            "INSERT INTO breach(name,title,domain,breach_date,added_date,pwn_count,description,data_classes,logo_url) "
            "VALUES(?,?,?,?,?,?,?,?,?) ON CONFLICT(name) DO UPDATE SET "
            "title=excluded.title, domain=excluded.domain, breach_date=excluded.breach_date, "
            "added_date=excluded.added_date, pwn_count=excluded.pwn_count, "
            "description=excluded.description, data_classes=excluded.data_classes, logo_url=excluded.logo_url",
            rows,
        )
    return len(rows)


# -------------------------------------------------------- MISP galaxy actors/tools
def _slugify(text: str) -> str:
    return re.sub(r"[^a-z0-9]+", "-", (text or "").lower()).strip("-") or "unknown"


def _str(value) -> str | None:
    if value is None:
        return None
    if isinstance(value, (list, tuple)):
        return ", ".join(str(x) for x in value)
    return str(value)


MALWARE_GALAXIES = (
    "malpedia",
    "mitre-enterprise-attack-malware",
    "mitre-mobile-attack-malware",
    "mitre-malware",
    "ransomware",
)


def galaxy_malware_rows(payload: dict, cluster: str) -> list[tuple]:
    rows = []
    for item in payload.get("values", []):
        name = (item.get("value") or "").strip()
        if not name:
            continue
        meta = item.get("meta") or {}
        rows.append((
            _slugify(name),
            name[:240],
            (item.get("description") or "")[:1000],
            _str(meta.get("type") or meta.get("category") or cluster),
            _json_refs(meta.get("refs")),
            f"misp-galaxy/{cluster}",
        ))
    return rows


def ingest_galaxy(client: httpx.Client) -> int:
    total = 0
    # Threat actors
    r = client.get("https://raw.githubusercontent.com/MISP/misp-galaxy/main/clusters/threat-actor.json")
    r.raise_for_status()
    data = r.json()
    actor_rows = []
    for v in data.get("values", []):
        name = (v.get("value") or "").strip()
        if not name:
            continue
        meta = v.get("meta") or {}
        actor_rows.append((
            _slugify(name),
            name[:240],
            ", ".join(meta.get("synonyms") or []),
            (v.get("description") or "")[:1000],
            _str(meta.get("country")),
            _str(meta.get("cfr-type-of-incident") or meta.get("motivation")),
            _json_refs(meta.get("refs")),
        ))
    with db.WRITE_LOCK, db.connect(write=True) as conn:
        conn.executemany(
            "INSERT INTO actor(slug,name,aliases,description,country,motivation,refs) VALUES(?,?,?,?,?,?,?) "
            "ON CONFLICT(slug) DO UPDATE SET name=excluded.name, aliases=excluded.aliases, "
            "description=excluded.description, country=excluded.country, motivation=excluded.motivation, refs=excluded.refs",
            actor_rows,
        )
    total += len(actor_rows)

    # MISP Galaxy has several malware clusters; combine them into a searchable index.
    for cluster in MALWARE_GALAXIES:
        url = f"https://raw.githubusercontent.com/MISP/misp-galaxy/main/clusters/{cluster}.json"
        try:
            response = client.get(url)
            response.raise_for_status()
            malware_rows = galaxy_malware_rows(response.json(), cluster)
            with db.WRITE_LOCK, db.connect(write=True) as conn:
                conn.executemany(
                    "INSERT INTO malware(slug,name,description,malware_type,refs,source) VALUES(?,?,?,?,?,?) "
                    "ON CONFLICT(slug) DO UPDATE SET name=excluded.name, description=excluded.description, "
                    "malware_type=excluded.malware_type, refs=excluded.refs, source=excluded.source",
                    malware_rows,
                )
            total += len(malware_rows)
            db.log_ingest(f"misp:{cluster}", len(malware_rows), "ok", url)
        except Exception as exc:  # noqa: BLE001 - each public cluster is independent
            db.log_ingest(f"misp:{cluster}", 0, "error", f"{type(exc).__name__}: {exc}"[:200])
    return total


# ------------------------------------------------------------- PoC trending (GitHub)
def ingest_poc(client: httpx.Client) -> int:
    token = os.environ.get("GITHUB_TOKEN") or os.environ.get("VULNDECK_GITHUB_TOKEN")
    headers = {"Accept": "application/vnd.github+json"}
    if token:
        headers["Authorization"] = f"Bearer {token}"
    try:
        r = client.get(
            "https://api.github.com/search/repositories",
            params={"q": "CVE exploit poc", "sort": "updated", "order": "desc", "per_page": 50},
            headers=headers,
        )
        r.raise_for_status()
    except Exception:
        return 0
    data = r.json()
    rows = []
    for repo in data.get("items", []) or []:
        text = f"{repo.get('name','')} {repo.get('description') or ''}"
        for cve in set(re.findall(r"CVE-\d{4}-\d{4,7}", text, re.I)):
            repo_url = repo.get("html_url", "")
            if not is_safe_http_url(repo_url) or urlsplit(repo_url).hostname not in {"github.com", "www.github.com"}:
                continue
            rows.append((
                cve.upper(),
                repo.get("full_name", ""),
                repo_url,
                int(repo.get("stargazers_count") or 0),
                (repo.get("description") or "")[:300],
                (repo.get("updated_at") or "")[:10],
            ))
    with db.WRITE_LOCK, db.connect(write=True) as conn:
        conn.executemany(
            "INSERT INTO poc(cve_id,repo,url,stars,description,published) VALUES(?,?,?,?,?,?) "
            "ON CONFLICT(cve_id,repo) DO UPDATE SET stars=excluded.stars, description=excluded.description, "
            "published=excluded.published, url=excluded.url",
            rows,
        )
    return len(rows)


# -------------------------------------------------------------- IOC extraction
IOC_CVE_RE = re.compile(r"CVE-\d{4}-\d{4,7}", re.I)
IOC_IP_RE = re.compile(r"(?<![\w.])(?:\d{1,3}\.){3}\d{1,3}(?![\w.])")
IOC_DOMAIN_RE = re.compile(
    r"(?<![a-z0-9_-])(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}(?![a-z0-9-])",
    re.I,
)
DOC_DOMAINS = {"example.com", "example.net", "example.org", "example.edu"}
NON_IOC_TLDS = {"arpa", "invalid", "local", "localhost", "test"}


def extract_iocs(text: str) -> list[tuple[str, str]]:
    """Extract public IPs and domain/CVE mentions; these are leads, not verdicts."""
    found: list[tuple[str, str]] = []
    seen: set[tuple[str, str]] = set()

    def add(kind: str, value: str) -> None:
        item = (kind, value)
        if item not in seen:
            seen.add(item)
            found.append(item)

    for cve in IOC_CVE_RE.findall(text or ""):
        add("cve", cve.upper())

    for candidate in IOC_IP_RE.findall(text or ""):
        try:
            address = ipaddress.ip_address(candidate)
        except ValueError:
            continue
        if address.is_global:
            add("ip", address.compressed)

    for candidate in IOC_DOMAIN_RE.findall(text or ""):
        domain = candidate.rstrip(".").lower()
        tld = domain.rsplit(".", 1)[-1]
        if domain not in DOC_DOMAINS and tld not in NON_IOC_TLDS:
            add("domain", domain)
    return found


def ingest_iocs(client: httpx.Client) -> int:
    with db.cursor() as conn:
        articles = conn.execute("SELECT link, title, summary FROM article").fetchall()
    rows = []
    for a in articles:
        text = f"{a['title'] or ''} {a['summary'] or ''}"
        rows.extend((a["link"], kind, value) for kind, value in extract_iocs(text))
    with db.WRITE_LOCK, db.connect(write=True) as conn:
        conn.execute("DELETE FROM article_ioc")
        conn.executemany(
            "INSERT INTO article_ioc(article_link, ioc_type, ioc_value) VALUES(?,?,?)",
            rows,
        )
    return len(rows)


# ------------------------------------------------------------------------- driver
JOBS = [
    ("cisa-kev", ingest_kev),
    ("epss", ingest_epss),
    ("advisories-osv", lambda c: ingest_osv(c)),
    ("rss-feeds", ingest_feeds),
    ("ransomware", ingest_ransomware),
    ("breaches", ingest_breaches),
    ("misp-galaxy", ingest_galaxy),
    ("poc-trending", ingest_poc),
    ("article-iocs", ingest_iocs),
]


def run(only: str | None = None) -> int:
    db.init_db()
    failures = 0
    with httpx.Client(timeout=TIMEOUT, headers={"User-Agent": UA}, follow_redirects=True) as client:
        for name, fn in JOBS:
            if only and only != name:
                continue
            started = datetime.now(timezone.utc)
            try:
                rows = fn(client)
                secs = (datetime.now(timezone.utc) - started).total_seconds()
                db.log_ingest(name, rows, "ok", f"{secs:.1f}s")
                print(f"[ok]   {name:20s} rows={rows:<7d} {secs:.1f}s", flush=True)
            except Exception as exc:  # noqa: BLE001
                failures += 1
                db.log_ingest(name, 0, "error", f"{type(exc).__name__}: {exc}")
                print(f"[fail] {name:20s} {type(exc).__name__}: {exc}", flush=True)
    db.set_meta("last_ingest", _now())
    return failures


if __name__ == "__main__":
    sys.exit(1 if run(sys.argv[1] if len(sys.argv) > 1 else None) else 0)
