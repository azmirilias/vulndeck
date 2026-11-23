"""Threat-hunting data ingest: Sigma rules, MITRE ATT&CK, Atomic Red Team.

All sources are free and keyless. Follows the same failure-tolerant,
low-memory contract as app.ingest: stream to disk, parse row-by-row,
record outcome in ingest_log.
"""
from __future__ import annotations

import hashlib
import json
import os
import re
import shutil
import subprocess
from datetime import datetime, timezone
from pathlib import Path

import httpx

from . import db

# ---------- helpers

SIGMA_REPO = "https://github.com/SigmaHQ/sigma.git"
ATOMIC_REPO = "https://github.com/redcanaryco/atomic-red-team.git"
ATTACK_URL = "https://raw.githubusercontent.com/mitre/cti/master/enterprise-attack/enterprise-attack.json"

TECH_RE = re.compile(r"^attack\.t(\d{4}(?:\.\d{3})?)$", re.I)
MAX_YAML = 200_000


def _now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def _sh(*args: str) -> None:
    subprocess.run(args, check=True, capture_output=True, timeout=600)


def _clone_or_pull(url: str, dest: Path) -> None:
    if (dest / ".git").exists():
        subprocess.run(["git", "-C", str(dest), "pull", "--ff-only", "--depth", "1", "--quiet"],
                       check=False, capture_output=True, timeout=600)
    else:
        shutil.rmtree(dest, ignore_errors=True)
        subprocess.run(["git", "clone", "--depth", "1", "--quiet", url, str(dest)],
                       check=True, capture_output=True, timeout=600)


def _json_str(value) -> str | None:
    if value is None:
        return None
    try:
        return json.dumps(value, ensure_ascii=False)
    except (TypeError, ValueError):
        return None


def _join(value) -> str:
    if value is None:
        return ""
    if isinstance(value, (list, tuple)):
        return ", ".join(str(v) for v in value)
    return str(value)


# ---------- Sigma

def ingest_sigma(client: httpx.Client) -> int:
    tmp = Path(os.environ.get("VULNDECK_TMPDIR", "/tmp"))
    repo = tmp / "sigma"
    _clone_or_pull(SIGMA_REPO, repo)
    import yaml  # local import; only needed for this source

    rows: list[tuple] = []
    for path in repo.rglob("*.yml"):
        rel = str(path.relative_to(repo))
        if not rel.startswith("rules/"):
            continue
        try:
            doc = yaml.safe_load(path.read_text(encoding="utf-8", errors="replace"))
        except Exception:
            continue
        if not isinstance(doc, dict):
            continue
        title = str(doc.get("title") or "").strip()
        if not title:
            continue
        tags = doc.get("tags") or []
        techniques = []
        for t in tags if isinstance(tags, list) else []:
            m = TECH_RE.match(str(t))
            if m:
                techniques.append("T" + m.group(1).upper())
        rid = hashlib.sha1(rel.encode()).hexdigest()
        rows.append((
            rid,
            title[:300],
            str(doc.get("description") or "")[:2000],
            str(doc.get("status") or ""),
            str(doc.get("level") or ""),
            _json_str(doc.get("logsource")),
            _json_str(doc.get("detection")),
            _join(tags)[:2000],
            _join(doc.get("author"))[:500],
            str(doc.get("date") or "")[:10],
            _join(doc.get("references"))[:2000],
            ",".join(sorted(set(techniques))),
            rel,
        ))
    with db.WRITE_LOCK, db.connect(write=True) as conn:
        conn.executemany(
            "INSERT INTO hunt_rule(id,title,description,status,level,logsource,detection,tags,author,date,refs,techniques,path) "
            "VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?) "
            "ON CONFLICT(id) DO UPDATE SET title=excluded.title, description=excluded.description, "
            "status=excluded.status, level=excluded.level, logsource=excluded.logsource, "
            "detection=excluded.detection, tags=excluded.tags, author=excluded.author, "
            "date=excluded.date, refs=excluded.refs, techniques=excluded.techniques, path=excluded.path",
            rows,
        )
    return len(rows)


# ---------- MITRE ATT&CK

def ingest_attack(client: httpx.Client) -> int:
    tmp = Path(os.environ.get("VULNDECK_TMPDIR", "/tmp"))
    raw = tmp / "enterprise-attack.json"
    with client.stream("GET", ATTACK_URL) as r:
        r.raise_for_status()
        with open(raw, "wb") as fh:
            for chunk in r.iter_bytes(1 << 16):
                fh.write(chunk)

    import ijson  # streaming parse, keeps RSS flat on the 49 MB bundle

    rows: list[tuple] = []
    with open(raw, "rb") as fh:
        for obj in ijson.items(fh, "objects.item"):
            if obj.get("type") != "attack-pattern":
                continue
            ext = obj.get("external_references") or []
            ext_id = ""
            url = ""
            for e in ext:
                if e.get("source_name") == "mitre-attack" and e.get("external_id", "").startswith("T"):
                    ext_id = e["external_id"]
                    url = e.get("url") or ""
                    break
            if not ext_id:
                continue
            tactics = ",".join(k.get("phase_name", "") for k in (obj.get("kill_chain_phases") or []))
            rows.append((
                ext_id,
                str(obj.get("name") or "")[:300],
                str(obj.get("description") or "")[:3000],
                tactics,
                _join(obj.get("x_mitre_platforms")),
                url,
                1 if obj.get("x_mitre_deprecated") else 0,
                1 if obj.get("x_mitre_is_subtechnique") else 0,
            ))
    raw.unlink(missing_ok=True)
    with db.WRITE_LOCK, db.connect(write=True) as conn:
        conn.executemany(
            "INSERT INTO hunt_technique(id,name,description,tactics,platforms,url,deprecated,is_sub) "
            "VALUES(?,?,?,?,?,?,?,?) "
            "ON CONFLICT(id) DO UPDATE SET name=excluded.name, description=excluded.description, "
            "tactics=excluded.tactics, platforms=excluded.platforms, url=excluded.url, "
            "deprecated=excluded.deprecated, is_sub=excluded.is_sub",
            rows,
        )
    return len(rows)


# ---------- Atomic Red Team

def ingest_atomics(client: httpx.Client) -> int:
    tmp = Path(os.environ.get("VULNDECK_TMPDIR", "/tmp"))
    repo = tmp / "atomic-red-team"
    _clone_or_pull(ATOMIC_REPO, repo)
    import yaml

    rows: list[tuple] = []
    for path in repo.glob("atomics/*/*.yaml"):
        rel = str(path.relative_to(repo))
        if rel.endswith("index.yaml"):
            continue
        try:
            raw_text = path.read_text(encoding="utf-8", errors="replace")[:MAX_YAML]
            doc = yaml.safe_load(raw_text)
        except Exception:
            continue
        if not isinstance(doc, dict):
            continue
        tid = str(doc.get("attack_technique") or "").strip().upper()
        if not tid:
            continue
        tests = doc.get("atomic_tests") or []
        rows.append((
            tid,
            str(doc.get("display_name") or "")[:300],
            rel,
            raw_text,
            len(tests) if isinstance(tests, list) else 0,
        ))
    with db.WRITE_LOCK, db.connect(write=True) as conn:
        conn.executemany(
            "INSERT INTO hunt_atomic(technique_id,name,path,yaml,test_count) VALUES(?,?,?,?,?) "
            "ON CONFLICT(technique_id) DO UPDATE SET name=excluded.name, path=excluded.path, "
            "yaml=excluded.yaml, test_count=excluded.test_count",
            rows,
        )
    return len(rows)


# ---------- IOC enrichment (on-demand, cached by caller)

def ioc_lookup(ioc: str, ioc_type: str) -> dict:
    """Enrich one indicator across configured providers. Returns per-source results."""
    key = os.environ.get("VT_KEY", "")
    abkey = os.environ.get("ABUSE_CH_KEY", "")
    otx = os.environ.get("OTX_KEY", "")
    out: dict = {}
    with httpx.Client(timeout=15.0, follow_redirects=True) as c:
        if key and ioc_type == "ip":
            out["virustotal"] = _vt_ip(c, ioc, key)
        if key and ioc_type == "domain":
            out["virustotal"] = _vt_domain(c, ioc, key)
        if abkey:
            out["threatfox"] = _threatfox(c, ioc, ioc_type, abkey)
            if ioc_type in ("ip", "domain"):
                out["urlhaus"] = _urlhaus(c, ioc, abkey)
        if otx and ioc_type in ("ip", "domain", "url"):
            out["otx"] = _otx(c, ioc, ioc_type, otx)
    return out


def _vt_ip(c: httpx.Client, ip: str, key: str) -> dict:
    r = c.get(f"https://www.virustotal.com/api/v3/ip_addresses/{ip}", headers={"x-apikey": key})
    if r.status_code != 200:
        return {"error": r.status_code}
    a = r.json().get("data", {}).get("attributes", {})
    votes = a.get("total_votes", {}) or {}
    return {"votes": votes, "asn": (a.get("as_owner") or "")[:80], "country": a.get("country")}


def _vt_domain(c: httpx.Client, domain: str, key: str) -> dict:
    r = c.get(f"https://www.virustotal.com/api/v3/domains/{domain}", headers={"x-apikey": key})
    if r.status_code != 200:
        return {"error": r.status_code}
    a = r.json().get("data", {}).get("attributes", {})
    votes = a.get("total_votes", {}) or {}
    return {"votes": votes, "registrar": (a.get("registrar") or "")[:80], "last_dns": a.get("last_dns_records_date")}


def _threatfox(c: httpx.Client, ioc: str, ioc_type: str, key: str) -> dict:
    body = {"query": "search_ioc", "search_term": ioc}
    r = c.post("https://threatfox-api.abuse.ch/api/v1/", headers={"Auth-Key": key}, json=body)
    if r.status_code != 200:
        return {"error": r.status_code}
    d = r.json()
    return {"status": d.get("query_status"), "count": len(d.get("data") or []) if isinstance(d.get("data"), list) else 0}


def _urlhaus(c: httpx.Client, host: str, key: str) -> dict:
    r = c.post("https://urlhaus-api.abuse.ch/v1/host/", headers={"Auth-Key": key}, data={"host": host})
    if r.status_code != 200:
        return {"error": r.status_code}
    d = r.json()
    return {"status": d.get("query_status"), "url_count": d.get("url_count")}


def _otx(c: httpx.Client, ioc: str, ioc_type: str, key: str) -> dict:
    r = c.get(
        f"https://otx.alienvault.com/api/v1/indicators/{ioc_type}/{ioc}/general",
        headers={"X-OTX-API-Key": key},
    )
    if r.status_code != 200:
        return {"error": r.status_code}
    d = r.json()
    return {"pulse_count": d.get("pulse_info", {}).get("count", 0), "malware_count": len(d.get("malware", {}) or [])}
