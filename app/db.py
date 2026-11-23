"""SQLite access layer — stdlib only, single writer, read-heavy."""
from __future__ import annotations

import os
import sqlite3
import threading
from contextlib import contextmanager

from .config import DB_PATH

SCHEMA = """
CREATE TABLE IF NOT EXISTS kev (
    cve_id          TEXT PRIMARY KEY,
    vendor          TEXT NOT NULL,
    product         TEXT NOT NULL,
    name            TEXT NOT NULL,
    date_added      TEXT,
    short_desc      TEXT,
    required_action TEXT,
    due_date        TEXT,
    ransomware_use  TEXT,
    notes           TEXT
);
CREATE INDEX IF NOT EXISTS idx_kev_date   ON kev(date_added DESC);
CREATE INDEX IF NOT EXISTS idx_kev_vendor ON kev(vendor, product);
CREATE INDEX IF NOT EXISTS idx_kev_ransom ON kev(ransomware_use);

CREATE TABLE IF NOT EXISTS epss (
    cve_id     TEXT PRIMARY KEY,
    score      REAL NOT NULL,
    percentile REAL NOT NULL,
    updated    TEXT
);

CREATE TABLE IF NOT EXISTS advisory (
    id         TEXT PRIMARY KEY,
    cve_id     TEXT,
    summary    TEXT NOT NULL,
    severity   TEXT,
    cvss       REAL,
    published  TEXT,
    updated    TEXT,
    ecosystem  TEXT,
    source     TEXT DEFAULT 'github-advisory',
    url        TEXT
);
CREATE INDEX IF NOT EXISTS idx_adv_cve ON advisory(cve_id);
CREATE INDEX IF NOT EXISTS idx_adv_pub ON advisory(published DESC);

CREATE TABLE IF NOT EXISTS article (
    link        TEXT PRIMARY KEY,
    source      TEXT NOT NULL,
    title       TEXT NOT NULL,
    published   TEXT,
    summary     TEXT,
    category    TEXT,
    ai_summary  TEXT
);
CREATE INDEX IF NOT EXISTS idx_art_pub ON article(published DESC);

CREATE TABLE IF NOT EXISTS meta (
    key   TEXT PRIMARY KEY,
    value TEXT
);

CREATE TABLE IF NOT EXISTS ransomware (
    id          TEXT PRIMARY KEY,
    group_name  TEXT,
    victim      TEXT NOT NULL,
    discovered  TEXT,
    sector      TEXT,
    country     TEXT,
    url         TEXT,
    source      TEXT DEFAULT 'ransomware.live'
);
CREATE INDEX IF NOT EXISTS idx_rw_discovered ON ransomware(discovered DESC);
CREATE INDEX IF NOT EXISTS idx_rw_group ON ransomware(group_name);

CREATE TABLE IF NOT EXISTS breach (
    name        TEXT PRIMARY KEY,
    title       TEXT,
    domain      TEXT,
    breach_date TEXT,
    added_date  TEXT,
    pwn_count   INTEGER,
    description TEXT,
    data_classes TEXT,
    logo_url    TEXT
);
CREATE INDEX IF NOT EXISTS idx_breach_date ON breach(breach_date DESC);

CREATE TABLE IF NOT EXISTS actor (
    slug        TEXT PRIMARY KEY,
    name        TEXT NOT NULL,
    aliases     TEXT,
    description TEXT,
    country     TEXT,
    motivation  TEXT,
    refs        TEXT,
    source      TEXT DEFAULT 'misp-galaxy'
);
CREATE INDEX IF NOT EXISTS idx_actor_name ON actor(name);

CREATE TABLE IF NOT EXISTS tool (
    slug        TEXT PRIMARY KEY,
    name        TEXT NOT NULL,
    description TEXT,
    tool_type   TEXT,
    refs        TEXT,
    source      TEXT DEFAULT 'misp-galaxy'
);
CREATE INDEX IF NOT EXISTS idx_tool_name ON tool(name);

CREATE TABLE IF NOT EXISTS malware (
    slug        TEXT PRIMARY KEY,
    name        TEXT NOT NULL,
    description TEXT,
    malware_type TEXT,
    refs        TEXT,
    source      TEXT NOT NULL DEFAULT 'misp-galaxy'
);
CREATE INDEX IF NOT EXISTS idx_malware_name ON malware(name);

CREATE TABLE IF NOT EXISTS poc (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    cve_id      TEXT NOT NULL,
    repo        TEXT NOT NULL,
    url         TEXT NOT NULL,
    stars       INTEGER DEFAULT 0,
    description TEXT,
    published   TEXT,
    UNIQUE(cve_id, repo)
);
CREATE INDEX IF NOT EXISTS idx_poc_cve ON poc(cve_id);

CREATE TABLE IF NOT EXISTS article_ioc (
    article_link TEXT NOT NULL,
    ioc_type     TEXT NOT NULL,
    ioc_value    TEXT NOT NULL,
    PRIMARY KEY (article_link, ioc_type, ioc_value)
);
CREATE INDEX IF NOT EXISTS idx_aioc_value ON article_ioc(ioc_value);

CREATE TABLE IF NOT EXISTS hunt_rule (
    id          TEXT PRIMARY KEY,
    title       TEXT NOT NULL,
    description TEXT,
    status      TEXT,
    level       TEXT,
    logsource   TEXT,
    detection   TEXT,
    tags        TEXT,
    author      TEXT,
    date        TEXT,
    refs        TEXT,
    techniques  TEXT,
    path        TEXT
);
CREATE INDEX IF NOT EXISTS idx_hr_level ON hunt_rule(level);
CREATE INDEX IF NOT EXISTS idx_hr_title ON hunt_rule(title);

CREATE TABLE IF NOT EXISTS hunt_technique (
    id          TEXT PRIMARY KEY,
    name        TEXT NOT NULL,
    description TEXT,
    tactics     TEXT,
    platforms   TEXT,
    url         TEXT,
    deprecated  INTEGER DEFAULT 0,
    is_sub      INTEGER DEFAULT 0
);
CREATE INDEX IF NOT EXISTS idx_ht_name ON hunt_technique(name);

CREATE TABLE IF NOT EXISTS hunt_atomic (
    technique_id TEXT PRIMARY KEY,
    name         TEXT,
    path         TEXT,
    yaml         TEXT,
    test_count   INTEGER DEFAULT 0
);

CREATE TABLE IF NOT EXISTS hunt_ioc_cache (
    ioc       TEXT NOT NULL,
    ioc_type  TEXT NOT NULL,
    source    TEXT NOT NULL,
    result    TEXT,
    ts        TEXT,
    expiry    TEXT,
    PRIMARY KEY (ioc, ioc_type, source)
);

CREATE TABLE IF NOT EXISTS hunt_hypothesis (
    id           INTEGER PRIMARY KEY AUTOINCREMENT,
    title        TEXT NOT NULL,
    hypothesis   TEXT,
    technique_id TEXT,
    data_sources TEXT,
    status       TEXT DEFAULT 'open',
    created      TEXT,
    notes        TEXT
);

CREATE TABLE IF NOT EXISTS ingest_log (
    id        INTEGER PRIMARY KEY AUTOINCREMENT,
    ts        TEXT,
    source    TEXT,
    rows      INTEGER,
    status    TEXT,
    detail    TEXT
);
"""

WRITE_LOCK = threading.Lock()


class ClosingConnection(sqlite3.Connection):
    """Close as well as commit/rollback when used in a ``with`` block."""

    def __exit__(self, exc_type, exc_value, traceback):
        try:
            return super().__exit__(exc_type, exc_value, traceback)
        finally:
            self.close()


def connect(write: bool = False) -> sqlite3.Connection:
    path = DB_PATH
    os.makedirs(os.path.dirname(path), exist_ok=True)
    conn = sqlite3.connect(path, timeout=15, check_same_thread=False, factory=ClosingConnection)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA busy_timeout=8000")
    conn.execute("PRAGMA temp_store=FILE")
    conn.execute("PRAGMA cache_size=-8000")  # ~8 MB page cache, keeps RSS flat
    if write:
        conn.execute("PRAGMA journal_mode=WAL")
        conn.execute("PRAGMA synchronous=NORMAL")
    return conn


def init_db() -> None:
    with WRITE_LOCK, connect(write=True) as conn:
        conn.executescript(SCHEMA)
        try:
            conn.execute("ALTER TABLE article ADD COLUMN ai_summary TEXT")
        except sqlite3.OperationalError:
            pass


@contextmanager
def cursor():
    conn = connect()
    try:
        yield conn
    finally:
        conn.close()


def get_meta(key: str, default: str = "") -> str:
    with cursor() as conn:
        row = conn.execute("SELECT value FROM meta WHERE key=?", (key,)).fetchone()
    return row["value"] if row else default


def set_meta(key: str, value: str) -> None:
    with WRITE_LOCK, connect(write=True) as conn:
        conn.execute(
            "INSERT INTO meta(key, value) VALUES(?,?) "
            "ON CONFLICT(key) DO UPDATE SET value=excluded.value",
            (key, value),
        )


def log_ingest(source: str, rows: int, status: str, detail: str = "") -> None:
    from datetime import datetime, timezone

    with WRITE_LOCK, connect(write=True) as conn:
        conn.execute(
            "INSERT INTO ingest_log(ts, source, rows, status, detail) VALUES(?,?,?,?,?)",
            (datetime.now(timezone.utc).isoformat(timespec="seconds"), source, rows, status, detail[:500]),
        )


COUNTS_SQL = {
    "kev": "SELECT COUNT(*) c FROM kev",
    "kev_ransomware": "SELECT COUNT(*) c FROM kev WHERE ransomware_use LIKE 'Known%'",
    "advisories": "SELECT COUNT(*) c FROM advisory",
    "vendors": "SELECT COUNT(DISTINCT vendor) c FROM kev",
    "articles": "SELECT COUNT(*) c FROM article",
    "epss_high": "SELECT COUNT(*) c FROM epss WHERE score >= 0.1",
    "ransomware": "SELECT COUNT(*) c FROM ransomware",
    "breaches": "SELECT COUNT(*) c FROM breach",
    "actors": "SELECT COUNT(*) c FROM actor",
    "malware": "SELECT COUNT(*) c FROM malware",
    "pocs": "SELECT COUNT(*) c FROM poc",
    "hunt_rules": "SELECT COUNT(*) c FROM hunt_rule",
    "hunt_techniques": "SELECT COUNT(*) c FROM hunt_technique WHERE deprecated=0",
    "hunt_atomics": "SELECT COUNT(*) c FROM hunt_atomic",
}


def counts() -> dict[str, int]:
    out: dict[str, int] = {}
    with cursor() as conn:
        for key, sql in COUNTS_SQL.items():
            out[key] = conn.execute(sql).fetchone()["c"]
    return out
