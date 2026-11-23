# VulnDeck

**DevSecOps vulnerability & threat intelligence, rendered as plain HTML.**

VulnDeck answers three questions fast: what is being exploited right now, how likely is
everything else to be exploited, and which open-source dependency is affected. It merges the
CISA KEV catalog, EPSS exploit-probability scores, the OSV advisory corpus and publisher RSS
into one server-rendered site that runs in ~60 MB of RAM on a single small VPS.

- **Exploited list** — every CVE with confirmed in-the-wild exploitation, cross-referenced with EPSS.
- **Vendor dossiers** — exploited-CVE history per vendor, generated as indexable pages.
- **Package advisories** — 60k+ OSV records with CVE mapping, CVSS 3.x base scoring and ecosystem tags.
- **Intel feed** — headline + link from CISA, Unit 42, Talos, Securelist, ESET, DFIR Report, SANS ISC, CERT-FR, NCSC UK.
- **Machine-readable** — JSON API, RSS, sitemap index, `security.txt`.
- **Ransomware Monitor** — Ransomware.live public victim claims with a dedicated page and RSS; claims are explicitly unverified.
- **Breach Watcher** — HIBP breach metadata plus separately labelled DailyDarkWeb reporting; no leaked records or dumps.
- **Actor & malware reference** — MISP Galaxy threat actors and malware/ransomware clusters, with source references.
- **PoC index** — scheduled GitHub repository metadata search attached to CVE pages; code is never downloaded or executed.
- **IOC mentions** — article-feed CVE, public IPv4 and domain matches shown as unverified mentions, searchable from article pages.
- **AI summaries** — on-request OpenCode Go summaries of RSS title/excerpt, cached and rate-limited per client.
- **Daily digest** — `/today` includes only records dated today in UTC.

## Why it is built this way

| Constraint | Decision |
|---|---|
| Must not eat RAM | One Python process, SQLite (WAL, 8 MB page cache), no ORM, no worker pool. Measured RSS: ~60 MB serving, ~80 MB during ingest. |
| Must not need Node | Server-rendered Jinja templates. No JS framework, no hydration, no client-side fetching. |
| Must be crawlable | Every page is complete HTML on first byte, with canonical URLs, JSON-LD, RSS, chunked sitemaps (1,786 CVE pages + 298 vendor pages out of the box). |
| Must not break the bank | Only free, keyless sources by default. No paid CTI feeds, no vendor APIs. |
| Must be honest | Every connector logs its outcome publicly at `/sources`. Failed feeds are shown as failed. |

## Quick start

```bash
python3 -m venv .venv && . .venv/bin/activate
pip install -r requirements.txt
python -m app.ingest          # ~30 s: KEV, EPSS, OSV advisories, RSS
python -m app.main 8090       # http://127.0.0.1:8090
```

Optional npm advisories (≈210 MB export, weekly job): `VULNDECK_OSV_NPM=1 python -m app.ingest advisories-osv`.

## Layout

```
app/config.py     brand, base URL, nav — the only file to touch when renaming
app/db.py         schema + SQLite access (stdlib only)
app/ingest.py     one function per upstream source, failure-isolated
app/web.py        routes, SEO surfaces (sitemap, RSS, JSON-LD, robots)
app/templates/    Jinja2, semantic HTML5
app/static/       one stylesheet, ~15 KB, no webfonts, dark mode included
deploy/           systemd unit, nginx vhost, timer for ingest
tests/            smoke tests against a temporary database
```

## Data sources

| Source | Data | Access | Terms |
|---|---|---|---|
| CISA KEV | exploited CVEs, due dates, ransomware flag | JSON feed | US Gov, public domain |
| EPSS (FIRST / Empirical Security) | exploitation probability, percentile | daily CSV.gz | free with attribution |
| OSV.dev | package advisories, aliases, CVSS vectors | bulk zip per ecosystem | OSV data is CC BY 4.0 / per-source |
| CVE.org, NVD | CVE records, CVSS, CPEs | REST | public |
| Publisher RSS | primary research headlines, short excerpts and original links | RSS/Atom | publisher retains rights |
| Ransomware.live | group, victim name, sector and discovery date | public RSS | leak-site claims; unverified, metadata only |
| Have I Been Pwned | breach name/domain/date/count/data classes | public metadata API | no exposed records or breach dumps |
| DailyDarkWeb | breach/access-sale reports | public RSS | claims shown separately as unverified; publisher retains rights |
| MISP Galaxy / MITRE clusters | threat actor, malware and ransomware reference profiles | public JSON | MISP Galaxy JSON: CC0 1.0 or BSD-style terms; keep attribution/references |
| GitHub search | trending repositories mentioning CVE IDs | public API; optional token | metadata/links only; code is never downloaded or run |
| OpenCode Go | requested summary of an RSS title and short excerpt | configured OpenCode model | output is generated; verify against the publisher |

Full detail and exclusions: `/sources` in the app, and [PROVENANCE.md](PROVENANCE.md).

## Optional API keys

IOC enrichment (Threat Hunting → IOC Lookup) and the PoC index run without any key, but
a key turns each source on. Copy `.env.example` to `.env` (mode 600) and fill in only
what you need; `vulndeck.service` loads it via `EnvironmentFile`. Sources without a key
are skipped gracefully — the rest of the site keeps running.

| Variable | Service | Enables | Notes |
|---|---|---|---|
| `VT_KEY` | VirusTotal | IP / domain reputation in IOC Lookup | free account has a daily quota |
| `ABUSE_CH_KEY` | abuse.ch | ThreatFox, MalwareBazaar, URLhaus lookups | free Auth-Key from abuse.ch |
| `OTX_KEY` | AlienVault OTX | pulses + malware count for IP / domain / URL | free key from OTX |
| `SHODAN_KEY` | Shodan | (optional) | free `oss` plan reports 0 query credits |
| `GITHUB_TOKEN` | GitHub | higher PoC-search rate limit | anonymous = 60 req/h |

Never commit `.env` — it is already in `.gitignore`. Only `.env.example` is tracked.

## Production deployment

Production hostname: `https://xxxx.xxxxx.com`.

Before switching the live VPS, create this DNS record at the domain provider and wait for it to resolve:

```text
xxxx.xxxxx.com(domain)  A  yyy.yyy.yyy.yyy(IP Address)
```

Verify DNS first (`dig +short https://xxxx.xxxxx.com A` must return `yyy.yyy.yyy.yyy`), then obtain a trusted certificate with the temporary ACME vhost and install the production config:

```bash
sudo cp deploy/vulndeck-acme-bootstrap.conf /etc/nginx/sites-available/vulndeck-acme-bootstrap.conf
sudo ln -sfn /etc/nginx/sites-available/vulndeck-acme-bootstrap.conf /etc/nginx/sites-enabled/vulndeck-acme-bootstrap.conf
sudo nginx -t && sudo systemctl reload nginx
sudo certbot certonly --webroot -w /var/www/html --non-interactive --agree-tos -m security@xxxxx.com -d xxxx.xxxxx.com
sudo rm /etc/nginx/sites-enabled/vulndeck-acme-bootstrap.conf

sudo cp deploy/vulndeck.service /etc/systemd/system/
sudo cp deploy/vulndeck-ingest.service deploy/vulndeck-ingest.timer /etc/systemd/system/
sudo cp deploy/vulndeck-rate-zone.conf /etc/nginx/conf.d/vulndeck-zone.conf
sudo cp deploy/nginx-vulndeck.conf /etc/nginx/sites-available/vulndeck.conf
sudo ln -sfn /etc/nginx/sites-available/vulndeck.conf /etc/nginx/sites-enabled/vulndeck.conf
sudo systemctl daemon-reload
sudo nginx -t && sudo systemctl restart vulndeck && sudo systemctl reload nginx
sudo systemctl enable --now vulndeck-ingest.timer
```

Do not install the production nginx file until the DNS record and certificate both exist. Data refresh runs every 30 minutes; temporary ingest files are kept under `data/tmp`.

## Licence

Code: MIT (see [LICENSE](LICENSE)). Upstream data remains the property of its publishers.
VulnDeck is an independent project — see [PROVENANCE.md](PROVENANCE.md).
