# Threat Hunting Module — VulnDeck (plan for review)

Integrated into the existing VulnDeck app (same FastAPI process, same port 8090,
same `vulndeck.azmirilias.com` nginx vhost). No new nginx site.

## Spike verdict (feasibility probed 2026-11-22)

| Question | Result |
|---|---|
| SigmaHQ ingest | VALIDATED — repo `SigmaHQ/sigma`, master, ~50 MB, updated daily. Shallow `git clone --depth 1` then scan `rules/**/*.yml`. Needs PyYAML. |
| MITRE ATT&CK | VALIDATED — `mitre/cti` `enterprise-attack.json` (49 MB). Download daily, parse STIX, keep only techniques/sub-techniques + tactics/platforms/URLs. |
| Atomic Red Team | VALIDATED — `redcanaryco/atomic-red-team`, clone `--depth 1`, read `atomics/index.yaml` + per-technique YAML. |
| Sigma matching (pySigma) | DEFERRED — MVP is a rule catalog only; matching engine is a later phase. PyYAML is the only new dep. |
| Keyless IOC enrichment | PARTIAL — `abuse.ch` (ThreatFox/MalwareBazaar/URLhaus) now returns `Unauthorized` without a free Auth-Key. Keyless working: RIPEstat (IP/ASN). crt.sh + ThreatMiner are slow/flaky. Optional keys later via env (`ABUSE_CH_KEY`, `OTX_KEY`, `VT_KEY`). |

## Dependencies to add (requirements.txt)
- `PyYAML` (Sigma + atomic parsing)
- (later) `pysigma` for matching; not MVP.

## Schema (new tables in `data/vulndeck.db`)

```
hunt_rule (
  id TEXT PRIMARY KEY,          -- sha1 of rule path
  title, description, status, level,
  logsource TEXT,               -- JSON {category, product, service}
  detection TEXT,               -- JSON (raw detection block)
  tags TEXT, author, date, references TEXT,
  techniques TEXT,              -- comma MITRE IDs
  path TEXT
)
hunt_technique (
  id TEXT PRIMARY KEY,          -- T1055
  name, description,
  tactics TEXT,                 -- comma
  platforms TEXT,               -- comma
  url, deprecated INTEGER, is_sub INTEGER
)
hunt_atomic (
  technique_id TEXT,            -- T1055
  name TEXT, path TEXT,
  yaml TEXT,                    -- raw per-technique yaml
  test_count INTEGER,
  PRIMARY KEY (technique_id)
)
hunt_ioc_cache (
  ioc TEXT, ioc_type TEXT,
  source TEXT, result TEXT,     -- JSON
  ts TEXT, expiry TEXT,
  PRIMARY KEY (ioc, ioc_type, source)
)
hunt_hypothesis (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  title, hypothesis, technique_id,
  data_sources TEXT, status TEXT,
  created TEXT, notes TEXT
)
```

## Route map

| Route | Content |
|---|---|
| `/hunt` | dashboard: rule/technique/atomic counts, coverage gap, latest rules |
| `/rules` | Sigma catalog — search + filter (level, logsource, technique) |
| `/rules/{id}` | rule detail (title, level, logsource, detection, refs) |
| `/techniques` | ATT&CK browse grouped by tactic |
| `/techniques/{id}` | technique detail + linked sigma rules + atomic tests |
| `/atomics` | Atomic Red Team index (search by technique) |
| `/ioc` | IOC lookup form + enrichment (hash/domain/ip, cached) |
| `/hunts` | hunt book (hypothesis list) + `/hunts/{id}` |
| `/api/ioc/{type}/{value}` | JSON enrichment endpoint |

All get canonical + JSON-LD + sitemap entries (reuse existing render/sitemap helpers).
NAV gains a "Hunt" entry.

## Ingest jobs (added to existing `vulndeck-ingest.timer`, or a second `hunt-ingest.timer` daily)

- `sigma` — pull repo, scan YAML, upsert `hunt_rule`
- `attack` — download 49 MB JSON, parse STIX, upsert `hunt_technique`
- `atomics` — pull repo, upsert `hunt_atomic`
- IOC enrichment is on-demand + cached (rate-limited, timeout), never during page render.

## Risks / rules

- Never call external search APIs during page rendering (per skill). IOC lookup is
  user-triggered with cache + per-client cooldown + timeout.
- 49 MB ATT&CK and ~50 MB Sigma are streamed/parsed once, not held in RAM or stored whole.
- Unverified/label-sensitivity rules from `references/cti-enrichment.md` apply to any new CTI source.
- Existing `/malware` page currently reads MISP `tool.json` but labels it "malware & tools";
  per skill it should use malware-specific clusters (`malpedia.json`, `mitre-malware.json`,
  `ransomware.json`), not `tool.json`. Fold this fix into this work.

## Build order (TDD, per phase)

1. Spike (done — this doc).
2. Schema + `hunt_ingest.py` + route skeleton — REVIEW (this doc).
3. TDD: parsers (sigma/att&ck/atomic) + URL/indicator safety + UTC date handling.
4. Routes + templates + SEO surfaces.
5. `requesting-code-review` + `dogfood` QA.
6. Deploy UAT on vulndeck, verify, then production.
