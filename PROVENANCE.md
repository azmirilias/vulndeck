# Provenance and independence

This file exists so there is never a question about where VulnDeck came from.

## Statement

VulnDeck was written from scratch for this repository. It is **not** a fork, mirror,
translation or derivative work of MANTIS, OpenCTI, MISP, IntelOwl, YETI, SpiderFoot or any
other threat-intelligence product. No source code, template markup, stylesheet, database
schema, copy or design asset was copied from those projects, and this project claims no
affiliation with their authors or maintainers.

Functional scope overlaps with several open-source CTI tools — that overlap is unavoidable in
a field built on the same open standards (CVE IDs, CVSS, EPSS, KEV, OSV, STIX concepts).
Functionality and ideas are not copyrightable; the implementation here is original and its
provenance is the commit history of this repository.

If a future contribution does adapt third-party code, it must:

1. be compatible with this project's MIT licence;
2. retain the upstream copyright notice in `THIRD_PARTY_NOTICES.md`;
3. name the project and the exact upstream commit or release in the commit message.

## What this project reads

| Upstream | Licence / terms | Used as |
|---|---|---|
| CISA Known Exploited Vulnerabilities | US Government work, public domain | exploited-CVE records |
| EPSS — FIRST.org / Empirical Security | free to use with attribution | exploitation probability |
| OSV.dev (aggregates GHSA, PyPA, Go, RustSec, OSS-Fuzz, …) | each source's own licence, CC BY 4.0 for OSV-authored data | package advisories |
| CVE.org / MITRE | CVE Terms of Use | CVE records (referenced, not mirrored) |
| NVD / NIST | public domain | CVSS and CPE context (linked, not mirrored) |
| CISA, Unit 42, Cisco Talos, Securelist, WeLiveSecurity, The DFIR Report, SANS ISC, Krebs on Security, Recorded Future, CERT-FR, NCSC UK, Full Disclosure | publisher copyright | title, short feed excerpt and source link only |
| Ransomware.live | public RSS; publisher terms | victim/group/sector/date metadata and original link; claims are unverified |
| Have I Been Pwned | public breach metadata API terms | breach metadata only; no exposed records |
| DailyDarkWeb | publisher copyright | RSS headlines, short excerpts and links; allegations are labelled unverified |
| MISP Galaxy JSON | dual-licensed CC0 1.0 or BSD-style 2-condition terms | structured actor/malware reference data; source names and references retained |
| GitHub repository search | GitHub API terms | public repository metadata and links only; no code downloaded or executed |
| OpenCode Go | configured model/provider terms | only on-request RSS title/excerpt is sent for a generated summary; no full publisher article is fetched |

## What this project deliberately avoids

- Leaked corpora, breach dumps, stealer logs, combolists.
- Any source whose terms forbid redistribution of derived data.
- Feeds that now require a key before returning a single byte (abuse.ch moved its public
  downloads behind a free Auth-Key in 2026; its legacy plain-text blocklists are still
  accepted where they remain published, but nothing is fetched from gated endpoints).
- Scraping behind authentication, paywalls, CAPTCHAs or bot walls.

## Design credit

The approach of leading with exploitation evidence rather than raw CVSS severity follows
public guidance from CISA (KEV) and FIRST (EPSS). The single-file-connector ingestion pattern
and the "public data only" stance echo lessons published by the MISP and OpenCTI communities.
Credit for those ideas belongs to them; the code in this repository is ours.
