# OSINT Scout

> **Attack Surface Reconnaissance Tool** — Aggregate recon intelligence from Shodan, Censys, and HackerTarget for any IP or domain. Includes CVE detection and risk scoring.

[![Python](https://img.shields.io/badge/Python-3.8%2B-blue?logo=python&logoColor=white)](https://python.org)
[![Shodan](https://img.shields.io/badge/Shodan-API-red)](https://shodan.io)
[![Censys](https://img.shields.io/badge/Censys-API%20v2-blue)](https://search.censys.io)
[![HackerTarget](https://img.shields.io/badge/HackerTarget-Free-green)](https://hackertarget.com)
[![License](https://img.shields.io/badge/License-MIT-green)](LICENSE)

---

## Features

| Feature | Source | Notes |
|---------|--------|-------|
| Open ports & services | Shodan + Censys + HackerTarget | Cross-referenced for accuracy |
| CVE / vulnerability detection | Shodan | Known exploits mapped to host |
| GeoIP + ASN + ISP info | All three | Country, city, org, ASN |
| Reverse DNS | HackerTarget | PTR record lookup |
| DNS records | HackerTarget | A, MX, NS, TXT for domains |
| Subdomain discovery | HackerTarget | Host search for domain targets |
| TLS certificate names | Censys | CN/SANs from leaf certificate |
| Whois data | HackerTarget | Registrar, creation/expiry dates |
| **Attack Surface Risk Score** | Aggregated | 0–100 with CRITICAL/HIGH/MEDIUM/LOW/INFO |
| Bulk scan | Built-in | `--file targets.txt` |
| JSON export | Built-in | `--export-json results.json` |

> **HackerTarget works with no API key** — 100 free queries/day.

---

## Quick Start

```bash
# 1. Clone
git clone https://github.com/thanhtoan1211/osint-scout.git
cd osint-scout

# 2. Install
pip install -r requirements.txt

# 3. Configure API keys
cp .env.example .env
# Edit .env — Shodan and Censys keys optional, HackerTarget works without

# 4. Scan
python scout.py -t 8.8.8.8
python scout.py -t google.com
```

---

## Usage

```
usage: scout [-h] (-t TARGET | -f FILE) [--export-json PATH] [--quiet] [--no-banner]
```

### Examples

```bash
# Single IP
python scout.py -t 185.220.101.45

# Domain (auto-resolves to IP, also pulls DNS + subdomains)
python scout.py -t target.com

# Bulk scan from file
python scout.py -f targets.txt --export-json results.json

# Quiet mode (risk summary only)
python scout.py -t 8.8.8.8 --quiet
```

---

## Sample Output

```
╭──────────────────────────────────────────────────╮
│  OSINT Scout  |  Attack Surface Reconnaissance   │
│  Shodan · Censys · HackerTarget  |  Bui Thanh Toan │
╰──────────────────────────────────────────────────╯

Scanning: 185.220.101.45

╭── Recon Report ──────────────────────────────────╮
│  Target  : 185.220.101.45                        │
│  Type    : IP                                    │
│  Scanned : 2025-01-10T08:00:00Z                  │
╰──────────────────────────────────────────────────╯

╭── Shodan ────────────────────────────────────────╮
│ Organization │ Emerald Onion                     │
│ ASN          │ AS396507                          │
│ Country      │ Germany                           │
│ Tags         │ tor                               │
│ Open Ports   │ 443, 9001                         │
│ CVEs         │ CVE-2021-44228  CVE-2022-0778     │
╰──────────────────────────────────────────────────╯

╭── HackerTarget ──────────────────────────────────╮
│ Reverse DNS  │ tor-exit.emeraldonion.org         │
│ Country      │ Germany                           │
│ ISP          │ Emerald Onion                     │
│ Open Ports   │ :443/tcp https                    │
│              │ :9001/tcp tor                     │
╰──────────────────────────────────────────────────╯

╭── Attack Surface Risk ───────────────────────────╮
│  Score   :   85/100  [█████████████████░░░]      │
│  Level   :   CRITICAL                            │
│  Ports   :   2 open                              │
│  CVEs    :   CVE-2021-44228, CVE-2022-0778       │
╰──────────────────────────────────────────────────╯
```

---

## Risk Score Logic

| Category | Points |
|----------|--------|
| Critical port exposed (RDP, SMB, Redis, MongoDB…) | +30 each |
| High-risk port (SSH, FTP, MySQL, MSSQL…) | +15 each |
| Other open port | +3 each |
| Known CVE on host | +25 each |
| **Cap** | 100 |

| Score | Level |
|-------|-------|
| 80–100 | CRITICAL |
| 60–79 | HIGH |
| 35–59 | MEDIUM |
| 10–34 | LOW |
| 0–9 | INFO |

### Critical ports tracked

| Port | Service |
|------|---------|
| 23 | Telnet |
| 445 | SMB |
| 3389 | RDP |
| 5900 | VNC |
| 6379 | Redis (no auth) |
| 9200 | Elasticsearch |
| 27017 | MongoDB |

---

## API Keys

| Service | Free Tier | Where to Sign Up |
|---------|-----------|-----------------|
| **Shodan** | 1 query/sec, limited results | [account.shodan.io](https://account.shodan.io/register) |
| **Censys** | 250 queries/month | [search.censys.io/register](https://search.censys.io/register) |
| **HackerTarget** | 100 queries/day (no key!) | [hackertarget.com](https://hackertarget.com) |

Configure in `.env`:
```env
SHODAN_API_KEY=your_key
CENSYS_API_ID=your_id
CENSYS_API_SECRET=your_secret
```

The tool runs with any combination of keys — even zero (HackerTarget only).

---

## Author

**Bui Thanh Toan** — Security Engineer
[buithanhtoan.vercel.app](https://buithanhtoan.vercel.app) · [github.com/thanhtoan1211](https://github.com/thanhtoan1211) · btoan123123@gmail.com
