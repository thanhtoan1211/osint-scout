# OSINT Scout

> **Enterprise Attack Surface & Credential Exposure Reconnaissance** — Aggregate threat intelligence from Shodan, Censys, and HackedList.io for any IP or domain. Covers open ports, CVEs, TLS data, and darknet credential breach exposure in a single scan.

[![Python](https://img.shields.io/badge/Python-3.8%2B-blue?logo=python&logoColor=white)](https://python.org)
[![Shodan](https://img.shields.io/badge/Shodan-API-red)](https://shodan.io)
[![Censys](https://img.shields.io/badge/Censys-API%20v2-blue)](https://search.censys.io)
[![HackedList](https://img.shields.io/badge/HackedList.io-Darknet_Intel-darkred)](https://hackedlist.io)
[![License](https://img.shields.io/badge/License-MIT-green)](LICENSE)

---

## Features

| Feature | Source | Notes |
|---------|--------|-------|
| Open ports & services | Shodan + Censys | Cross-referenced for accuracy |
| CVE / vulnerability detection | Shodan | Known exploits mapped to host |
| GeoIP + ASN + ISP info | Shodan + Censys | Country, city, org, ASN |
| TLS certificate names | Censys | CN/SANs from leaf certificate |
| **Credential breach intelligence** | HackedList.io | Infostealer dump exposure by domain |
| **Credential exposure level** | HackedList.io | NONE / LOW / MEDIUM / HIGH / CRITICAL |
| **Attack Surface Risk Score** | Aggregated | 0–100 combining ports + CVEs + credential exposure |
| Bulk scan | Built-in | `--file targets.txt` |
| JSON export | Built-in | `--export-json results.json` |

---

## Enterprise Architecture

The three data sources cover distinct security dimensions:

```
┌─────────────┐  ports + CVEs    ┌───────────────────────┐
│   Shodan    │ ───────────────► │                       │
├─────────────┤                  │     Composite Risk    │
│   Censys    │ ─── ports + TLS ►│     Score (0–100)     │
├─────────────┤                  │                       │
│ HackedList  │ ── cred. breach ►│                       │
└─────────────┘                  └───────────────────────┘
```

- **Shodan** — external attack surface: what ports and services are exposed, known CVEs
- **Censys** — secondary validation: corroborates open ports, adds TLS certificate intelligence
- **HackedList.io** — credential compromise: how many domain accounts are in darknet infostealer dumps

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
# Edit .env — all three keys are optional; the tool runs with any subset

# 4. Scan
python scout.py -t 8.8.8.8
python scout.py -t google.com
```

---

## Usage

```
usage: scout [-h] (-t TARGET | -f FILE) [--export-json PATH] [--quiet] [--verbose] [--no-banner]
```

### Examples

```bash
# Single IP
python scout.py -t 185.220.101.45

# Domain (auto-resolves, also pulls credential breach data from HackedList)
python scout.py -t target.com

# Bulk scan from file
python scout.py -f targets.txt --export-json results.json

# Verbose debug output
python scout.py -t 8.8.8.8 --verbose

# Quiet mode (risk summary only)
python scout.py -t 8.8.8.8 --quiet
```

---

## Sample Output

```
╭─────────────────────────────────────────────────────────────╮
│  OSINT Scout  |  Attack Surface & Credential Exposure Recon │
│  Shodan · Censys · HackedList.io  |  Bui Thanh Toan         │
╰─────────────────────────────────────────────────────────────╯

Scanning: corp.example.com

╭── Recon Report ──────────────────────────────────────────────╮
│  Target  : corp.example.com                                  │
│  Type    : DOMAIN                                            │
│  IP      : 203.0.113.42                                      │
│  Scanned : 2025-01-10T08:00:00Z                              │
╰──────────────────────────────────────────────────────────────╯

╭── Shodan ────────────────────────────────────────────────────╮
│ Organization │ Corp Networks                                 │
│ ASN          │ AS64496                                       │
│ Open Ports   │ 22, 443, 3389                                 │
│ CVEs         │ CVE-2021-44228                                │
╰──────────────────────────────────────────────────────────────╯

╭── HackedList.io — Credential Intelligence ───────────────────╮
│ Domain             │ corp.example.com                        │
│ Compromised Creds  │ 1,523                                   │
│ Exposure Level     │ HIGH                                    │
│ Infostealer Sources│ RedLine Stealer                         │
│                    │ Vidar Stealer                           │
│ Latest Breach      │ 2024-06-01                              │
╰──────────────────────────────────────────────────────────────╯

╭── Attack Surface Risk ───────────────────────────────────────╮
│  Score   :   95/100  [███████████████████░]                  │
│  Level   :   CRITICAL                                        │
│  Ports   :   3 open                                          │
│  Creds   :   1,523 compromised credentials (infostealer)     │
│  Critical:   3389(RDP)                                       │
│  High    :   22(SSH)                                         │
│  CVEs    :   CVE-2021-44228                                  │
╰──────────────────────────────────────────────────────────────╯
```

---

## Risk Score Logic

### Attack Surface (ports + CVEs)

| Category | Points |
|----------|--------|
| Critical port exposed (RDP, SMB, Redis, MongoDB…) | +30 each |
| High-risk port (SSH, FTP, MySQL, MSSQL…) | +15 each |
| Other open port | +3 each |
| Known CVE on host | +25 each |

### Credential Exposure (HackedList.io)

| Compromised Accounts | Added Points |
|----------------------|-------------|
| 1 – 99 | +5 |
| 100 – 999 | +10 |
| 1,000 – 9,999 | +20 |
| 10,000+ | +30 |

### Risk Levels

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
| 6379 | Redis (unauthenticated) |
| 9200 | Elasticsearch |
| 27017 | MongoDB |

> HTTP/HTTPS (80, 443, 8080, 8443) are intentionally excluded — normal for public web servers.

---

## API Keys

| Service | Requirement | Where to Sign Up |
|---------|-------------|-----------------|
| **Shodan** | Optional (free tier: 1 req/s) | [account.shodan.io](https://account.shodan.io/register) |
| **Censys** | Optional (free tier: 250 req/month) | [search.censys.io/register](https://search.censys.io/register) |
| **HackedList.io** | Optional (paid, domain owners) | [hackedlist.io](https://hackedlist.io) |

Configure in `.env`:
```env
SHODAN_API_KEY=your_key
CENSYS_API_ID=your_id
CENSYS_API_SECRET=your_secret
HACKEDLIST_API_KEY=your_key
```

The tool runs with any combination of keys — results are simply skipped for missing sources.

> **Note:** HackedList credential intelligence is only applicable to domain targets (not plain IPs), as breach data is indexed by email domain.

---

## Running Tests

```bash
pip install pytest
pytest tests/ -v
```

89 tests covering: target classification, risk scoring (ports + CVEs + credentials), rate limiting, TTL cache, all parsers, and full scan orchestration with mocked HTTP.

---

## Author

**Bui Thanh Toan** — Security Engineer
[buithanhtoan.vercel.app](https://buithanhtoan.vercel.app) · [github.com/thanhtoan1211](https://github.com/thanhtoan1211) · btoan123123@gmail.com
