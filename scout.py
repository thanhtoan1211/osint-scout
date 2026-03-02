#!/usr/bin/env python3
"""
OSINT Scout — Attack Surface Reconnaissance Tool
=================================================
Aggregate recon intelligence from Shodan, Censys, and HackerTarget
for any IP or domain. Identifies open ports, services, CVEs, and
calculates an attack-surface risk score.

Author : Bui Thanh Toan
Email  : btoan123123@gmail.com
Web    : https://buithanhtoan.vercel.app
GitHub : https://github.com/thanhtoan1211
"""

import argparse
import json
import os
import re
import sys
import time
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Optional, Tuple

import requests
from dotenv import load_dotenv
from rich import box
from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.text import Text

# ── Load .env ─────────────────────────────────────────────────────────────────
load_dotenv(dotenv_path=Path(__file__).parent / ".env")

console = Console()

# ── API base URLs ──────────────────────────────────────────────────────────────
SHODAN_BASE = "https://api.shodan.io"
CENSYS_BASE = "https://search.censys.io/api/v2"
HT_BASE     = "https://api.hackertarget.com"

# ── Patterns ───────────────────────────────────────────────────────────────────
RE_IPV4   = re.compile(r"^(\d{1,3}\.){3}\d{1,3}$")
RE_DOMAIN = re.compile(r"^(?:[a-zA-Z0-9-]+\.)+[a-zA-Z]{2,}$")

# ── Risk config ────────────────────────────────────────────────────────────────
RISK_COLORS = {
    "CRITICAL": "red",
    "HIGH":     "orange1",
    "MEDIUM":   "yellow",
    "LOW":      "green",
    "INFO":     "cyan",
}

# Ports that indicate significant exposure
HIGH_RISK_PORTS: Dict[int, str] = {
    21:    "FTP",
    22:    "SSH",
    23:    "Telnet",
    25:    "SMTP",
    80:    "HTTP",
    443:   "HTTPS",
    445:   "SMB",
    1433:  "MSSQL",
    3306:  "MySQL",
    3389:  "RDP",
    5432:  "PostgreSQL",
    5900:  "VNC",
    6379:  "Redis",
    8080:  "HTTP-Alt",
    8443:  "HTTPS-Alt",
    9200:  "Elasticsearch",
    9300:  "Elasticsearch (cluster)",
    27017: "MongoDB",
    28017: "MongoDB (web)",
}

# Extra weight — these are almost always dangerous if exposed
CRITICAL_PORTS = {23, 445, 3389, 5900, 6379, 9200, 27017}


# ── Helpers ────────────────────────────────────────────────────────────────────

def classify(target: str) -> str:
    t = target.strip()
    if RE_IPV4.match(t):   return "ip"
    if RE_DOMAIN.match(t): return "domain"
    return "unknown"


def calc_risk(ports: List[int], cves: List[str]) -> Tuple[int, str]:
    score = 0
    for p in ports:
        if p in CRITICAL_PORTS:    score += 30
        elif p in HIGH_RISK_PORTS: score += 15
        else:                      score += 3
    score += len(cves) * 25
    score  = min(score, 100)
    level  = (
        "CRITICAL" if score >= 80 else
        "HIGH"     if score >= 60 else
        "MEDIUM"   if score >= 35 else
        "LOW"      if score >= 10 else "INFO"
    )
    return score, level


# ── Shodan ────────────────────────────────────────────────────────────────────

class ShodanClient:
    def __init__(self, key: str):
        self.key = key
        self.s   = requests.Session()

    def host(self, ip: str) -> Dict:
        r = self.s.get(f"{SHODAN_BASE}/shodan/host/{ip}",
                       params={"key": self.key}, timeout=15)
        r.raise_for_status()
        return r.json()

    def resolve(self, domain: str) -> Optional[str]:
        r = self.s.get(f"{SHODAN_BASE}/dns/resolve",
                       params={"hostnames": domain, "key": self.key}, timeout=10)
        r.raise_for_status()
        return r.json().get(domain)


def parse_shodan(raw: Dict) -> Dict:
    ports = sorted(raw.get("ports", []))
    vulns = list(raw.get("vulns", {}).keys())

    services = []
    for item in raw.get("data", [])[:10]:
        port    = item.get("port", "?")
        product = item.get("product", "")
        version = item.get("version", "")
        module  = item.get("_shodan", {}).get("module", "")
        label   = f"{product} {version}".strip() or module
        services.append(f":{port}  {label}" if label else f":{port}")

    return {
        "source":      "Shodan",
        "org":         raw.get("org", "N/A"),
        "isp":         raw.get("isp", "N/A"),
        "asn":         raw.get("asn", "N/A"),
        "country":     raw.get("country_name", "N/A"),
        "city":        raw.get("city", "N/A"),
        "os":          raw.get("os") or "N/A",
        "hostnames":   raw.get("hostnames", [])[:5],
        "tags":        raw.get("tags", []),
        "ports":       ports,
        "services":    services,
        "cves":        vulns,
        "last_update": raw.get("last_update", "N/A"),
    }


# ── Censys ────────────────────────────────────────────────────────────────────

class CensysClient:
    def __init__(self, api_id: str, secret: str):
        self.auth = (api_id, secret)
        self.s    = requests.Session()

    def host(self, ip: str) -> Dict:
        r = self.s.get(f"{CENSYS_BASE}/hosts/{ip}",
                       auth=self.auth, timeout=15)
        r.raise_for_status()
        return r.json()


def parse_censys(raw: Dict) -> Dict:
    res = raw.get("result", {})
    services, ports, certs = [], [], []

    for svc in res.get("services", []):
        p         = svc.get("port")
        transport = svc.get("transport_protocol", "tcp").upper()
        name      = svc.get("service_name", "UNKNOWN")
        sw        = svc.get("software", [])
        product   = sw[0].get("product", "") if sw else ""
        label     = f"{name} {product}".strip()
        services.append(f":{p}/{transport}  {label}".strip())
        ports.append(p)

        # TLS certificate names
        tls = svc.get("tls", {})
        for cn in tls.get("certificates", {}).get("leaf_data", {}).get("names", [])[:2]:
            certs.append(cn)

    loc     = res.get("location", {})
    asn_inf = res.get("autonomous_system", {})
    return {
        "source":      "Censys",
        "org":         asn_inf.get("name", "N/A"),
        "asn":         asn_inf.get("asn", "N/A"),
        "country":     loc.get("country", "N/A"),
        "city":        loc.get("city", "N/A"),
        "ports":       sorted(ports),
        "services":    services[:10],
        "certs":       list(set(certs))[:5],
        "last_update": res.get("last_updated_at", "N/A"),
    }


# ── HackerTarget ──────────────────────────────────────────────────────────────

class HackerTargetClient:
    def __init__(self, key: Optional[str] = None):
        self.key = key
        self.s   = requests.Session()

    def _get(self, endpoint: str, q: str) -> str:
        params = {"q": q}
        if self.key:
            params["apikey"] = self.key
        r = self.s.get(f"{HT_BASE}/{endpoint}/", params=params, timeout=25)
        r.raise_for_status()
        return r.text.strip()

    def geoip(self, q):       return self._get("geoip", q)
    def reversedns(self, q):  return self._get("reversedns", q)
    def dnslookup(self, q):   return self._get("dnslookup", q)
    def hostsearch(self, q):  return self._get("hostsearch", q)
    def nmap(self, q):        return self._get("nmap", q)
    def whois(self, q):       return self._get("whois", q)


def parse_hackertarget(target: str, target_type: str, ht: HackerTargetClient) -> Dict:
    result = {
        "source":       "HackerTarget",
        "reverse_dns":  "N/A",
        "geoip":        {},
        "dns_records":  [],
        "subdomains":   [],
        "open_ports":   [],
        "whois_info":   {},
    }

    # ── GeoIP
    try:
        for line in ht.geoip(target).splitlines():
            if ":" in line:
                k, _, v = line.partition(":")
                result["geoip"][k.strip()] = v.strip()
        time.sleep(0.4)
    except Exception:
        pass

    # ── Reverse DNS (IP targets)
    if target_type == "ip":
        try:
            rdns = ht.reversedns(target)
            if rdns and "error" not in rdns.lower():
                result["reverse_dns"] = rdns.split()[-1]
            time.sleep(0.4)
        except Exception:
            pass

    # ── DNS records (domain targets)
    if target_type == "domain":
        try:
            dns_raw = ht.dnslookup(target)
            result["dns_records"] = [
                l for l in dns_raw.splitlines()
                if l and "error" not in l.lower()
            ][:12]
            time.sleep(0.4)
        except Exception:
            pass

        # ── Subdomain/host search
        try:
            hs_raw = ht.hostsearch(target)
            result["subdomains"] = [
                l.split(",")[0] for l in hs_raw.splitlines()
                if l and "error" not in l.lower()
            ][:10]
            time.sleep(0.4)
        except Exception:
            pass

    # ── Nmap port scan
    try:
        nmap_raw = ht.nmap(target)
        ports = []
        for line in nmap_raw.splitlines():
            m = re.search(r"(\d+)/(tcp|udp)\s+(\w+)\s*(.*)?", line)
            if m and m.group(3) == "open":
                ports.append({
                    "port":    int(m.group(1)),
                    "proto":   m.group(2),
                    "service": (m.group(4) or "").strip() or "unknown",
                })
        result["open_ports"] = ports[:15]
        time.sleep(0.4)
    except Exception:
        pass

    # ── Whois
    try:
        whois_raw = ht.whois(target)
        info = {}
        for line in whois_raw.splitlines():
            for field in ("Registrar", "Creation Date", "Expiry Date",
                          "Updated Date", "Name Server", "Registrant Org"):
                if line.strip().lower().startswith(field.lower()) and ":" in line:
                    k, _, v = line.partition(":")
                    if field not in info:
                        info[field] = v.strip()
        result["whois_info"] = info
        time.sleep(0.4)
    except Exception:
        pass

    return result


# ── Core scanner ───────────────────────────────────────────────────────────────

class OSINTScout:
    def __init__(self, shodan_key=None, censys_id=None, censys_secret=None,
                 ht_key=None):
        self.shodan = ShodanClient(shodan_key) if shodan_key else None
        self.censys = CensysClient(censys_id, censys_secret) \
                      if (censys_id and censys_secret) else None
        self.ht     = HackerTargetClient(ht_key)

    def scan(self, target: str) -> Dict:
        target      = target.strip()
        target_type = classify(target)
        ip          = target

        record = {
            "target":       target,
            "type":         target_type,
            "ip":           None,
            "timestamp":    datetime.utcnow().isoformat() + "Z",
            "shodan":       None,
            "censys":       None,
            "hackertarget": None,
            "risk":         {},
            "summary":      {},
        }

        if target_type == "unknown":
            record["error"] = f"Cannot classify target: {target!r}"
            return record

        # ── Resolve domain → IP
        if target_type == "domain":
            if self.shodan:
                try:
                    resolved = self.shodan.resolve(target)
                    if resolved:
                        ip = resolved
                except Exception:
                    pass
            if ip == target:
                # Fallback: parse HackerTarget DNS lookup
                try:
                    dns_raw = self.ht.dnslookup(target)
                    for line in dns_raw.splitlines():
                        m = re.search(r"\b(\d{1,3}(?:\.\d{1,3}){3})\b", line)
                        if m:
                            ip = m.group(1)
                            break
                    time.sleep(0.4)
                except Exception:
                    pass

        record["ip"] = ip if ip != target else None

        all_ports: List[int] = []
        all_cves:  List[str] = []

        # ── Shodan
        if self.shodan:
            try:
                sh = parse_shodan(self.shodan.host(ip))
                record["shodan"] = sh
                all_ports.extend(sh["ports"])
                all_cves.extend(sh["cves"])
                time.sleep(0.3)
            except Exception as e:
                record["shodan"] = {"source": "Shodan", "error": str(e)}

        # ── Censys
        if self.censys:
            try:
                ce = parse_censys(self.censys.host(ip))
                record["censys"] = ce
                all_ports.extend(ce["ports"])
                time.sleep(0.3)
            except Exception as e:
                record["censys"] = {"source": "Censys", "error": str(e)}

        # ── HackerTarget (no key required for basic queries)
        try:
            ht_data = parse_hackertarget(target, target_type, self.ht)
            record["hackertarget"] = ht_data
            all_ports.extend(p["port"] for p in ht_data.get("open_ports", []))
        except Exception as e:
            record["hackertarget"] = {"source": "HackerTarget", "error": str(e)}

        # ── Risk scoring
        unique_ports = sorted(set(all_ports))
        unique_cves  = sorted(set(all_cves))
        score, level = calc_risk(unique_ports, unique_cves)

        record["risk"]    = {"score": score, "level": level}
        record["summary"] = {
            "unique_ports":     unique_ports,
            "total_open_ports": len(unique_ports),
            "high_risk_ports":  [p for p in unique_ports if p in HIGH_RISK_PORTS],
            "critical_ports":   [p for p in unique_ports if p in CRITICAL_PORTS],
            "cves":             unique_cves,
        }
        return record


# ── Rendering ──────────────────────────────────────────────────────────────────

def print_banner():
    console.print(Panel(
        "[bold cyan]OSINT Scout[/bold cyan]  [dim]|[/dim]  "
        "[dim]Attack Surface Reconnaissance Tool[/dim]\n"
        "[dim]Shodan  ·  Censys  ·  HackerTarget  |  Author: Bui Thanh Toan[/dim]",
        border_style="bright_blue", expand=False
    ))


def _table(title: str, color: str) -> Table:
    t = Table(
        title=f"[bold]{title}[/bold]",
        box=box.ROUNDED,
        border_style=color,
        show_header=True,
        header_style="bold magenta",
        min_width=58,
    )
    t.add_column("Field", style="bold white", no_wrap=True, width=22)
    t.add_column("Value")
    return t


def render_shodan(data: Optional[Dict]) -> Optional[Table]:
    if not data:
        return None
    if "error" in data:
        t = _table("Shodan", "red")
        t.add_row("Error", data["error"])
        return t

    color = "red" if data.get("cves") else "bright_blue"
    t = _table("Shodan", color)
    t.add_row("Organization", data.get("org", "N/A"))
    t.add_row("ISP",          data.get("isp", "N/A"))
    t.add_row("ASN",          str(data.get("asn", "N/A")))
    t.add_row("Country",      data.get("country", "N/A"))
    t.add_row("City",         data.get("city", "N/A"))
    t.add_row("OS",           data.get("os", "N/A"))

    hostnames = data.get("hostnames", [])
    if hostnames:
        t.add_row("Hostnames", "\n".join(hostnames))

    tags = data.get("tags", [])
    if tags:
        t.add_row("Tags", ", ".join(tags))

    ports = data.get("ports", [])
    t.add_row("Open Ports",
              Text(", ".join(str(p) for p in ports) or "None",
                   style="yellow" if ports else "dim"))

    services = data.get("services", [])
    if services:
        t.add_row("Services", "\n".join(services))

    cves = data.get("cves", [])
    cve_text = Text()
    if cves:
        for c in cves:
            cve_text.append(c + "\n", style="bold red")
    else:
        cve_text = Text("None found", style="green")
    t.add_row("CVEs", cve_text)
    t.add_row("Last Scan", data.get("last_update", "N/A"))
    return t


def render_censys(data: Optional[Dict]) -> Optional[Table]:
    if not data:
        return None
    if "error" in data:
        t = _table("Censys", "red")
        t.add_row("Error", data["error"])
        return t

    t = _table("Censys", "bright_blue")
    t.add_row("Organization", data.get("org", "N/A"))
    t.add_row("ASN",          str(data.get("asn", "N/A")))
    t.add_row("Country",      data.get("country", "N/A"))
    t.add_row("City",         data.get("city", "N/A"))

    ports = data.get("ports", [])
    t.add_row("Open Ports",
              Text(", ".join(str(p) for p in ports) or "None",
                   style="yellow" if ports else "dim"))

    services = data.get("services", [])
    if services:
        t.add_row("Services", "\n".join(services))

    certs = data.get("certs", [])
    if certs:
        t.add_row("TLS Certs", "\n".join(certs))

    t.add_row("Last Scan", data.get("last_update", "N/A"))
    return t


def render_hackertarget(data: Optional[Dict]) -> Optional[Table]:
    if not data:
        return None
    if "error" in data:
        t = _table("HackerTarget", "red")
        t.add_row("Error", data["error"])
        return t

    t = _table("HackerTarget", "green")
    geo = data.get("geoip", {})

    t.add_row("Reverse DNS", data.get("reverse_dns", "N/A"))
    if geo.get("Country"):  t.add_row("Country",   geo["Country"])
    if geo.get("City"):     t.add_row("City",       geo["City"])
    if geo.get("Latitude"): t.add_row("Lat / Lon",
                                      f"{geo.get('Latitude','?')} / {geo.get('Longitude','?')}")
    if geo.get("ISP"):      t.add_row("ISP",        geo["ISP"])

    dns = data.get("dns_records", [])
    if dns:
        t.add_row("DNS Records", "\n".join(dns))

    subs = data.get("subdomains", [])
    if subs:
        t.add_row("Subdomains", "\n".join(subs))

    ports = data.get("open_ports", [])
    if ports:
        port_lines = [f":{p['port']}/{p['proto']}  {p['service']}" for p in ports]
        t.add_row("Open Ports", Text("\n".join(port_lines), style="yellow"))

    whois = data.get("whois_info", {})
    for field in ("Registrar", "Registrant Org", "Creation Date",
                  "Expiry Date", "Name Server"):
        if whois.get(field):
            t.add_row(field, whois[field])

    return t


def render_risk(risk: Dict, summary: Dict):
    score       = risk.get("score", 0)
    level       = risk.get("level", "INFO")
    color       = RISK_COLORS.get(level, "white")
    bar_filled  = int(score / 5)
    bar         = "█" * bar_filled + "░" * (20 - bar_filled)

    crit   = summary.get("critical_ports", [])
    high   = [p for p in summary.get("high_risk_ports", []) if p not in crit]
    cves   = summary.get("cves", [])
    total  = summary.get("total_open_ports", 0)

    content = Text()
    content.append("  Score   :  ", style="bold white")
    content.append(f"{score:>3}/100  [{bar}]\n", style=f"bold {color}")
    content.append("  Level   :  ", style="bold white")
    content.append(f"{level}\n", style=f"bold {color}")
    content.append("  Ports   :  ", style="bold white")
    content.append(f"{total} open\n")

    if crit:
        content.append("  Critical:  ", style="bold white")
        content.append(
            "  ".join(f"{p} ({HIGH_RISK_PORTS.get(p,'?')})" for p in crit) + "\n",
            style="bold red"
        )
    if high:
        content.append("  High    :  ", style="bold white")
        content.append(
            "  ".join(f"{p} ({HIGH_RISK_PORTS.get(p,'?')})" for p in high[:8]) + "\n",
            style="yellow"
        )
    if cves:
        content.append("  CVEs    :  ", style="bold white")
        shown = cves[:5]
        content.append(", ".join(shown), style="bold red")
        if len(cves) > 5:
            content.append(f"  (+{len(cves)-5} more)", style="dim")
        content.append("\n")

    console.print(Panel(
        content,
        title=f"[bold]Attack Surface Risk[/bold]",
        border_style=color,
        expand=False,
    ))


def render_record(rec: Dict):
    # Header panel
    hdr = Text()
    hdr.append("  Target  : ", style="bold white")
    hdr.append(f"{rec['target']}\n", style="bold yellow")
    hdr.append("  Type    : ", style="bold white")
    hdr.append(f"{rec['type'].upper()}\n", style="cyan")
    if rec.get("ip") and rec["ip"] != rec["target"]:
        hdr.append("  IP      : ", style="bold white")
        hdr.append(f"{rec['ip']}\n", style="cyan")
    hdr.append("  Scanned : ", style="bold white")
    hdr.append(rec.get("timestamp", ""), style="dim")

    console.print(Panel(
        hdr, title="[bold]Recon Report[/bold]",
        border_style="bright_blue", expand=False
    ))

    if rec.get("error"):
        console.print(f"  [red]Error:[/red] {rec['error']}\n")
        return

    for fn, key in [
        (render_shodan,       "shodan"),
        (render_censys,       "censys"),
        (render_hackertarget, "hackertarget"),
    ]:
        tbl = fn(rec.get(key))
        if tbl:
            console.print(tbl)

    if rec.get("risk"):
        render_risk(rec["risk"], rec.get("summary", {}))
    console.print()


# ── CLI ────────────────────────────────────────────────────────────────────────

def main():
    p = argparse.ArgumentParser(
        prog="scout",
        description="OSINT Scout — Shodan + Censys + HackerTarget recon tool",
        epilog=(
            "Examples:\n"
            "  python scout.py -t 8.8.8.8\n"
            "  python scout.py -t google.com\n"
            "  python scout.py -f targets.txt --export-json results.json\n"
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    mx = p.add_mutually_exclusive_group(required=True)
    mx.add_argument("-t", "--target", metavar="TARGET", help="IP address or domain")
    mx.add_argument("-f", "--file",   metavar="FILE",   help="File with targets, one per line")
    p.add_argument("--export-json", metavar="PATH", help="Save results as JSON")
    p.add_argument("--quiet",     action="store_true", help="Summary risk only, no detail tables")
    p.add_argument("--no-banner", action="store_true")
    args = p.parse_args()

    if not args.no_banner:
        print_banner()

    shodan_key    = os.getenv("SHODAN_API_KEY")
    censys_id     = os.getenv("CENSYS_API_ID")
    censys_secret = os.getenv("CENSYS_API_SECRET")
    ht_key        = os.getenv("HACKERTARGET_API_KEY")  # optional

    if not shodan_key:
        console.print("[yellow]SHODAN_API_KEY not set — Shodan checks skipped.[/yellow]")
    if not (censys_id and censys_secret):
        console.print("[yellow]CENSYS_API_ID / CENSYS_API_SECRET not set — Censys checks skipped.[/yellow]")
    console.print("[dim]HackerTarget: free tier (no key required for basic scans)[/dim]\n")

    scout = OSINTScout(shodan_key, censys_id, censys_secret, ht_key)

    targets: List[str] = []
    if args.target:
        targets = [args.target]
    elif args.file:
        fp = Path(args.file)
        if not fp.is_file():
            console.print(f"[red]File not found:[/red] {args.file}")
            sys.exit(1)
        targets = [
            l.strip() for l in fp.read_text().splitlines()
            if l.strip() and not l.strip().startswith("#")
        ]
        console.print(f"[cyan]Loaded {len(targets)} target(s) from[/cyan] {args.file}\n")

    results = []
    for target in targets:
        console.print(f"[dim]Scanning:[/dim] [bold cyan]{target}[/bold cyan]")
        rec = scout.scan(target)
        results.append(rec)
        if not args.quiet:
            render_record(rec)

    if args.export_json:
        with open(args.export_json, "w") as f:
            json.dump(results, f, indent=2, default=str)
        console.print(f"\n[green]JSON saved:[/green] {args.export_json}")


if __name__ == "__main__":
    main()
