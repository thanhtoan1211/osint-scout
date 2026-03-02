#!/usr/bin/env python3
"""
OSINT Scout — Enterprise Attack Surface Reconnaissance
======================================================
Concurrent intelligence from Shodan, Censys, and HackerTarget.

Enterprise features:
  - Parallel source queries via ThreadPoolExecutor
  - Thread-safe token-bucket rate limiting per API
  - Exponential-backoff retry (429, 5xx, timeout)
  - TTL result cache — skips duplicate targets in bulk runs
  - Structured logging (--verbose to enable debug output)
  - Progress bar for bulk scans

Author : Bui Thanh Toan
Email  : btoan123123@gmail.com
Web    : https://buithanhtoan.vercel.app
GitHub : https://github.com/thanhtoan1211
"""

import argparse
import json
import logging
import os
import re
import sys
import time
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timedelta
from functools import wraps
from pathlib import Path
from threading import Lock
from typing import Dict, List, Optional, Tuple

import requests
from dotenv import load_dotenv
from rich import box
from rich.console import Console
from rich.logging import RichHandler
from rich.panel import Panel
from rich.progress import (
    BarColumn, Progress, SpinnerColumn, TextColumn, TimeElapsedColumn,
)
from rich.table import Table
from rich.text import Text

# ── Bootstrap ──────────────────────────────────────────────────────────────────
load_dotenv(dotenv_path=Path(__file__).parent / ".env")

console = Console()
log     = logging.getLogger("scout")

# ── API base URLs ──────────────────────────────────────────────────────────────
SHODAN_BASE = "https://api.shodan.io"
CENSYS_BASE = "https://search.censys.io/api/v2"
HT_BASE     = "https://api.hackertarget.com"

# ── Patterns ───────────────────────────────────────────────────────────────────
RE_IPV4   = re.compile(
    r"^(?:(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}"
    r"(?:25[0-5]|2[0-4]\d|[01]?\d\d?)$"
)
RE_DOMAIN = re.compile(r"^(?:[a-zA-Z0-9_-]+\.)+[a-zA-Z]{2,}$")

# ── Risk config ────────────────────────────────────────────────────────────────
RISK_COLORS: Dict[str, str] = {
    "CRITICAL": "red",
    "HIGH":     "orange1",
    "MEDIUM":   "yellow",
    "LOW":      "green",
    "INFO":     "cyan",
}

# HTTP (80/443/8080/8443) intentionally excluded — normal for public web servers
HIGH_RISK_PORTS: Dict[int, str] = {
    21:    "FTP",
    22:    "SSH",
    23:    "Telnet",
    25:    "SMTP",
    445:   "SMB",
    1433:  "MSSQL",
    3306:  "MySQL",
    3389:  "RDP",
    5432:  "PostgreSQL",
    5900:  "VNC",
    6379:  "Redis",
    9200:  "Elasticsearch",
    9300:  "Elasticsearch-cluster",
    27017: "MongoDB",
    28017: "MongoDB-web",
}

# Extra risk weight — almost always dangerous if internet-exposed
CRITICAL_PORTS = frozenset({23, 445, 3389, 5900, 6379, 9200, 27017})


# ── Pure helpers ───────────────────────────────────────────────────────────────

def classify(target: str) -> str:
    """Classify a string as 'ip', 'domain', or 'unknown'."""
    t = target.strip()
    if RE_IPV4.match(t):   return "ip"
    if RE_DOMAIN.match(t): return "domain"
    return "unknown"


def calc_risk(ports: List[int], cves: List[str]) -> Tuple[int, str]:
    """Return (score 0-100, level string) for a given set of ports and CVEs."""
    score = sum(
        30 if p in CRITICAL_PORTS else 15 if p in HIGH_RISK_PORTS else 3
        for p in ports
    ) + len(cves) * 25
    score = min(score, 100)
    level = (
        "CRITICAL" if score >= 80 else
        "HIGH"     if score >= 60 else
        "MEDIUM"   if score >= 35 else
        "LOW"      if score >= 10 else "INFO"
    )
    return score, level


# ── Rate limiter (token-bucket, thread-safe) ───────────────────────────────────

class RateLimiter:
    """
    Thread-safe minimum-interval rate limiter.

    Guarantees at least `1 / calls_per_second` seconds between successive
    calls that pass through ``acquire()``.  Multiple threads block on a
    single shared lock so the overall throughput never exceeds the limit.
    """

    def __init__(self, calls_per_second: float) -> None:
        self._interval  = 1.0 / max(calls_per_second, 1e-9)
        self._last_call = 0.0
        self._lock      = Lock()

    def acquire(self) -> None:
        with self._lock:
            now  = time.monotonic()
            wait = self._interval - (now - self._last_call)
            if wait > 0:
                time.sleep(wait)
            self._last_call = time.monotonic()


# ── TTL result cache (thread-safe) ────────────────────────────────────────────

class ScanCache:
    """
    In-memory TTL cache for scan results.

    Avoids duplicate API calls when the same target appears multiple times
    in a bulk run or when ``scan()`` is called twice within the TTL window.
    """

    def __init__(self, ttl_seconds: int = 300) -> None:
        self._store: Dict[str, Tuple[datetime, Dict]] = {}
        self._ttl   = timedelta(seconds=ttl_seconds)
        self._lock  = Lock()

    def get(self, key: str) -> Optional[Dict]:
        with self._lock:
            entry = self._store.get(key)
            if entry is None:
                return None
            ts, data = entry
            if datetime.utcnow() - ts < self._ttl:
                return data
            del self._store[key]
            return None

    def put(self, key: str, data: Dict) -> None:
        with self._lock:
            self._store[key] = (datetime.utcnow(), data)

    def clear(self) -> None:
        with self._lock:
            self._store.clear()

    def size(self) -> int:
        with self._lock:
            return len(self._store)


# ── Retry decorator ────────────────────────────────────────────────────────────

def retry(
    max_attempts: int = 3,
    base_delay:   float = 2.0,
    retriable:    Tuple[int, ...] = (429, 500, 502, 503, 504),
):
    """
    Exponential-backoff retry for transient HTTP and timeout errors.

    Respects ``Retry-After`` headers for 429 responses.
    Non-retriable HTTP errors (401, 403, 404) are re-raised immediately.
    """
    def decorator(func):
        @wraps(func)
        def wrapper(*args, **kwargs):
            for attempt in range(max_attempts):
                try:
                    return func(*args, **kwargs)
                except requests.HTTPError as exc:
                    code = exc.response.status_code
                    if code not in retriable or attempt == max_attempts - 1:
                        raise
                    wait = float(
                        exc.response.headers.get("Retry-After",
                                                  base_delay * (2 ** attempt))
                    )
                    log.warning(
                        "HTTP %d from %s (attempt %d/%d) — retrying in %.0fs",
                        code, func.__qualname__, attempt + 1, max_attempts, wait,
                    )
                    time.sleep(wait)
                except requests.Timeout:
                    if attempt == max_attempts - 1:
                        raise
                    wait = base_delay * (2 ** attempt)
                    log.warning(
                        "Timeout in %s (attempt %d/%d) — retrying in %.0fs",
                        func.__qualname__, attempt + 1, max_attempts, wait,
                    )
                    time.sleep(wait)
        return wrapper
    return decorator


# ── Shodan ────────────────────────────────────────────────────────────────────

class ShodanClient:
    """Thin Shodan REST client with built-in rate limiting and retry."""

    _limiter = RateLimiter(calls_per_second=1.0)   # free tier: 1 req/s

    def __init__(self, key: str) -> None:
        self.key = key
        self.s   = requests.Session()
        self.s.headers["User-Agent"] = "osint-scout/2.0"

    @retry()
    def host(self, ip: str) -> Dict:
        self._limiter.acquire()
        r = self.s.get(
            f"{SHODAN_BASE}/shodan/host/{ip}",
            params={"key": self.key},
            timeout=15,
        )
        r.raise_for_status()
        return r.json()

    @retry()
    def resolve(self, domain: str) -> Optional[str]:
        self._limiter.acquire()
        r = self.s.get(
            f"{SHODAN_BASE}/dns/resolve",
            params={"hostnames": domain, "key": self.key},
            timeout=10,
        )
        r.raise_for_status()
        return r.json().get(domain)


def parse_shodan(raw: Dict) -> Dict:
    """Parse a raw Shodan /shodan/host/{ip} response into a normalised dict."""
    ports = sorted(raw.get("ports", []))
    vulns = sorted(raw.get("vulns", {}).keys())

    services: List[str] = []
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
    """Thin Censys v2 REST client with retry."""

    def __init__(self, api_id: str, secret: str) -> None:
        self.auth = (api_id, secret)
        self.s    = requests.Session()
        self.s.headers["User-Agent"] = "osint-scout/2.0"

    @retry()
    def host(self, ip: str) -> Dict:
        r = self.s.get(
            f"{CENSYS_BASE}/hosts/{ip}",
            auth=self.auth,
            timeout=15,
        )
        r.raise_for_status()
        return r.json()


def parse_censys(raw: Dict) -> Dict:
    """Parse a raw Censys v2 /hosts/{ip} response into a normalised dict."""
    res = raw.get("result", {})
    services: List[str] = []
    ports:    List[int] = []
    certs:    List[str] = []

    for svc in res.get("services", []):
        p         = svc.get("port")
        transport = svc.get("transport_protocol", "tcp").upper()
        name      = svc.get("service_name", "UNKNOWN")
        sw        = svc.get("software", [])
        product   = sw[0].get("product", "") if sw else ""
        label     = f"{name} {product}".strip()
        services.append(f":{p}/{transport}  {label}".strip())
        if p is not None:
            ports.append(p)
        for cn in (
            svc.get("tls", {})
            .get("certificates", {})
            .get("leaf_data", {})
            .get("names", [])[:2]
        ):
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
    """
    HackerTarget API client.

    No key is required for the free tier (100 queries/day).
    The rate limiter enforces 1 req/s to avoid triggering their throttle.
    """

    _limiter = RateLimiter(calls_per_second=1.0)

    def __init__(self, key: Optional[str] = None) -> None:
        self.key = key
        self.s   = requests.Session()
        self.s.headers["User-Agent"] = "osint-scout/2.0"

    @retry(max_attempts=2, base_delay=3.0)
    def _get(self, endpoint: str, q: str) -> str:
        self._limiter.acquire()
        params = {"q": q}
        if self.key:
            params["apikey"] = self.key
        r = self.s.get(f"{HT_BASE}/{endpoint}/", params=params, timeout=30)
        r.raise_for_status()
        text = r.text.strip()
        if text.lower().startswith("error"):
            raise RuntimeError(f"HackerTarget: {text}")
        return text

    def geoip(self, q: str)      -> str: return self._get("geoip",      q)
    def reversedns(self, q: str) -> str: return self._get("reversedns", q)
    def dnslookup(self, q: str)  -> str: return self._get("dnslookup",  q)
    def hostsearch(self, q: str) -> str: return self._get("hostsearch", q)
    def nmap(self, q: str)       -> str: return self._get("nmap",       q)
    def whois(self, q: str)      -> str: return self._get("whois",      q)


# ── HackerTarget pure parsers (testable without network) ──────────────────────

def parse_hackertarget_geoip(raw: str) -> Dict[str, str]:
    result: Dict[str, str] = {}
    for line in raw.splitlines():
        if ":" in line:
            k, _, v = line.partition(":")
            result[k.strip()] = v.strip()
    return result


def parse_hackertarget_nmap(raw: str) -> List[Dict]:
    """Parse HackerTarget nmap plain-text output into a list of port dicts."""
    ports: List[Dict] = []
    for line in raw.splitlines():
        # matches: "22/tcp  open  ssh" or "3389/tcp open  ms-wbt-server"
        m = re.match(r"^(\d+)/(tcp|udp)\s+open\s+(\S*)", line.strip())
        if m:
            ports.append({
                "port":    int(m.group(1)),
                "proto":   m.group(2),
                "service": m.group(3) or "unknown",
            })
    return ports[:15]


def parse_hackertarget_whois(raw: str) -> Dict[str, str]:
    info: Dict[str, str] = {}
    for line in raw.splitlines():
        for field in (
            "Registrar", "Creation Date", "Expiry Date",
            "Updated Date", "Name Server", "Registrant Org",
        ):
            if (
                line.strip().lower().startswith(field.lower())
                and ":" in line
                and field not in info
            ):
                _, _, v = line.partition(":")
                info[field] = v.strip()
    return info


# ── Core scanner ───────────────────────────────────────────────────────────────

class OSINTScout:
    """
    Orchestrates parallel queries to Shodan, Censys, and HackerTarget,
    aggregates port/CVE data, and computes an attack-surface risk score.

    Args:
        shodan_key: Shodan API key (None → Shodan skipped).
        censys_id / censys_secret: Censys API credentials (both required).
        ht_key: HackerTarget API key (None → free-tier, 100 req/day).
        cache_ttl: Seconds to cache results for the same target (default 300).
    """

    def __init__(
        self,
        shodan_key:    Optional[str] = None,
        censys_id:     Optional[str] = None,
        censys_secret: Optional[str] = None,
        ht_key:        Optional[str] = None,
        cache_ttl:     int = 300,
    ) -> None:
        self.shodan = ShodanClient(shodan_key) if shodan_key else None
        self.censys = (
            CensysClient(censys_id, censys_secret)
            if (censys_id and censys_secret) else None
        )
        self.ht     = HackerTargetClient(ht_key)
        self._cache = ScanCache(ttl_seconds=cache_ttl)

    # ── Private helpers ────────────────────────────────────────────────────────

    def _resolve(self, domain: str) -> str:
        """Resolve domain → IP via Shodan DNS, falling back to HackerTarget."""
        if self.shodan:
            try:
                ip = self.shodan.resolve(domain)
                if ip:
                    log.debug("Shodan DNS: %s → %s", domain, ip)
                    return ip
            except Exception as exc:
                log.debug("Shodan DNS failed: %s", exc)

        try:
            raw = self.ht.dnslookup(domain)
            for line in raw.splitlines():
                m = re.search(r"\b((?:\d{1,3}\.){3}\d{1,3})\b", line)
                if m:
                    ip = m.group(1)
                    log.debug("HackerTarget DNS: %s → %s", domain, ip)
                    return ip
        except Exception as exc:
            log.debug("HackerTarget DNS failed: %s", exc)

        log.warning("Could not resolve %s — using as-is for queries", domain)
        return domain

    def _query_shodan(self, ip: str) -> Dict:
        return parse_shodan(self.shodan.host(ip))  # type: ignore[union-attr]

    def _query_censys(self, ip: str) -> Dict:
        return parse_censys(self.censys.host(ip))  # type: ignore[union-attr]

    def _query_hackertarget(
        self, domain_or_ip: str, ip: str, target_type: str
    ) -> Dict:
        result: Dict = {
            "source":      "HackerTarget",
            "reverse_dns": "N/A",
            "geoip":       {},
            "dns_records": [],
            "subdomains":  [],
            "open_ports":  [],
            "whois_info":  {},
        }

        try:
            result["geoip"] = parse_hackertarget_geoip(
                self.ht.geoip(domain_or_ip)
            )
        except Exception as e:
            log.debug("HT geoip: %s", e)

        if target_type == "ip":
            try:
                rdns = self.ht.reversedns(ip)
                result["reverse_dns"] = rdns.split()[-1] if rdns else "N/A"
            except Exception as e:
                log.debug("HT reversedns: %s", e)

        if target_type == "domain":
            try:
                raw = self.ht.dnslookup(domain_or_ip)
                result["dns_records"] = [l for l in raw.splitlines() if l][:12]
            except Exception as e:
                log.debug("HT dnslookup: %s", e)

            try:
                raw = self.ht.hostsearch(domain_or_ip)
                result["subdomains"] = [
                    l.split(",")[0] for l in raw.splitlines() if l
                ][:10]
            except Exception as e:
                log.debug("HT hostsearch: %s", e)

        # Nmap must use the resolved IP, not a domain string
        try:
            raw = self.ht.nmap(ip)
            result["open_ports"] = parse_hackertarget_nmap(raw)
        except Exception as e:
            log.debug("HT nmap: %s", e)

        try:
            raw = self.ht.whois(domain_or_ip)
            result["whois_info"] = parse_hackertarget_whois(raw)
        except Exception as e:
            log.debug("HT whois: %s", e)

        return result

    # ── Public API ─────────────────────────────────────────────────────────────

    def scan(self, target: str) -> Dict:
        """
        Run a full OSINT scan against *target* (IP or domain).

        Sources are queried concurrently.  Results are cached for
        ``cache_ttl`` seconds so repeated calls don't waste API quota.
        """
        target = target.strip()
        log.debug("scan(%r)", target)

        cached = self._cache.get(target)
        if cached:
            log.info("Cache hit: %s (returning cached result)", target)
            return cached

        target_type = classify(target)
        record: Dict = {
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

        ip = self._resolve(target) if target_type == "domain" else target
        record["ip"] = ip if ip != target else None

        all_ports: List[int] = []
        all_cves:  List[str] = []

        # ── Concurrent source queries ──────────────────────────────────────────
        task_map: Dict[str, object] = {}
        with ThreadPoolExecutor(max_workers=3, thread_name_prefix="scout") as pool:
            if self.shodan and ip:
                task_map["shodan"] = pool.submit(self._query_shodan, ip)
            if self.censys and ip:
                task_map["censys"] = pool.submit(self._query_censys, ip)
            task_map["hackertarget"] = pool.submit(
                self._query_hackertarget, target, ip, target_type
            )

            for key, future in task_map.items():  # type: ignore[assignment]
                try:
                    data = future.result(timeout=120)  # type: ignore[union-attr]
                    record[key] = data
                    if key == "shodan":
                        all_ports.extend(data.get("ports", []))
                        all_cves.extend(data.get("cves", []))
                    elif key == "censys":
                        all_ports.extend(data.get("ports", []))
                    elif key == "hackertarget":
                        all_ports.extend(
                            p["port"] for p in data.get("open_ports", [])
                        )
                except Exception as exc:
                    log.error("Source %s failed for %s: %s", key, target, exc)
                    record[key] = {"source": key.title(), "error": str(exc)}

        # ── Risk scoring ───────────────────────────────────────────────────────
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

        self._cache.put(target, record)
        return record


# ── Rendering ──────────────────────────────────────────────────────────────────

def print_banner() -> None:
    console.print(Panel(
        "[bold cyan]OSINT Scout[/bold cyan]  [dim]|[/dim]  "
        "[dim]Attack Surface Reconnaissance[/dim]\n"
        "[dim]Shodan  ·  Censys  ·  HackerTarget  |  Bui Thanh Toan[/dim]",
        border_style="bright_blue",
        expand=False,
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

    if data.get("hostnames"):
        t.add_row("Hostnames", "\n".join(data["hostnames"]))
    if data.get("tags"):
        t.add_row("Tags", ", ".join(data["tags"]))

    ports = data.get("ports", [])
    t.add_row(
        "Open Ports",
        Text(", ".join(str(p) for p in ports) or "None",
             style="yellow" if ports else "dim"),
    )
    if data.get("services"):
        t.add_row("Services", "\n".join(data["services"]))

    cves = data.get("cves", [])
    if cves:
        cve_text = Text()
        for c in cves:
            cve_text.append(c + "\n", style="bold red")
        t.add_row("CVEs", cve_text)
    else:
        t.add_row("CVEs", Text("None found", style="green"))

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
    t.add_row(
        "Open Ports",
        Text(", ".join(str(p) for p in ports) or "None",
             style="yellow" if ports else "dim"),
    )
    if data.get("services"):
        t.add_row("Services", "\n".join(data["services"]))
    if data.get("certs"):
        t.add_row("TLS Certs", "\n".join(data["certs"]))

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
    if geo.get("Country"):
        t.add_row("Country", geo["Country"])
    if geo.get("City"):
        t.add_row("City", geo["City"])
    if geo.get("Latitude"):
        t.add_row("Lat / Lon",
                  f"{geo.get('Latitude', '?')} / {geo.get('Longitude', '?')}")
    if geo.get("ISP"):
        t.add_row("ISP", geo["ISP"])
    if data.get("dns_records"):
        t.add_row("DNS Records", "\n".join(data["dns_records"]))
    if data.get("subdomains"):
        t.add_row("Subdomains", "\n".join(data["subdomains"]))

    ports = data.get("open_ports", [])
    if ports:
        t.add_row(
            "Open Ports",
            Text(
                "\n".join(f":{p['port']}/{p['proto']}  {p['service']}"
                          for p in ports),
                style="yellow",
            ),
        )

    for field in ("Registrar", "Registrant Org", "Creation Date",
                  "Expiry Date", "Name Server"):
        if data.get("whois_info", {}).get(field):
            t.add_row(field, data["whois_info"][field])

    return t


def render_risk(risk: Dict, summary: Dict) -> None:
    score      = risk.get("score", 0)
    level      = risk.get("level", "INFO")
    color      = RISK_COLORS.get(level, "white")
    bar_filled = int(score / 5)
    bar        = "█" * bar_filled + "░" * (20 - bar_filled)

    crit  = summary.get("critical_ports", [])
    high  = [p for p in summary.get("high_risk_ports", []) if p not in crit]
    cves  = summary.get("cves", [])
    total = summary.get("total_open_ports", 0)

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
            "  ".join(f"{p}({HIGH_RISK_PORTS.get(p, '?')})" for p in crit) + "\n",
            style="bold red",
        )
    if high:
        content.append("  High    :  ", style="bold white")
        content.append(
            "  ".join(f"{p}({HIGH_RISK_PORTS.get(p, '?')})"
                      for p in high[:8]) + "\n",
            style="yellow",
        )
    if cves:
        content.append("  CVEs    :  ", style="bold white")
        content.append(", ".join(cves[:5]), style="bold red")
        if len(cves) > 5:
            content.append(f"  (+{len(cves) - 5} more)", style="dim")
        content.append("\n")

    console.print(Panel(
        content,
        title="[bold]Attack Surface Risk[/bold]",
        border_style=color,
        expand=False,
    ))


def render_record(rec: Dict) -> None:
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
        border_style="bright_blue", expand=False,
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


# ── Logging setup ─────────────────────────────────────────────────────────────

def setup_logging(verbose: bool = False) -> None:
    level = logging.DEBUG if verbose else logging.WARNING
    logging.basicConfig(
        level=level,
        format="%(message)s",
        handlers=[RichHandler(console=console, show_path=False, markup=True)],
    )
    log.setLevel(level)


# ── CLI ────────────────────────────────────────────────────────────────────────

def main() -> None:
    p = argparse.ArgumentParser(
        prog="scout",
        description="OSINT Scout — Shodan + Censys + HackerTarget recon tool",
        epilog=(
            "Examples:\n"
            "  python scout.py -t 8.8.8.8\n"
            "  python scout.py -t google.com --verbose\n"
            "  python scout.py -f targets.txt --export-json results.json\n"
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    mx = p.add_mutually_exclusive_group(required=True)
    mx.add_argument("-t", "--target", metavar="TARGET", help="IP address or domain")
    mx.add_argument("-f", "--file",   metavar="FILE",
                    help="File with targets, one per line")
    p.add_argument("--export-json", metavar="PATH", help="Save results as JSON")
    p.add_argument("--quiet",     action="store_true",
                   help="Skip per-target detail tables")
    p.add_argument("--verbose",   action="store_true",
                   help="Enable debug logging")
    p.add_argument("--no-banner", action="store_true")
    args = p.parse_args()

    setup_logging(verbose=args.verbose)

    if not args.no_banner:
        print_banner()

    shodan_key    = os.getenv("SHODAN_API_KEY")
    censys_id     = os.getenv("CENSYS_API_ID")
    censys_secret = os.getenv("CENSYS_API_SECRET")
    ht_key        = os.getenv("HACKERTARGET_API_KEY")

    if not shodan_key:
        console.print(
            "[yellow]SHODAN_API_KEY not set — Shodan checks skipped.[/yellow]"
        )
    if not (censys_id and censys_secret):
        console.print(
            "[yellow]CENSYS_API_ID / CENSYS_API_SECRET not set — "
            "Censys checks skipped.[/yellow]"
        )
    console.print(
        "[dim]HackerTarget: free tier active "
        "(100 queries/day without API key)[/dim]\n"
    )

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
            l.strip() for l in fp.read_text(encoding="utf-8").splitlines()
            if l.strip() and not l.strip().startswith("#")
        ]
        # Deduplicate while preserving order
        seen: set = set()
        targets = [t for t in targets if not (t in seen or seen.add(t))]  # type: ignore
        console.print(
            f"[cyan]Loaded {len(targets)} unique target(s) from[/cyan] {args.file}\n"
        )

    results: List[Dict] = []

    if len(targets) > 1:
        # Progress bar for bulk runs
        with Progress(
            SpinnerColumn(),
            TextColumn("[bold cyan]{task.description}"),
            BarColumn(),
            TextColumn("{task.completed}/{task.total}"),
            TimeElapsedColumn(),
            console=console,
            transient=True,
        ) as progress:
            task = progress.add_task("Scanning", total=len(targets))
            for target in targets:
                progress.update(task, description=f"Scanning [bold]{target}[/bold]")
                rec = scout.scan(target)
                results.append(rec)
                if not args.quiet:
                    render_record(rec)
                progress.advance(task)
    else:
        for target in targets:
            console.print(
                f"[dim]Scanning:[/dim] [bold cyan]{target}[/bold cyan]"
            )
            rec = scout.scan(target)
            results.append(rec)
            if not args.quiet:
                render_record(rec)

    if args.export_json:
        with open(args.export_json, "w", encoding="utf-8") as f:
            json.dump(results, f, indent=2, default=str)
        console.print(f"\n[green]JSON saved:[/green] {args.export_json}")


if __name__ == "__main__":
    main()
