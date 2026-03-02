"""
OSINT Scout — Test Suite
========================
Tests cover: classify, calc_risk, RateLimiter, ScanCache,
all pure parsers, and OSINTScout.scan() with mocked HTTP.

Run:
    pip install pytest
    pytest tests/ -v
"""

import sys
import time
import threading
from datetime import datetime, timedelta
from pathlib import Path
from unittest.mock import MagicMock, patch, PropertyMock

import pytest

# ── ensure scout is importable from parent directory ──────────────────────────
sys.path.insert(0, str(Path(__file__).parent.parent))

from scout import (
    classify,
    calc_risk,
    RateLimiter,
    ScanCache,
    parse_shodan,
    parse_censys,
    parse_hackertarget_geoip,
    parse_hackertarget_nmap,
    parse_hackertarget_whois,
    OSINTScout,
    HIGH_RISK_PORTS,
    CRITICAL_PORTS,
)


# ══════════════════════════════════════════════════════════════════════════════
# Fixtures — realistic mock API responses
# ══════════════════════════════════════════════════════════════════════════════

SHODAN_HOST_CLEAN = {
    "ip_str":       "8.8.8.8",
    "org":          "Google LLC",
    "isp":          "Google LLC",
    "asn":          "AS15169",
    "country_name": "United States",
    "city":         "Mountain View",
    "os":           None,
    "hostnames":    ["dns.google"],
    "tags":         [],
    "ports":        [53, 443],
    "vulns":        {},
    "data": [
        {
            "port":     53,
            "product":  "Google public DNS",
            "version":  "",
            "_shodan":  {"module": "dns"},
        },
        {
            "port":     443,
            "product":  "nginx",
            "version":  "1.18.0",
            "_shodan":  {"module": "https"},
        },
    ],
    "last_update": "2025-01-10T08:00:00.000Z",
}

SHODAN_HOST_MALICIOUS = {
    "ip_str":       "185.220.101.45",
    "org":          "Emerald Onion",
    "isp":          "Emerald Onion",
    "asn":          "AS396507",
    "country_name": "Germany",
    "city":         "Frankfurt",
    "os":           None,
    "hostnames":    ["tor-exit.emeraldonion.org"],
    "tags":         ["tor"],
    "ports":        [443, 3389, 6379],
    "vulns":        {
        "CVE-2021-44228": {"cvss": 10.0},
        "CVE-2022-0778":  {"cvss": 7.5},
    },
    "data": [
        {"port": 443,  "product": "nginx", "version": "1.18.0",
         "_shodan": {"module": "https"}},
        {"port": 3389, "product": "Microsoft Terminal Services", "version": "",
         "_shodan": {"module": "rdp"}},
        {"port": 6379, "product": "Redis", "version": "6.2.6",
         "_shodan": {"module": "redis"}},
    ],
    "last_update": "2025-01-10T08:00:00.000Z",
}

CENSYS_HOST = {
    "result": {
        "ip": "8.8.8.8",
        "services": [
            {
                "port":               53,
                "transport_protocol": "udp",
                "service_name":       "DNS",
                "software":           [],
                "tls":                {},
            },
            {
                "port":               443,
                "transport_protocol": "tcp",
                "service_name":       "HTTPS",
                "software":           [{"product": "nginx"}],
                "tls": {
                    "certificates": {
                        "leaf_data": {
                            "names": ["*.google.com", "google.com"]
                        }
                    }
                },
            },
        ],
        "location": {
            "country": "United States",
            "city":    "Mountain View",
        },
        "autonomous_system": {
            "asn":  15169,
            "name": "Google LLC",
        },
        "last_updated_at": "2025-01-10T08:00:00Z",
    }
}

HT_GEOIP_RAW = (
    "IP: 8.8.8.8\n"
    "Country: United States\n"
    "State: California\n"
    "City: Mountain View\n"
    "Latitude: 37.3860\n"
    "Longitude: -122.0838\n"
    "ISP: Google LLC\n"
)

HT_RDNS_RAW = "8.8.8.8 dns.google\n"

HT_NMAP_RAW = (
    "Starting Nmap scan...\n"
    "PORT     STATE  SERVICE\n"
    "53/tcp   open   domain\n"
    "443/tcp  open   https\n"
    "8080/tcp closed http-proxy\n"   # closed — should NOT be included
    "22/tcp   open   ssh\n"
)

HT_NMAP_EMPTY = "Starting Nmap scan...\nNmap done: 0 hosts up\n"

HT_WHOIS_RAW = (
    "Domain Name: GOOGLE.COM\n"
    "Registrar: MarkMonitor Inc.\n"
    "Updated Date: 2024-09-09T00:00:00Z\n"
    "Creation Date: 1997-09-15T04:00:00Z\n"
    "Expiry Date: 2028-09-14T04:00:00Z\n"
    "Name Server: ns1.google.com\n"
)


# ══════════════════════════════════════════════════════════════════════════════
# TestClassify
# ══════════════════════════════════════════════════════════════════════════════

class TestClassify:

    # ── Valid IPv4 ─────────────────────────────────────────────────────────────
    def test_ip_standard(self):
        assert classify("8.8.8.8") == "ip"

    def test_ip_loopback(self):
        assert classify("127.0.0.1") == "ip"

    def test_ip_broadcast(self):
        assert classify("255.255.255.255") == "ip"

    def test_ip_zeros(self):
        assert classify("0.0.0.0") == "ip"

    def test_ip_leading_whitespace(self):
        assert classify("  1.2.3.4  ") == "ip"

    # ── Invalid IPv4 — must NOT match ─────────────────────────────────────────
    def test_ip_octet_256(self):
        assert classify("256.1.1.1") == "unknown"

    def test_ip_octet_999(self):
        assert classify("999.0.0.1") == "unknown"

    def test_ip_only_three_octets(self):
        assert classify("192.168.1") == "unknown"

    def test_ip_trailing_dot(self):
        assert classify("192.168.1.") == "unknown"

    # ── Valid domains ─────────────────────────────────────────────────────────
    def test_domain_simple(self):
        assert classify("google.com") == "domain"

    def test_domain_subdomain(self):
        assert classify("mail.google.com") == "domain"

    def test_domain_multi_tld(self):
        assert classify("bbc.co.uk") == "domain"

    def test_domain_hyphen(self):
        assert classify("my-site.example.com") == "domain"

    def test_domain_underscore(self):
        assert classify("_dmarc.example.com") == "domain"

    # ── Unknown ───────────────────────────────────────────────────────────────
    def test_unknown_bare_word(self):
        assert classify("foobar") == "unknown"

    def test_unknown_hash(self):
        assert classify("44d88612fea8a8f36de82e1278abb02f") == "unknown"

    def test_unknown_empty(self):
        assert classify("") == "unknown"


# ══════════════════════════════════════════════════════════════════════════════
# TestCalcRisk
# ══════════════════════════════════════════════════════════════════════════════

class TestCalcRisk:

    def test_no_ports_no_cves(self):
        score, level = calc_risk([], [])
        assert score == 0
        assert level == "INFO"

    def test_single_low_port(self):
        # Port 8888 is not in HIGH_RISK or CRITICAL → +3
        score, level = calc_risk([8888], [])
        assert score == 3
        assert level == "INFO"

    def test_single_high_risk_port(self):
        # SSH (22) → +15
        score, level = calc_risk([22], [])
        assert score == 15
        assert level == "LOW"

    def test_single_critical_port(self):
        # RDP (3389) → +30 → LOW range (10-34)
        score, level = calc_risk([3389], [])
        assert score == 30
        assert level == "LOW"

    def test_two_critical_ports(self):
        # 3389 + 445 → 60
        score, level = calc_risk([3389, 445], [])
        assert score == 60
        assert level == "HIGH"

    def test_three_critical_ports(self):
        # 3389 + 445 + 6379 → 90 (capped at 100)
        score, level = calc_risk([3389, 445, 6379], [])
        assert score == 90
        assert level == "CRITICAL"

    def test_cve_only(self):
        # 2 CVEs → 50
        score, level = calc_risk([], ["CVE-2021-44228", "CVE-2022-0778"])
        assert score == 50
        assert level == "MEDIUM"

    def test_mixed_critical_and_cves(self):
        # 3389 (30) + 2 CVEs (50) = 80 → capped at 80 → CRITICAL
        score, level = calc_risk([3389], ["CVE-2021-44228", "CVE-2022-0778"])
        assert score == 80
        assert level == "CRITICAL"

    def test_score_capped_at_100(self):
        # Many critical ports + many CVEs → must never exceed 100
        ports = list(CRITICAL_PORTS)
        cves  = [f"CVE-2024-{i:04d}" for i in range(10)]
        score, _ = calc_risk(ports, cves)
        assert score == 100

    def test_http_https_not_counted_as_high_risk(self):
        # 80 and 443 are NOT in HIGH_RISK_PORTS → only +3 each
        score, level = calc_risk([80, 443], [])
        assert score == 6
        assert level == "INFO"

    def test_level_boundaries(self):
        # Exact boundary checks
        assert calc_risk([], [])[1]  == "INFO"       # 0
        assert calc_risk([22], [])[1] == "LOW"        # 15
        # MEDIUM boundary: score 35
        # 22 (15) + 8888 (3) * 6 + need 2 more = 22 (15) + 7 low ports (21) = 36
        score, level = calc_risk([22, 100, 101, 102, 103, 104, 105, 106], [])
        assert level == "MEDIUM"


# ══════════════════════════════════════════════════════════════════════════════
# TestRateLimiter
# ══════════════════════════════════════════════════════════════════════════════

class TestRateLimiter:

    def test_first_call_immediate(self):
        rl = RateLimiter(calls_per_second=100.0)
        start = time.monotonic()
        rl.acquire()
        elapsed = time.monotonic() - start
        assert elapsed < 0.05, "First acquire() should not block"

    def test_second_call_respects_interval(self):
        # 2 calls/second → 0.5s interval
        rl = RateLimiter(calls_per_second=2.0)
        rl.acquire()
        start = time.monotonic()
        rl.acquire()
        elapsed = time.monotonic() - start
        assert elapsed >= 0.45, f"Expected ~0.5s wait, got {elapsed:.3f}s"

    def test_thread_safety_no_exceed(self):
        """Multiple threads must never exceed the configured rate."""
        rl       = RateLimiter(calls_per_second=10.0)
        calls    = []
        lock     = threading.Lock()

        def worker():
            rl.acquire()
            with lock:
                calls.append(time.monotonic())

        threads = [threading.Thread(target=worker) for _ in range(5)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()

        # All timestamps should be at least 0.09s apart (1/10 - 10% tolerance)
        calls.sort()
        for i in range(1, len(calls)):
            gap = calls[i] - calls[i - 1]
            assert gap >= 0.09, f"Gap {gap:.3f}s is too small — rate exceeded"


# ══════════════════════════════════════════════════════════════════════════════
# TestScanCache
# ══════════════════════════════════════════════════════════════════════════════

class TestScanCache:

    def test_miss_on_empty(self):
        cache = ScanCache(ttl_seconds=60)
        assert cache.get("8.8.8.8") is None

    def test_hit_within_ttl(self):
        cache = ScanCache(ttl_seconds=60)
        data  = {"target": "8.8.8.8", "risk": {"score": 0}}
        cache.put("8.8.8.8", data)
        assert cache.get("8.8.8.8") == data

    def test_miss_after_ttl_expired(self):
        cache = ScanCache(ttl_seconds=1)
        cache.put("1.2.3.4", {"target": "1.2.3.4"})
        time.sleep(1.1)
        assert cache.get("1.2.3.4") is None

    def test_overwrite(self):
        cache = ScanCache(ttl_seconds=60)
        cache.put("1.1.1.1", {"v": 1})
        cache.put("1.1.1.1", {"v": 2})
        assert cache.get("1.1.1.1") == {"v": 2}

    def test_clear(self):
        cache = ScanCache(ttl_seconds=60)
        cache.put("a", {"x": 1})
        cache.put("b", {"x": 2})
        assert cache.size() == 2
        cache.clear()
        assert cache.size() == 0
        assert cache.get("a") is None

    def test_different_keys_independent(self):
        cache = ScanCache(ttl_seconds=60)
        cache.put("a", {"data": "A"})
        cache.put("b", {"data": "B"})
        assert cache.get("a")["data"] == "A"
        assert cache.get("b")["data"] == "B"

    def test_thread_safe_concurrent_writes(self):
        cache   = ScanCache(ttl_seconds=60)
        errors  = []

        def writer(key, val):
            try:
                for _ in range(50):
                    cache.put(key, {"v": val})
                    cache.get(key)
            except Exception as e:
                errors.append(e)

        threads = [threading.Thread(target=writer, args=(str(i), i))
                   for i in range(8)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()

        assert not errors, f"Thread-safety errors: {errors}"


# ══════════════════════════════════════════════════════════════════════════════
# TestParseShodan
# ══════════════════════════════════════════════════════════════════════════════

class TestParseShodan:

    def test_clean_host_ports(self):
        result = parse_shodan(SHODAN_HOST_CLEAN)
        assert result["ports"] == [53, 443]

    def test_clean_host_no_cves(self):
        result = parse_shodan(SHODAN_HOST_CLEAN)
        assert result["cves"] == []

    def test_clean_host_org(self):
        result = parse_shodan(SHODAN_HOST_CLEAN)
        assert result["org"] == "Google LLC"

    def test_clean_host_hostnames(self):
        result = parse_shodan(SHODAN_HOST_CLEAN)
        assert "dns.google" in result["hostnames"]

    def test_malicious_host_cves(self):
        result = parse_shodan(SHODAN_HOST_MALICIOUS)
        assert "CVE-2021-44228" in result["cves"]
        assert "CVE-2022-0778"  in result["cves"]

    def test_malicious_host_ports(self):
        result = parse_shodan(SHODAN_HOST_MALICIOUS)
        assert 3389 in result["ports"]
        assert 6379 in result["ports"]

    def test_services_extracted(self):
        result = parse_shodan(SHODAN_HOST_CLEAN)
        # Should contain at least one service entry
        assert len(result["services"]) >= 1
        # Service for port 443 should mention nginx
        assert any("nginx" in svc for svc in result["services"])

    def test_missing_fields_use_defaults(self):
        result = parse_shodan({})
        assert result["org"]     == "N/A"
        assert result["country"] == "N/A"
        assert result["os"]      == "N/A"
        assert result["ports"]   == []
        assert result["cves"]    == []

    def test_ports_sorted(self):
        raw    = dict(SHODAN_HOST_CLEAN)
        raw["ports"] = [443, 22, 80, 8080]
        result = parse_shodan(raw)
        assert result["ports"] == sorted(result["ports"])

    def test_source_field(self):
        assert parse_shodan({})["source"] == "Shodan"


# ══════════════════════════════════════════════════════════════════════════════
# TestParseCensys
# ══════════════════════════════════════════════════════════════════════════════

class TestParseCensys:

    def test_ports_extracted(self):
        result = parse_censys(CENSYS_HOST)
        assert 443 in result["ports"]

    def test_org_extracted(self):
        result = parse_censys(CENSYS_HOST)
        assert result["org"] == "Google LLC"

    def test_certs_extracted(self):
        result = parse_censys(CENSYS_HOST)
        assert any("google.com" in c for c in result["certs"])

    def test_services_formatted(self):
        result = parse_censys(CENSYS_HOST)
        # Should have an entry containing HTTPS
        assert any("HTTPS" in s for s in result["services"])

    def test_empty_response(self):
        result = parse_censys({})
        assert result["ports"]    == []
        assert result["services"] == []
        assert result["certs"]    == []

    def test_none_port_filtered(self):
        """Services with missing port should not crash or add None to list."""
        raw = {
            "result": {
                "services": [{"service_name": "UNKNOWN"}],
                "location": {},
                "autonomous_system": {},
            }
        }
        result = parse_censys(raw)
        assert None not in result["ports"]

    def test_source_field(self):
        assert parse_censys({})["source"] == "Censys"

    def test_ports_sorted(self):
        result = parse_censys(CENSYS_HOST)
        assert result["ports"] == sorted(result["ports"])


# ══════════════════════════════════════════════════════════════════════════════
# TestParseHackerTargetHelpers
# ══════════════════════════════════════════════════════════════════════════════

class TestParseHackerTargetGeoip:

    def test_parses_all_fields(self):
        result = parse_hackertarget_geoip(HT_GEOIP_RAW)
        assert result["Country"]   == "United States"
        assert result["City"]      == "Mountain View"
        assert result["Latitude"]  == "37.3860"
        assert result["ISP"]       == "Google LLC"

    def test_empty_string(self):
        assert parse_hackertarget_geoip("") == {}

    def test_lines_without_colon_ignored(self):
        raw    = "no colon here\nCountry: Germany\n"
        result = parse_hackertarget_geoip(raw)
        assert len(result) == 1
        assert result["Country"] == "Germany"


class TestParseHackerTargetNmap:

    def test_open_ports_extracted(self):
        result = parse_hackertarget_nmap(HT_NMAP_RAW)
        ports  = [p["port"] for p in result]
        assert 53   in ports
        assert 443  in ports
        assert 22   in ports
        # closed port must NOT be included
        assert 8080 not in ports

    def test_service_name_captured(self):
        result = parse_hackertarget_nmap(HT_NMAP_RAW)
        by_port = {p["port"]: p for p in result}
        assert by_port[53]["service"]  == "domain"
        assert by_port[443]["service"] == "https"

    def test_proto_captured(self):
        result = parse_hackertarget_nmap(HT_NMAP_RAW)
        for p in result:
            assert p["proto"] in ("tcp", "udp")

    def test_empty_nmap_output(self):
        assert parse_hackertarget_nmap(HT_NMAP_EMPTY) == []

    def test_max_15_ports(self):
        lines = "\n".join(
            f"{port}/tcp  open  svc" for port in range(1, 25)
        )
        result = parse_hackertarget_nmap(lines)
        assert len(result) <= 15

    def test_udp_ports_included(self):
        raw    = "53/udp  open  domain\n"
        result = parse_hackertarget_nmap(raw)
        assert result[0]["proto"] == "udp"


class TestParseHackerTargetWhois:

    def test_registrar_extracted(self):
        result = parse_hackertarget_whois(HT_WHOIS_RAW)
        assert "MarkMonitor" in result.get("Registrar", "")

    def test_creation_date_extracted(self):
        result = parse_hackertarget_whois(HT_WHOIS_RAW)
        assert "1997" in result.get("Creation Date", "")

    def test_expiry_date_extracted(self):
        result = parse_hackertarget_whois(HT_WHOIS_RAW)
        assert "2028" in result.get("Expiry Date", "")

    def test_empty_whois(self):
        assert parse_hackertarget_whois("") == {}

    def test_no_duplicate_fields(self):
        # First occurrence wins
        raw    = "Registrar: First\nRegistrar: Second\n"
        result = parse_hackertarget_whois(raw)
        assert result["Registrar"] == "First"


# ══════════════════════════════════════════════════════════════════════════════
# TestOSINTScoutScan — integration tests with mocked HTTP
# ══════════════════════════════════════════════════════════════════════════════

def _make_scout(
    shodan_key="test-shodan",
    censys_id="test-id",
    censys_secret="test-secret",
    ht_key=None,
) -> OSINTScout:
    return OSINTScout(shodan_key, censys_id, censys_secret, ht_key,
                      cache_ttl=300)


class TestOSINTScoutScan:

    def test_unknown_target_returns_error(self):
        scout  = _make_scout()
        result = scout.scan("not-valid!!!")
        assert result["type"]  == "unknown"
        assert "error" in result

    def test_ip_scan_full_result(self):
        """Full IP scan with all three sources returning mocked data."""
        scout = _make_scout()

        # Patch the private query methods directly — no HTTP needed
        scout._query_shodan       = MagicMock(return_value=parse_shodan(SHODAN_HOST_CLEAN))
        scout._query_censys       = MagicMock(return_value=parse_censys(CENSYS_HOST))
        scout._query_hackertarget = MagicMock(return_value={
            "source":      "HackerTarget",
            "reverse_dns": "dns.google",
            "geoip":       {"Country": "US"},
            "dns_records": [],
            "subdomains":  [],
            "open_ports":  [{"port": 53, "proto": "tcp", "service": "domain"}],
            "whois_info":  {},
        })

        result = scout.scan("8.8.8.8")

        assert result["target"] == "8.8.8.8"
        assert result["type"]   == "ip"
        assert result["shodan"] is not None
        assert result["censys"] is not None
        assert result["hackertarget"] is not None
        assert "score" in result["risk"]
        assert "level" in result["risk"]
        assert isinstance(result["summary"]["unique_ports"], list)

    def test_source_failure_recorded_as_error(self):
        """A failing source should not crash the scan; error is captured."""
        scout = _make_scout()
        scout._query_shodan       = MagicMock(side_effect=Exception("API key invalid"))
        scout._query_censys       = MagicMock(return_value=parse_censys(CENSYS_HOST))
        scout._query_hackertarget = MagicMock(return_value={
            "source": "HackerTarget", "open_ports": [],
            "geoip": {}, "dns_records": [], "subdomains": [],
            "reverse_dns": "N/A", "whois_info": {},
        })

        result = scout.scan("8.8.8.8")
        assert "error" in result["shodan"]
        assert result["censys"] is not None   # other sources still work

    def test_cache_hit_skips_queries(self):
        """Second call for the same target must return cached data."""
        scout = _make_scout()
        scout._query_shodan       = MagicMock(return_value=parse_shodan(SHODAN_HOST_CLEAN))
        scout._query_censys       = MagicMock(return_value=parse_censys(CENSYS_HOST))
        scout._query_hackertarget = MagicMock(return_value={
            "source": "HackerTarget", "open_ports": [], "geoip": {},
            "dns_records": [], "subdomains": [], "reverse_dns": "N/A",
            "whois_info": {},
        })

        scout.scan("1.1.1.1")
        scout.scan("1.1.1.1")   # second call — should be a cache hit

        # Each query method should only have been called once
        assert scout._query_shodan.call_count       == 1
        assert scout._query_censys.call_count       == 1
        assert scout._query_hackertarget.call_count == 1

    def test_domain_resolves_before_querying(self):
        """Domain targets should be resolved to IP before Shodan/Censys calls."""
        scout = _make_scout()
        scout._resolve = MagicMock(return_value="8.8.8.8")
        scout._query_shodan       = MagicMock(return_value=parse_shodan(SHODAN_HOST_CLEAN))
        scout._query_censys       = MagicMock(return_value=parse_censys(CENSYS_HOST))
        scout._query_hackertarget = MagicMock(return_value={
            "source": "HackerTarget", "open_ports": [], "geoip": {},
            "dns_records": [], "subdomains": [], "reverse_dns": "N/A",
            "whois_info": {},
        })

        result = scout.scan("google.com")

        scout._resolve.assert_called_once_with("google.com")
        assert result["ip"] == "8.8.8.8"

    def test_risk_score_critical_for_dangerous_ports(self):
        """Scanning a host with RDP + Redis + 2 CVEs → CRITICAL risk."""
        scout = _make_scout()
        scout._query_shodan = MagicMock(
            return_value=parse_shodan(SHODAN_HOST_MALICIOUS)
        )
        scout._query_censys       = MagicMock(return_value=parse_censys({}))
        scout._query_hackertarget = MagicMock(return_value={
            "source": "HackerTarget", "open_ports": [], "geoip": {},
            "dns_records": [], "subdomains": [], "reverse_dns": "N/A",
            "whois_info": {},
        })

        result = scout.scan("185.220.101.45")

        assert result["risk"]["level"]      == "CRITICAL"
        assert result["risk"]["score"]      == 100   # capped
        assert 3389 in result["summary"]["critical_ports"]
        assert 6379 in result["summary"]["critical_ports"]
        assert "CVE-2021-44228" in result["summary"]["cves"]

    def test_no_api_keys_still_runs_hackertarget(self):
        """Without Shodan/Censys keys, HackerTarget alone should run."""
        scout = OSINTScout(shodan_key=None, censys_id=None,
                           censys_secret=None, cache_ttl=300)
        scout._query_hackertarget = MagicMock(return_value={
            "source":      "HackerTarget",
            "open_ports":  [{"port": 22, "proto": "tcp", "service": "ssh"}],
            "geoip":       {},
            "dns_records": [],
            "subdomains":  [],
            "reverse_dns": "N/A",
            "whois_info":  {},
        })

        result = scout.scan("1.2.3.4")

        assert result["shodan"]  is None
        assert result["censys"]  is None
        assert result["hackertarget"] is not None
        scout._query_hackertarget.assert_called_once()

    def test_duplicate_targets_deduplicated_via_cache(self):
        """scanning same target twice = 1 API hit each source, 2 results."""
        scout = _make_scout()
        scout._query_shodan       = MagicMock(return_value=parse_shodan(SHODAN_HOST_CLEAN))
        scout._query_censys       = MagicMock(return_value=parse_censys(CENSYS_HOST))
        scout._query_hackertarget = MagicMock(return_value={
            "source": "HackerTarget", "open_ports": [], "geoip": {},
            "dns_records": [], "subdomains": [], "reverse_dns": "N/A",
            "whois_info": {},
        })

        r1 = scout.scan("4.4.4.4")
        r2 = scout.scan("4.4.4.4")  # cache hit

        assert r1 is r2   # identical dict objects from cache
        assert scout._query_shodan.call_count == 1


# ══════════════════════════════════════════════════════════════════════════════
# Entry point
# ══════════════════════════════════════════════════════════════════════════════

if __name__ == "__main__":
    pytest.main([__file__, "-v"])
