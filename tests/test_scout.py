"""
OSINT Scout — Test Suite
========================
Tests cover: classify, calc_risk (incl. credential risk + CVSS weighting),
RateLimiter, ScanCache, retry decorator, parse_shodan, parse_censys,
parse_hackedlist, OSINTScout.scan() / _resolve() with mocked HTTP.

Run:
    pip install pytest
    pytest tests/ -v
"""

import sys
import time
import threading
from datetime import datetime, timedelta
from pathlib import Path
from unittest.mock import MagicMock

import pytest
import requests

# ── ensure scout is importable from parent directory ──────────────────────────
sys.path.insert(0, str(Path(__file__).parent.parent))

from scout import (
    classify,
    calc_risk,
    retry,
    RateLimiter,
    ScanCache,
    parse_shodan,
    parse_censys,
    parse_hackedlist,
    OSINTScout,
    HIGH_RISK_PORTS,
    CRITICAL_PORTS,
    CRED_EXPOSURE_THRESHOLDS,
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

# HackedList fixtures
HL_DOMAIN_CLEAN = {
    "domain":        "safe-domain.com",
    "total":         0,
    "sources":       [],
    "latest_breach": None,
    "first_seen":    None,
}

HL_DOMAIN_LOW = {
    "domain":        "small-org.com",
    "total":         42,
    "sources":       ["RedLine Stealer"],
    "latest_breach": "2024-01-15",
    "first_seen":    "2023-06-01",
}

HL_DOMAIN_MEDIUM = {
    "domain":        "example.com",
    "total":         523,
    "sources":       ["RedLine Stealer", "Vidar Stealer"],
    "latest_breach": "2024-06-01",
    "first_seen":    "2022-03-10",
}

HL_DOMAIN_CRITICAL = {
    "domain":        "bigcorp.com",
    "total":         15_000,
    "sources":       ["RedLine Stealer", "Vidar", "Raccoon", "Aurora"],
    "latest_breach": "2024-11-01",
    "first_seen":    "2021-01-01",
}

HL_DOMAIN_ALT_FIELD = {
    # Some API versions use "count" instead of "total"
    "domain":     "alt.com",
    "count":      200,
    "infostealers": "Vidar, Aurora",   # comma-separated string variant
    "last_seen":  "2024-09-01",
}

# Minimal HackedList mock return value for OSINTScout scan tests
_HL_MOCK_CLEAN = {
    "source":            "HackedList",
    "domain":            "example.com",
    "total_credentials": 0,
    "sources":           [],
    "latest_breach":     "N/A",
    "first_seen":        "N/A",
    "exposure_level":    "NONE",
}

_HL_MOCK_EXPOSED = {
    "source":            "HackedList",
    "domain":            "example.com",
    "total_credentials": 1_500,
    "sources":           ["RedLine Stealer"],
    "latest_breach":     "2024-10-01",
    "first_seen":        "2022-01-01",
    "exposure_level":    "HIGH",
}


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
        risk = calc_risk([], {})
        assert risk["score"] == 0
        assert risk["level"] == "INFO"

    def test_single_low_port(self):
        # Port 8888 is not in HIGH_RISK or CRITICAL → +3
        risk = calc_risk([8888], {})
        assert risk["score"] == 3
        assert risk["level"] == "INFO"

    def test_single_high_risk_port(self):
        # SSH (22) → +15
        risk = calc_risk([22], {})
        assert risk["score"] == 15
        assert risk["level"] == "LOW"

    def test_single_critical_port(self):
        # RDP (3389) → +30 → LOW range (10-34)
        risk = calc_risk([3389], {})
        assert risk["score"] == 30
        assert risk["level"] == "LOW"

    def test_two_critical_ports(self):
        # 3389 + 445 → 60
        risk = calc_risk([3389, 445], {})
        assert risk["score"] == 60
        assert risk["level"] == "HIGH"

    def test_three_critical_ports(self):
        # 3389 + 445 + 6379 → 90 (capped at 100)
        risk = calc_risk([3389, 445, 6379], {})
        assert risk["score"] == 90
        assert risk["level"] == "CRITICAL"

    def test_cve_only(self):
        # CVSS 10.0 → round(min(25, 25)) = 25
        # CVSS  7.5 → round(min(18.75, 25)) = 19
        # total cve_score = 44, comp = 44 → MEDIUM
        risk = calc_risk([], {"CVE-2021-44228": 10.0, "CVE-2022-0778": 7.5})
        assert risk["score"] == 44
        assert risk["level"] == "MEDIUM"

    def test_mixed_critical_and_cves(self):
        # 3389(30) + CVSS 10.0(25) + CVSS 7.5(19) = 74 → HIGH
        risk = calc_risk([3389], {"CVE-2021-44228": 10.0, "CVE-2022-0778": 7.5})
        assert risk["score"] == 74
        assert risk["level"] == "HIGH"

    def test_score_capped_at_100(self):
        # Many critical ports + many CVEs → must never exceed 100
        ports = list(CRITICAL_PORTS)
        cves  = {f"CVE-2024-{i:04d}": 9.0 for i in range(10)}
        risk  = calc_risk(ports, cves)
        assert risk["score"] == 100

    def test_http_https_not_counted_as_high_risk(self):
        # 80 and 443 are NOT in HIGH_RISK_PORTS → only +3 each
        risk = calc_risk([80, 443], {})
        assert risk["score"] == 6
        assert risk["level"] == "INFO"

    def test_level_boundaries(self):
        # Exact boundary checks
        assert calc_risk([], {})["level"]   == "INFO"   # 0
        assert calc_risk([22], {})["level"] == "LOW"    # 15
        # MEDIUM boundary: score 36 (15 + 7×3 = 36)
        risk = calc_risk([22, 100, 101, 102, 103, 104, 105, 106], {})
        assert risk["level"] == "MEDIUM"

    # ── Credential exposure (cred_count parameter) ─────────────────────────────

    def test_zero_credentials_no_extra_risk(self):
        # Default cred_count=0 has no effect
        risk = calc_risk([], {}, cred_count=0)
        assert risk["score"] == 0
        assert risk["level"] == "INFO"

    def test_few_credentials_adds_low_risk(self):
        # ce_score = 25, comp = 0 + 25//2 = 12 → LOW
        risk = calc_risk([], {}, cred_count=50)
        assert risk["score"] == 12
        assert risk["level"] == "LOW"

    def test_medium_credential_exposure(self):
        # ce_score = 50, comp = 0 + 50//2 = 25 → LOW
        risk = calc_risk([], {}, cred_count=500)
        assert risk["score"] == 25
        assert risk["level"] == "LOW"

    def test_high_credential_exposure(self):
        # ce_score = 75, comp = 0 + 75//2 = 37 → MEDIUM
        risk = calc_risk([], {}, cred_count=5_000)
        assert risk["score"] == 37
        assert risk["level"] == "MEDIUM"

    def test_critical_credential_exposure(self):
        # ce_score = 100, comp = 0 + 100//2 = 50 → MEDIUM
        risk = calc_risk([], {}, cred_count=15_000)
        assert risk["score"] == 50
        assert risk["level"] == "MEDIUM"

    def test_credentials_combined_with_ports_boosts_level(self):
        # SSH(as=15) + 1000 creds(ce=75): comp = 15 + 75//2 = 15+37 = 52 → MEDIUM
        risk = calc_risk([22], {}, cred_count=1_000)
        assert risk["score"] == 52
        assert risk["level"] == "MEDIUM"

    def test_cred_count_cannot_exceed_100(self):
        # Massive credentials + dangerous ports must stay capped
        ports = list(CRITICAL_PORTS)
        risk  = calc_risk(ports, {}, cred_count=50_000)
        assert risk["score"] == 100

    def test_cvss_weighting_high_vs_low_cve(self):
        """High CVSS CVE must contribute more risk than low CVSS CVE."""
        risk_high = calc_risk([], {"CVE-A": 10.0})
        risk_low  = calc_risk([], {"CVE-B": 3.0})
        assert risk_high["attack_surface_score"] > risk_low["attack_surface_score"]
        assert risk_high["attack_surface_score"] == 25  # round(min(25.0, 25)) = 25
        assert risk_low["attack_surface_score"]  == 8   # round(min(7.5, 25))  = 8

    def test_risk_dict_has_all_keys(self):
        """calc_risk must return a dict with all expected breakdown keys."""
        risk = calc_risk([22], {"CVE-A": 5.0}, cred_count=100)
        for key in (
            "score", "level",
            "attack_surface_score", "attack_surface_level",
            "credential_score",     "credential_level",
        ):
            assert key in risk

    def test_attack_surface_and_credential_independent(self):
        """attack_surface_score should be unaffected by credential count."""
        risk_no_creds   = calc_risk([22], {"CVE-A": 8.0}, cred_count=0)
        risk_with_creds = calc_risk([22], {"CVE-A": 8.0}, cred_count=5_000)
        assert risk_no_creds["attack_surface_score"] == risk_with_creds["attack_surface_score"]
        assert risk_with_creds["score"] > risk_no_creds["score"]


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
# TestRetry
# ══════════════════════════════════════════════════════════════════════════════

class TestRetry:

    def test_retry_on_connection_error(self):
        """ConnectionError should be retried up to max_attempts."""
        call_count = 0

        @retry(max_attempts=3, base_delay=0.01)
        def flaky():
            nonlocal call_count
            call_count += 1
            if call_count < 3:
                raise requests.ConnectionError("Connection refused")
            return "success"

        assert flaky() == "success"
        assert call_count == 3

    def test_retry_on_503(self):
        """HTTP 503 should be retried; call count equals max_attempts."""
        call_count = 0

        @retry(max_attempts=2, base_delay=0.01)
        def always_503():
            nonlocal call_count
            call_count += 1
            mock_resp = MagicMock()
            mock_resp.status_code = 503
            mock_resp.headers     = {}
            raise requests.HTTPError(response=mock_resp)

        with pytest.raises(requests.HTTPError):
            always_503()
        assert call_count == 2

    def test_no_retry_on_401(self):
        """HTTP 401 (auth failure) must NOT be retried — re-raised immediately."""
        call_count = 0

        @retry(max_attempts=3, base_delay=0.01)
        def auth_fail():
            nonlocal call_count
            call_count += 1
            mock_resp = MagicMock()
            mock_resp.status_code = 401
            mock_resp.headers     = {}
            raise requests.HTTPError(response=mock_resp)

        with pytest.raises(requests.HTTPError):
            auth_fail()
        assert call_count == 1  # no retry for 401


# ══════════════════════════════════════════════════════════════════════════════
# TestParseShodan
# ══════════════════════════════════════════════════════════════════════════════

class TestParseShodan:

    def test_clean_host_ports(self):
        result = parse_shodan(SHODAN_HOST_CLEAN)
        assert result["ports"] == [53, 443]

    def test_clean_host_no_cves(self):
        result = parse_shodan(SHODAN_HOST_CLEAN)
        assert result["cves"] == {}

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

    def test_malicious_host_cve_cvss_values(self):
        """CVEs must be a Dict[str, float] with correct CVSS scores."""
        result = parse_shodan(SHODAN_HOST_MALICIOUS)
        assert result["cves"]["CVE-2021-44228"] == 10.0
        assert result["cves"]["CVE-2022-0778"]  == 7.5

    def test_malicious_host_ports(self):
        result = parse_shodan(SHODAN_HOST_MALICIOUS)
        assert 3389 in result["ports"]
        assert 6379 in result["ports"]

    def test_services_extracted(self):
        result = parse_shodan(SHODAN_HOST_CLEAN)
        assert len(result["services"]) >= 1
        assert any("nginx" in svc for svc in result["services"])

    def test_missing_fields_use_defaults(self):
        result = parse_shodan({})
        assert result["org"]     == "N/A"
        assert result["country"] == "N/A"
        assert result["os"]      == "N/A"
        assert result["ports"]   == []
        assert result["cves"]    == {}

    def test_ports_sorted(self):
        raw        = dict(SHODAN_HOST_CLEAN)
        raw["ports"] = [443, 22, 80, 8080]
        result     = parse_shodan(raw)
        assert result["ports"] == sorted(result["ports"])

    def test_source_field(self):
        assert parse_shodan({})["source"] == "Shodan"

    def test_cve_default_cvss_when_missing(self):
        """CVEs without a cvss field should default to 5.0."""
        raw = {"vulns": {"CVE-1234-5678": {}}}
        result = parse_shodan(raw)
        assert result["cves"]["CVE-1234-5678"] == 5.0


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
# TestParseHackedList
# ══════════════════════════════════════════════════════════════════════════════

class TestParseHackedList:

    def test_source_field(self):
        assert parse_hackedlist({})["source"] == "HackedList"

    def test_clean_domain_zero_credentials(self):
        result = parse_hackedlist(HL_DOMAIN_CLEAN)
        assert result["total_credentials"] == 0
        assert result["exposure_level"]    == "NONE"

    def test_low_exposure(self):
        result = parse_hackedlist(HL_DOMAIN_LOW)
        assert result["total_credentials"] == 42
        assert result["exposure_level"]    == "LOW"

    def test_medium_exposure(self):
        result = parse_hackedlist(HL_DOMAIN_MEDIUM)
        assert result["total_credentials"] == 523
        assert result["exposure_level"]    == "MEDIUM"

    def test_critical_exposure(self):
        result = parse_hackedlist(HL_DOMAIN_CRITICAL)
        assert result["total_credentials"] == 15_000
        assert result["exposure_level"]    == "CRITICAL"

    def test_sources_extracted(self):
        result = parse_hackedlist(HL_DOMAIN_MEDIUM)
        assert "RedLine Stealer" in result["sources"]
        assert "Vidar Stealer"   in result["sources"]

    def test_breach_dates_extracted(self):
        result = parse_hackedlist(HL_DOMAIN_MEDIUM)
        assert result["latest_breach"] == "2024-06-01"
        assert result["first_seen"]    == "2022-03-10"

    def test_empty_response_defaults(self):
        result = parse_hackedlist({})
        assert result["total_credentials"] == 0
        assert result["sources"]           == []
        assert result["latest_breach"]     == "N/A"
        assert result["first_seen"]        == "N/A"
        assert result["exposure_level"]    == "NONE"

    def test_alt_field_names_count(self):
        """API may return 'count' instead of 'total' — both must work."""
        result = parse_hackedlist(HL_DOMAIN_ALT_FIELD)
        assert result["total_credentials"] == 200

    def test_alt_field_infostealers_as_string(self):
        """'infostealers' as a comma-separated string must be split."""
        result = parse_hackedlist(HL_DOMAIN_ALT_FIELD)
        assert "Vidar" in result["sources"]
        assert "Aurora" in result["sources"]

    def test_alt_field_last_seen(self):
        """'last_seen' should fall back to 'latest_breach'."""
        result = parse_hackedlist(HL_DOMAIN_ALT_FIELD)
        assert result["latest_breach"] == "2024-09-01"

    def test_none_breach_dates_normalised(self):
        """None breach dates should become 'N/A'."""
        result = parse_hackedlist(HL_DOMAIN_CLEAN)
        assert result["latest_breach"] == "N/A"
        assert result["first_seen"]    == "N/A"

    def test_sources_capped_at_ten(self):
        """At most 10 sources should be returned."""
        raw = {
            "domain":  "example.com",
            "total":   999,
            "sources": [f"Stealer-{i}" for i in range(20)],
        }
        result = parse_hackedlist(raw)
        assert len(result["sources"]) <= 10

    def test_high_exposure_level(self):
        raw = {"domain": "corp.com", "total": 1_500}
        result = parse_hackedlist(raw)
        assert result["exposure_level"] == "HIGH"

    def test_non_numeric_total_defaults_to_zero(self):
        """Non-numeric 'total' field must not crash — defaults to 0."""
        raw = {"domain": "broken.com", "total": "N/A"}
        result = parse_hackedlist(raw)
        assert result["total_credentials"] == 0
        assert result["exposure_level"]    == "NONE"


# ══════════════════════════════════════════════════════════════════════════════
# TestOSINTScoutScan — integration tests with mocked HTTP
# ══════════════════════════════════════════════════════════════════════════════

def _make_scout(
    shodan_key="test-shodan",
    censys_id="test-id",
    censys_secret="test-secret",
    hackedlist_key="test-hl-key",
) -> OSINTScout:
    return OSINTScout(
        shodan_key, censys_id, censys_secret, hackedlist_key,
        cache_ttl=300,
    )


class TestOSINTScoutScan:

    def test_unknown_target_returns_error(self):
        scout  = _make_scout()
        result = scout.scan("not-valid!!!")
        assert result["type"]  == "unknown"
        assert "error" in result

    def test_ip_scan_shodan_and_censys_queried(self):
        """Full IP scan: Shodan + Censys run; HackedList is skipped (IP target)."""
        scout = _make_scout()
        scout._query_shodan     = MagicMock(return_value=parse_shodan(SHODAN_HOST_CLEAN))
        scout._query_censys     = MagicMock(return_value=parse_censys(CENSYS_HOST))
        scout._query_hackedlist = MagicMock()

        result = scout.scan("8.8.8.8")

        assert result["target"] == "8.8.8.8"
        assert result["type"]   == "ip"
        assert result["shodan"] is not None
        assert result["censys"] is not None
        assert result["hackedlist"] is None        # HackedList skipped for IPs
        scout._query_hackedlist.assert_not_called()
        assert "score" in result["risk"]
        assert "level" in result["risk"]
        assert isinstance(result["summary"]["unique_ports"], list)

    def test_hackedlist_queried_for_domain_target(self):
        """HackedList should be queried when target is a domain."""
        scout = _make_scout()
        scout._resolve          = MagicMock(return_value="8.8.8.8")
        scout._query_shodan     = MagicMock(return_value=parse_shodan(SHODAN_HOST_CLEAN))
        scout._query_censys     = MagicMock(return_value=parse_censys(CENSYS_HOST))
        scout._query_hackedlist = MagicMock(return_value=_HL_MOCK_CLEAN)

        result = scout.scan("google.com")

        scout._query_hackedlist.assert_called_once_with("google.com")
        assert result["hackedlist"] is not None
        assert result["hackedlist"]["source"] == "HackedList"

    def test_hackedlist_skipped_for_ip_target(self):
        """HackedList must NOT be called when scanning a plain IP address."""
        scout = _make_scout()
        scout._query_shodan     = MagicMock(return_value=parse_shodan(SHODAN_HOST_CLEAN))
        scout._query_censys     = MagicMock(return_value=parse_censys(CENSYS_HOST))
        scout._query_hackedlist = MagicMock()

        result = scout.scan("1.2.3.4")

        scout._query_hackedlist.assert_not_called()
        assert result["hackedlist"] is None

    def test_source_failure_recorded_as_error(self):
        """A failing source should not crash the scan; error is captured."""
        scout = _make_scout()
        scout._query_shodan     = MagicMock(side_effect=Exception("API key invalid"))
        scout._query_censys     = MagicMock(return_value=parse_censys(CENSYS_HOST))
        scout._query_hackedlist = MagicMock()

        result = scout.scan("8.8.8.8")

        assert "error" in result["shodan"]
        assert result["censys"] is not None   # other sources still work

    def test_cache_hit_skips_queries(self):
        """Second call for the same target must return cached data."""
        scout = _make_scout()
        scout._query_shodan     = MagicMock(return_value=parse_shodan(SHODAN_HOST_CLEAN))
        scout._query_censys     = MagicMock(return_value=parse_censys(CENSYS_HOST))
        scout._query_hackedlist = MagicMock(return_value=_HL_MOCK_CLEAN)

        scout.scan("example.com")
        scout.scan("example.com")   # second call — should be a cache hit

        # Each query method should only have been called once
        assert scout._query_shodan.call_count     == 1
        assert scout._query_censys.call_count     == 1
        assert scout._query_hackedlist.call_count == 1

    def test_domain_resolves_before_querying(self):
        """Domain targets should be resolved to IP before Shodan/Censys calls."""
        scout = _make_scout()
        scout._resolve          = MagicMock(return_value="8.8.8.8")
        scout._query_shodan     = MagicMock(return_value=parse_shodan(SHODAN_HOST_CLEAN))
        scout._query_censys     = MagicMock(return_value=parse_censys(CENSYS_HOST))
        scout._query_hackedlist = MagicMock(return_value=_HL_MOCK_CLEAN)

        result = scout.scan("google.com")

        scout._resolve.assert_called_once_with("google.com")
        assert result["ip"] == "8.8.8.8"

    def test_risk_score_critical_for_dangerous_ports(self):
        """Scanning a host with RDP + Redis + 2 CVEs (CVSS 10 + 7.5) → CRITICAL."""
        scout = _make_scout()
        scout._query_shodan     = MagicMock(
            return_value=parse_shodan(SHODAN_HOST_MALICIOUS)
        )
        scout._query_censys     = MagicMock(return_value=parse_censys({}))
        scout._query_hackedlist = MagicMock()

        result = scout.scan("185.220.101.45")

        # port_score = 3(443) + 30(3389) + 30(6379) = 63
        # cve_score  = 25(CVSS10) + 19(CVSS7.5) = 44
        # as_score   = min(107, 100) = 100 → capped
        assert result["risk"]["level"]      == "CRITICAL"
        assert result["risk"]["score"]      == 100
        assert 3389 in result["summary"]["critical_ports"]
        assert 6379 in result["summary"]["critical_ports"]
        assert "CVE-2021-44228" in result["summary"]["cves"]

    def test_credential_exposure_boosts_risk_score(self):
        """High credential count from HackedList should raise the risk score."""
        scout = _make_scout()
        scout._resolve          = MagicMock(return_value="93.184.216.34")
        scout._query_shodan     = MagicMock(return_value=parse_shodan({}))
        scout._query_censys     = MagicMock(return_value=parse_censys({}))
        scout._query_hackedlist = MagicMock(return_value=_HL_MOCK_EXPOSED)

        # _HL_MOCK_EXPOSED: total_credentials=1500 → ce_score=75, comp=0+37=37
        result = scout.scan("example.com")

        assert result["risk"]["score"] == 37
        assert result["summary"]["credential_exposure"] == 1_500

    def test_no_api_keys_scan_completes_without_crash(self):
        """Without any API keys, scan completes and returns a valid record."""
        scout = OSINTScout(
            shodan_key=None, censys_id=None,
            censys_secret=None, hackedlist_key=None,
            cache_ttl=300,
        )
        result = scout.scan("1.2.3.4")

        assert result["shodan"]     is None
        assert result["censys"]     is None
        assert result["hackedlist"] is None
        assert "score" in result["risk"]
        assert result["risk"]["score"] == 0

    def test_duplicate_targets_deduplicated_via_cache(self):
        """Scanning same target twice = 1 API hit per source, 2 results."""
        scout = _make_scout()
        scout._resolve          = MagicMock(return_value="4.4.4.4")
        scout._query_shodan     = MagicMock(return_value=parse_shodan(SHODAN_HOST_CLEAN))
        scout._query_censys     = MagicMock(return_value=parse_censys(CENSYS_HOST))
        scout._query_hackedlist = MagicMock(return_value=_HL_MOCK_CLEAN)

        r1 = scout.scan("domain-a.com")
        r2 = scout.scan("domain-a.com")   # cache hit

        assert r1 is r2   # identical dict objects from cache
        assert scout._query_shodan.call_count     == 1
        assert scout._query_hackedlist.call_count == 1

    def test_summary_contains_credential_exposure_field(self):
        """summary dict must always include 'credential_exposure' key."""
        scout = _make_scout()
        scout._query_shodan     = MagicMock(return_value=parse_shodan(SHODAN_HOST_CLEAN))
        scout._query_censys     = MagicMock(return_value=parse_censys(CENSYS_HOST))
        scout._query_hackedlist = MagicMock()

        result = scout.scan("8.8.8.8")

        assert "credential_exposure" in result["summary"]
        assert result["summary"]["credential_exposure"] == 0

    def test_risk_dict_has_two_dimensional_breakdown(self):
        """result['risk'] must include both attack_surface and credential fields."""
        scout = _make_scout()
        scout._query_shodan     = MagicMock(return_value=parse_shodan(SHODAN_HOST_CLEAN))
        scout._query_censys     = MagicMock(return_value=parse_censys(CENSYS_HOST))
        scout._query_hackedlist = MagicMock()

        result = scout.scan("8.8.8.8")

        risk = result["risk"]
        for key in ("score", "level", "attack_surface_score", "attack_surface_level",
                    "credential_score", "credential_level"):
            assert key in risk


# ══════════════════════════════════════════════════════════════════════════════
# TestResolve
# ══════════════════════════════════════════════════════════════════════════════

class TestResolve:

    def test_resolve_uses_system_dns_when_no_shodan(self):
        """Without Shodan client, _resolve must fall back to socket.gethostbyname."""
        from unittest.mock import patch
        scout = _make_scout(shodan_key=None)
        with patch("scout.socket.gethostbyname", return_value="93.184.216.34") as mock_dns:
            result = scout._resolve("example.com")
        mock_dns.assert_called_once_with("example.com")
        assert result == "93.184.216.34"

    def test_resolve_uses_shodan_dns_if_available(self):
        """With Shodan available and responding, Shodan DNS takes priority."""
        scout = _make_scout()
        scout.shodan.resolve = MagicMock(return_value="8.8.8.8")
        assert scout._resolve("google.com") == "8.8.8.8"

    def test_resolve_falls_back_to_system_if_shodan_fails(self):
        """If Shodan DNS raises, system resolver must be used as fallback."""
        from unittest.mock import patch
        scout = _make_scout()
        scout.shodan.resolve = MagicMock(side_effect=Exception("Shodan API error"))
        with patch("scout.socket.gethostbyname", return_value="1.2.3.4"):
            result = scout._resolve("example.com")
        assert result == "1.2.3.4"


# ══════════════════════════════════════════════════════════════════════════════
# Entry point
# ══════════════════════════════════════════════════════════════════════════════

if __name__ == "__main__":
    pytest.main([__file__, "-v"])
