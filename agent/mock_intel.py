"""
Realistic Mock Threat Intelligence Responses

These mocks mirror the exact JSON structure returned by the real APIs.
Used when no API keys are configured so the pipeline still produces
meaningful results for development, demos, and testing.

Each mock is seeded by the input (IP, URL, hash) so repeated queries
return consistent data.
"""

import hashlib
import random
from typing import Dict, Any, Optional


def _seed_from(value: str) -> random.Random:
    """Deterministic RNG seeded by the input value."""
    h = int(hashlib.md5(value.encode()).hexdigest()[:8], 16)
    return random.Random(h)


# ---------------------------------------------------------------------------
# VirusTotal v2 mock
# ---------------------------------------------------------------------------

def mock_virustotal_ip(ip: str) -> Dict[str, Any]:
    """Mock VirusTotal /ip-address/report — mirrors real VT v2 response."""
    rng = _seed_from(f"vt_ip_{ip}")

    num_detected_urls = rng.randint(0, 25)
    num_detected_samples = rng.randint(0, 15)
    num_undetected = rng.randint(0, 50)

    detected_urls = [
        {
            "url": f"http://{ip}/{rng.choice(['malware', 'phish', 'exploit', 'c2', 'drop'])}/{i}.html",
            "positives": rng.randint(1, 72),
            "total": 72,
            "scan_date": f"2024-{rng.randint(1,12):02d}-{rng.randint(1,28):02d} {rng.randint(0,23):02d}:{rng.randint(0,59):02d}:{rng.randint(0,59):02d}"
        }
        for i in range(num_detected_urls)
    ]

    detected_samples = [
        {
            "sha256": hashlib.sha256(f"{ip}_sample_{i}".encode()).hexdigest(),
            "positives": rng.randint(1, 68),
            "total": 68,
            "date": f"2024-{rng.randint(1,12):02d}-{rng.randint(1,28):02d}"
        }
        for i in range(num_detected_samples)
    ]

    return {
        "response_code": 1,
        "verbose_msg": "IP address found in dataset",
        "asn": rng.randint(1000, 65000),
        "as_owner": rng.choice([
            "DIGITALOCEAN-ASN", "OVH SAS", "AMAZON-AES", "HETZNER-AS",
            "CLOUDFLARENET", "GOOGLE", "MICROSOFT-CORP-MSN-AS-BLOCK"
        ]),
        "country": rng.choice(["US", "RU", "CN", "DE", "NL", "RO", "UA", "BR"]),
        "detected_urls": detected_urls,
        "detected_communicating_samples": detected_samples,
        "detected_downloaded_samples": detected_samples[:num_detected_samples // 2],
        "undetected_urls": [{"url": f"http://{ip}/page{i}"} for i in range(num_undetected)],
        "resolutions": [
            {"hostname": f"host{i}.example.com", "last_resolved": "2024-01-15"}
            for i in range(rng.randint(0, 8))
        ],
    }


def mock_virustotal_url(url: str) -> Dict[str, Any]:
    """Mock VirusTotal /url/report."""
    rng = _seed_from(f"vt_url_{url}")
    positives = rng.randint(0, 45)
    total = 72

    return {
        "response_code": 1,
        "verbose_msg": "Scan finished",
        "scan_id": hashlib.sha256(url.encode()).hexdigest()[:32],
        "resource": url,
        "url": url,
        "scan_date": "2024-06-15 12:30:00",
        "positives": positives,
        "total": total,
        "scans": {
            engine: {
                "detected": rng.random() < (positives / total),
                "result": rng.choice(["malicious site", "phishing", "malware", "clean site"]),
            }
            for engine in ["Google Safebrowsing", "Kaspersky", "Fortinet", "Sophos",
                           "BitDefender", "ESET", "Avira", "Symantec", "McAfee"]
        },
        "filescan_id": None,
    }


def mock_virustotal_file(file_hash: str) -> Dict[str, Any]:
    """Mock VirusTotal /file/report."""
    rng = _seed_from(f"vt_file_{file_hash}")
    positives = rng.randint(0, 60)
    total = 68

    return {
        "response_code": 1,
        "verbose_msg": "Scan finished",
        "resource": file_hash,
        "sha256": hashlib.sha256(file_hash.encode()).hexdigest(),
        "md5": file_hash if len(file_hash) == 32 else hashlib.md5(file_hash.encode()).hexdigest(),
        "scan_date": "2024-06-15 08:15:00",
        "positives": positives,
        "total": total,
        "scans": {
            engine: {
                "detected": rng.random() < (positives / total),
                "result": rng.choice([
                    "Trojan.GenericKD", "W32/Emotet.A", "Malware.Generic",
                    "Heur.Trojan.Generic", "", "clean"
                ]),
                "version": f"{rng.randint(1,30)}.{rng.randint(0,9)}.{rng.randint(0,9)}",
                "update": "20240615"
            }
            for engine in ["Kaspersky", "BitDefender", "ESET-NOD32", "McAfee",
                           "Symantec", "Avast", "AVG", "Sophos", "Fortinet",
                           "TrendMicro", "ClamAV", "Malwarebytes"]
        },
        "permalink": f"https://www.virustotal.com/gui/file/{file_hash}",
    }


# ---------------------------------------------------------------------------
# AbuseIPDB v2 mock
# ---------------------------------------------------------------------------

def mock_abuseipdb_check(ip: str) -> Dict[str, Any]:
    """Mock AbuseIPDB /api/v2/check — mirrors real response structure."""
    rng = _seed_from(f"abuse_{ip}")

    abuse_confidence = rng.randint(0, 100)
    total_reports = rng.randint(0, 500) if abuse_confidence > 20 else rng.randint(0, 5)

    categories = []
    if abuse_confidence > 30:
        category_pool = [
            (3, "Fraud Orders"), (4, "DDoS Attack"), (5, "FTP Brute-Force"),
            (9, "Open Proxy"), (10, "Web Spam"), (11, "Email Spam"),
            (14, "Port Scan"), (15, "Hacking"), (18, "Brute-Force"),
            (19, "Bad Web Bot"), (20, "Exploited Host"), (21, "Web App Attack"),
            (22, "SSH"), (23, "IoT Targeted"),
        ]
        num_cats = rng.randint(1, min(5, len(category_pool)))
        chosen = rng.sample(category_pool, num_cats)
        categories = [c[0] for c in chosen]

    reports = [
        {
            "reportedAt": f"2024-{rng.randint(1,12):02d}-{rng.randint(1,28):02d}T{rng.randint(0,23):02d}:{rng.randint(0,59):02d}:00+00:00",
            "comment": rng.choice([
                "Brute force login attempts",
                "Port scanning detected",
                "SSH brute force",
                "Web application attack",
                "Spam source",
                "Credential stuffing",
                "DDoS participation",
            ]),
            "categories": rng.sample(categories, min(len(categories), 2)) if categories else [15],
            "reporterId": rng.randint(1000, 99999),
            "reporterCountryCode": rng.choice(["US", "DE", "GB", "FR", "JP"]),
            "reporterCountryName": "N/A",
        }
        for _ in range(min(total_reports, 10))
    ]

    return {
        "data": {
            "ipAddress": ip,
            "isPublic": True,
            "ipVersion": 4,
            "isWhitelisted": False,
            "abuseConfidencePercentage": abuse_confidence,
            "countryCode": rng.choice(["US", "RU", "CN", "DE", "NL", "RO", "UA", "KR"]),
            "countryName": "N/A",
            "usageType": rng.choice([
                "Data Center/Web Hosting/Transit",
                "Fixed Line ISP",
                "Content Delivery Network",
                "Commercial",
                "University/College/School",
            ]),
            "isp": rng.choice([
                "DigitalOcean LLC", "OVH SAS", "Hetzner Online GmbH",
                "Amazon Technologies Inc.", "Google LLC",
                "Cloudflare Inc.", "Microsoft Corporation"
            ]),
            "domain": f"host-{ip.replace('.', '-')}.example.com",
            "hostnames": [f"server-{ip.replace('.', '-')}.provider.net"],
            "totalReports": total_reports,
            "numDistinctUsers": rng.randint(1, min(total_reports + 1, 200)),
            "lastReportedAt": "2024-06-15T10:30:00+00:00" if total_reports > 0 else None,
            "reports": reports,
        }
    }


# ---------------------------------------------------------------------------
# Shodan mock
# ---------------------------------------------------------------------------

def mock_shodan_host(ip: str) -> Dict[str, Any]:
    """Mock Shodan /shodan/host/{ip} — mirrors real response structure."""
    rng = _seed_from(f"shodan_{ip}")

    common_ports = [21, 22, 23, 25, 53, 80, 110, 143, 443, 445, 993, 995,
                    3306, 3389, 5432, 5900, 6379, 8080, 8443, 8888, 9200, 27017]
    num_ports = rng.randint(1, 15)
    ports = sorted(rng.sample(common_ports, min(num_ports, len(common_ports))))

    vulns = []
    if rng.random() > 0.4:
        vuln_pool = [
            "CVE-2021-44228", "CVE-2023-44487", "CVE-2024-3094",
            "CVE-2021-26855", "CVE-2020-1472", "CVE-2019-0708",
            "CVE-2023-23397", "CVE-2022-26134", "CVE-2021-34473",
            "CVE-2023-4966", "CVE-2024-21887",
        ]
        vulns = rng.sample(vuln_pool, rng.randint(1, min(5, len(vuln_pool))))

    services = []
    for port in ports:
        service_map = {
            21: "ftp", 22: "ssh", 23: "telnet", 25: "smtp", 53: "dns",
            80: "http", 110: "pop3", 143: "imap", 443: "https", 445: "smb",
            3306: "mysql", 3389: "rdp", 5432: "postgresql", 6379: "redis",
            8080: "http-proxy", 8443: "https-alt", 9200: "elasticsearch",
            27017: "mongodb",
        }
        product_map = {
            22: "OpenSSH", 80: "nginx", 443: "nginx", 8080: "Apache Tomcat",
            3306: "MySQL", 5432: "PostgreSQL", 6379: "Redis",
            9200: "Elasticsearch", 27017: "MongoDB",
        }
        services.append({
            "port": port,
            "transport": "tcp",
            "product": product_map.get(port, ""),
            "version": f"{rng.randint(1,15)}.{rng.randint(0,9)}",
            "_shodan": {"module": service_map.get(port, "unknown")},
            "data": f"Service banner for port {port}",
        })

    return {
        "ip_str": ip,
        "ip": int.from_bytes([int(x) for x in ip.split(".")], byteorder="big"),
        "asn": f"AS{rng.randint(1000, 65000)}",
        "org": rng.choice([
            "DigitalOcean LLC", "OVH SAS", "Hetzner Online GmbH",
            "Amazon.com Inc.", "Google LLC", "Microsoft Corporation",
            "Cloudflare Inc.", "Linode LLC",
        ]),
        "isp": rng.choice(["DigitalOcean LLC", "OVH SAS", "Amazon.com Inc."]),
        "os": rng.choice(["Linux", "Windows Server 2019", "Ubuntu", None]),
        "ports": ports,
        "vulns": vulns,
        "hostnames": [f"server.{rng.choice(['example.com', 'hosting.net', 'cloud.io'])}"],
        "city": rng.choice(["Amsterdam", "Frankfurt", "New York", "London", "Singapore"]),
        "country_code": rng.choice(["US", "DE", "NL", "SG", "GB"]),
        "country_name": "N/A",
        "last_update": "2024-06-15T12:00:00.000000",
        "data": services,
        "tags": ["cloud"] if rng.random() > 0.5 else [],
    }


# ---------------------------------------------------------------------------
# Registry: pick the right mock by tool + query type
# ---------------------------------------------------------------------------

MOCK_REGISTRY = {
    ("virustotal", "ip"):   mock_virustotal_ip,
    ("virustotal", "url"):  mock_virustotal_url,
    ("virustotal", "file"): mock_virustotal_file,
    ("abuseipdb", "ip"):    mock_abuseipdb_check,
    ("shodan", "ip"):       mock_shodan_host,
}


def get_mock_response(tool: str, query_type: str, value: str) -> Optional[Dict[str, Any]]:
    """Get a mock response for a given tool and query type."""
    fn = MOCK_REGISTRY.get((tool, query_type))
    if fn:
        return fn(value)
    return None
