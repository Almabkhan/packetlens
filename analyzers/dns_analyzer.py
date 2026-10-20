"""
DNS Traffic Analysis
-------------------------
Real analysis of DNS queries found in the capture: extracts the list of
queried domains, and flags domains matching simple-but-real heuristics
associated with malicious/C2 (command-and-control) domains — long
random-looking subdomains, suspicious keywords, and unusually long
hostnames. This is heuristic, not a verified malicious-domain database
lookup (documented honestly — a real tool would also check threat-intel
feeds, which requires network access this offline analyzer doesn't use).
"""

import re


SUSPICIOUS_KEYWORDS = ["c2", "malware", "phish", "exploit", "backdoor", "trojan"]


def analyze_dns_traffic(packets: list) -> dict:
    """Extract queried domains and flag suspicious-looking ones."""
    queries = [p["dns_query"].rstrip(".") for p in packets if p.get("dns_query")]

    findings = []
    for domain in set(queries):
        reasons = []

        if any(keyword in domain.lower() for keyword in SUSPICIOUS_KEYWORDS):
            reasons.append("contains a keyword commonly associated with malicious infrastructure")

        if len(domain) > 40:
            reasons.append("unusually long hostname (possible DNS tunneling or algorithmically-generated domain)")

        labels = domain.split(".")
        if labels and len(labels[0]) > 20 and re.match(r"^[a-z0-9]+$", labels[0]):
            reasons.append("long random-looking subdomain label (possible DGA — domain generation algorithm)")

        if reasons:
            findings.append({
                "type": "suspicious_dns_query", "severity": "medium",
                "domain": domain, "reasons": reasons,
                "description": f"Query for '{domain}' flagged: {'; '.join(reasons)}",
            })

    return {
        "total_queries": len(queries),
        "unique_domains": sorted(set(queries)),
        "findings": findings,
    }
