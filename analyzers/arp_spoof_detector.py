"""
ARP Spoofing Detection
---------------------------
Real detection logic: ARP spoofing (a classic MITM technique) works by
having an attacker claim a victim's IP address with the attacker's own
MAC address. This analyzer tracks every (IP -> MAC) binding seen via
ARP "is-at" replies, and flags any IP that gets claimed by more than
one distinct MAC address — the actual signature of ARP spoofing.
"""

from collections import defaultdict


def detect_arp_spoofing(packets: list) -> list:
    """Track IP->MAC bindings from ARP packets and flag conflicting claims."""
    arp_packets = [p for p in packets if p["protocol"] == "ARP" and p.get("arp_src_ip")]

    ip_to_macs = defaultdict(list)
    for p in arp_packets:
        ip_to_macs[p["arp_src_ip"]].append({"mac": p["arp_src_mac"], "timestamp": p["timestamp"], "index": p["index"]})

    findings = []
    for ip, claims in ip_to_macs.items():
        distinct_macs = {c["mac"] for c in claims}
        if len(distinct_macs) > 1:
            findings.append({
                "type": "arp_spoofing_suspected", "severity": "critical",
                "claimed_ip": ip,
                "conflicting_macs": sorted(distinct_macs),
                "claim_count": len(claims),
                "description": f"IP {ip} was claimed by {len(distinct_macs)} different MAC addresses ({', '.join(sorted(distinct_macs))}) — classic ARP spoofing/MITM signature",
            })

    return findings
