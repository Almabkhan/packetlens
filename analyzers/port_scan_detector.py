"""
Port Scan Detection
------------------------
Real detection logic: groups SYN packets by source IP and time window,
flagging a source as a likely scanner when it hits many distinct ports
on a target within a short time span — the actual signature of a port
scan (vs. normal traffic, which rarely touches more than a few ports
per host in quick succession).
"""

from collections import defaultdict


def detect_port_scans(packets: list, port_threshold: int = 15, time_window_seconds: float = 10.0) -> list:
    """
    Detect likely port scans: a (src_ip, dst_ip) pair where the number
    of DISTINCT destination ports contacted within `time_window_seconds`
    exceeds `port_threshold`.
    """
    syn_packets = [
        p for p in packets
        if p["protocol"] == "TCP" and p.get("flags") and "S" in p["flags"] and "A" not in p["flags"]
    ]

    if not syn_packets:
        return []

    # Group by (src, dst) pair
    pairs = defaultdict(list)
    for p in syn_packets:
        pairs[(p["src_ip"], p["dst_ip"])].append(p)

    findings = []
    for (src, dst), pkts in pairs.items():
        pkts.sort(key=lambda p: p["timestamp"])
        start_time = pkts[0]["timestamp"]
        end_time = pkts[-1]["timestamp"]
        duration = end_time - start_time

        distinct_ports = {p["dst_port"] for p in pkts}

        if len(distinct_ports) >= port_threshold and duration <= time_window_seconds:
            findings.append({
                "type": "port_scan_detected",
                "severity": "high",
                "source_ip": src,
                "target_ip": dst,
                "ports_scanned": len(distinct_ports),
                "duration_seconds": round(duration, 3),
                "description": f"{src} scanned {len(distinct_ports)} distinct ports on {dst} within {round(duration, 2)}s — consistent with a SYN/port scan",
            })

    return findings
