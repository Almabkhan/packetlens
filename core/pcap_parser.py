"""
PCAP Parser
---------------
Real packet capture file parsing using Scapy. Reads .pcap/.pcapng files
and extracts structured data for each packet: timestamps, source/dest
IPs and ports, protocol, size, and payload (for plaintext-credential
detection). This is offline, file-based analysis — no live packet
capture or network sniffing.
"""

from scapy.all import rdpcap, IP, IPv6, TCP, UDP, ARP, Raw, DNS


def parse_pcap(file_path: str) -> list:
    """
    Parse a pcap file and return a list of structured packet dicts.
    Each dict captures the fields needed for the analyzers (protocol
    stats, port scan detection, credential leaks, ARP spoofing, DNS).
    """
    packets = rdpcap(file_path)
    parsed = []

    for i, pkt in enumerate(packets):
        entry = {
            "index": i,
            "timestamp": float(pkt.time),
            "size": len(pkt),
            "src_ip": None,
            "dst_ip": None,
            "src_port": None,
            "dst_port": None,
            "protocol": "OTHER",
            "flags": None,
            "payload": None,
            "arp_src_mac": None,
            "arp_src_ip": None,
            "dns_query": None,
        }

        if pkt.haslayer(IP):
            entry["src_ip"] = pkt[IP].src
            entry["dst_ip"] = pkt[IP].dst
        elif pkt.haslayer(IPv6):
            entry["src_ip"] = pkt[IPv6].src
            entry["dst_ip"] = pkt[IPv6].dst

        if pkt.haslayer(TCP):
            entry["protocol"] = "TCP"
            entry["src_port"] = pkt[TCP].sport
            entry["dst_port"] = pkt[TCP].dport
            entry["flags"] = str(pkt[TCP].flags)
        elif pkt.haslayer(UDP):
            entry["protocol"] = "UDP"
            entry["src_port"] = pkt[UDP].sport
            entry["dst_port"] = pkt[UDP].dport
        elif pkt.haslayer(ARP):
            entry["protocol"] = "ARP"
            entry["arp_src_mac"] = pkt[ARP].hwsrc
            entry["arp_src_ip"] = pkt[ARP].psrc

        if pkt.haslayer(DNS) and pkt[DNS].qd is not None:
            try:
                entry["dns_query"] = pkt[DNS].qd.qname.decode(errors="ignore")
            except Exception:
                pass

        if pkt.haslayer(Raw):
            try:
                entry["payload"] = bytes(pkt[Raw].load)
            except Exception:
                entry["payload"] = None

        parsed.append(entry)

    return parsed


def get_capture_summary(packets: list) -> dict:
    """Basic capture-level statistics."""
    if not packets:
        return {"total_packets": 0}

    timestamps = [p["timestamp"] for p in packets]
    protocol_counts = {}
    for p in packets:
        protocol_counts[p["protocol"]] = protocol_counts.get(p["protocol"], 0) + 1

    unique_ips = set()
    for p in packets:
        if p["src_ip"]:
            unique_ips.add(p["src_ip"])
        if p["dst_ip"]:
            unique_ips.add(p["dst_ip"])

    return {
        "total_packets": len(packets),
        "duration_seconds": round(max(timestamps) - min(timestamps), 3) if len(timestamps) > 1 else 0,
        "protocol_counts": protocol_counts,
        "unique_hosts": len(unique_ips),
        "total_bytes": sum(p["size"] for p in packets),
    }
