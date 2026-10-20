"""
Synthetic Test Capture Generator
-------------------------------------
Generates small, synthetic .pcap files entirely offline (no real network
traffic, no live capture) to validate PacketLens's analyzers against
known, controlled scenarios: a port scan, plaintext FTP credentials, and
ARP spoofing. This is the same approach used throughout this portfolio —
self-authored test fixtures, not real captured traffic.
"""

import time
from scapy.all import wrpcap, Ether, IP, TCP, UDP, ARP, Raw, DNS, DNSQR


def generate_port_scan_pcap(path: str):
    """Simulate a SYN scan: one source IP hitting many ports on one target in quick succession."""
    packets = []
    base_time = time.time()
    attacker_ip = "203.0.113.50"
    target_ip = "10.0.0.5"

    for i, port in enumerate(range(20, 90)):
        pkt = Ether() / IP(src=attacker_ip, dst=target_ip) / TCP(sport=40000 + i, dport=port, flags="S")
        pkt.time = base_time + i * 0.01  # 10ms apart — fast, scan-like
        packets.append(pkt)

    wrpcap(path, packets)


def generate_plaintext_credentials_pcap(path: str):
    """Simulate an FTP login sent in plaintext (a real, common finding)."""
    packets = []
    base_time = time.time()
    client_ip = "10.0.0.20"
    server_ip = "10.0.0.5"

    ftp_commands = [b"USER admin\r\n", b"PASS SuperSecret123\r\n", b"LIST\r\n"]
    for i, cmd in enumerate(ftp_commands):
        pkt = Ether() / IP(src=client_ip, dst=server_ip) / TCP(sport=51000, dport=21, flags="PA") / Raw(load=cmd)
        pkt.time = base_time + i * 0.5
        packets.append(pkt)

    wrpcap(path, packets)


def generate_arp_spoofing_pcap(path: str):
    """Simulate ARP spoofing: two different MAC addresses claiming the same IP."""
    packets = []
    base_time = time.time()
    victim_ip = "10.0.0.1"

    legit_mac = "aa:bb:cc:dd:ee:01"
    attacker_mac = "aa:bb:cc:dd:ee:99"

    # Legitimate ARP reply
    pkt1 = Ether(src=legit_mac) / ARP(op=2, psrc=victim_ip, hwsrc=legit_mac)
    pkt1.time = base_time
    packets.append(pkt1)

    # Attacker claims the SAME IP with a DIFFERENT MAC shortly after
    pkt2 = Ether(src=attacker_mac) / ARP(op=2, psrc=victim_ip, hwsrc=attacker_mac)
    pkt2.time = base_time + 2
    packets.append(pkt2)

    wrpcap(path, packets)


def generate_dns_traffic_pcap(path: str):
    """Simulate normal DNS query traffic."""
    packets = []
    base_time = time.time()
    client_ip = "10.0.0.20"
    dns_server = "8.8.8.8"

    domains = [b"example.com", b"github.com", b"suspicious-c2-domain-xyz123.net"]
    for i, domain in enumerate(domains):
        pkt = (Ether() / IP(src=client_ip, dst=dns_server) / UDP(sport=50000 + i, dport=53) /
               DNS(rd=1, qd=DNSQR(qname=domain)))
        pkt.time = base_time + i
        packets.append(pkt)

    wrpcap(path, packets)


def generate_normal_traffic_pcap(path: str):
    """Simulate ordinary, benign traffic (for false-positive testing)."""
    packets = []
    base_time = time.time()
    client_ip = "10.0.0.20"
    server_ip = "93.184.216.34"

    for i in range(5):
        pkt = Ether() / IP(src=client_ip, dst=server_ip) / TCP(sport=52000, dport=443, flags="PA") / Raw(load=b"encrypted-tls-data")
        pkt.time = base_time + i * 1.0
        packets.append(pkt)

    wrpcap(path, packets)


if __name__ == "__main__":
    import os
    os.makedirs(os.path.dirname(__file__), exist_ok=True)
    generate_port_scan_pcap(os.path.join(os.path.dirname(__file__), "port_scan.pcap"))
    generate_plaintext_credentials_pcap(os.path.join(os.path.dirname(__file__), "plaintext_creds.pcap"))
    generate_arp_spoofing_pcap(os.path.join(os.path.dirname(__file__), "arp_spoofing.pcap"))
    generate_dns_traffic_pcap(os.path.join(os.path.dirname(__file__), "dns_traffic.pcap"))
    generate_normal_traffic_pcap(os.path.join(os.path.dirname(__file__), "normal_traffic.pcap"))
    print("Sample pcap files generated.")
