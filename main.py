#!/usr/bin/env python3
"""
PacketLens — Offline Packet Capture Security Analyzer
-----------------------------------------------------------
Analyzes .pcap files for port scans, plaintext credential leaks, ARP
spoofing, and suspicious DNS queries. Pure file-based, offline analysis
— no live packet capture or network sniffing.

Usage:
    python main.py samples/port_scan.pcap
    python main.py samples/plaintext_creds.pcap --output-dir ./scan_output
"""

import argparse
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))

from core.pcap_parser import parse_pcap, get_capture_summary
from analyzers.port_scan_detector import detect_port_scans
from analyzers.credential_leak_detector import detect_plaintext_credentials
from analyzers.arp_spoof_detector import detect_arp_spoofing
from analyzers.dns_analyzer import analyze_dns_traffic
from reports.generator import build_report, save_json_report, save_html_report


def analyze_pcap(file_path: str) -> dict:
    packets = parse_pcap(file_path)
    summary = get_capture_summary(packets)

    findings = []
    findings.extend(detect_port_scans(packets))
    findings.extend(detect_plaintext_credentials(packets))
    findings.extend(detect_arp_spoofing(packets))

    dns_result = analyze_dns_traffic(packets)
    findings.extend(dns_result["findings"])

    return build_report(file_path, summary, findings, dns_result)


def main():
    parser = argparse.ArgumentParser(description="PacketLens — offline pcap security analyzer")
    parser.add_argument("pcap_file", help="Path to a .pcap/.pcapng file to analyze")
    parser.add_argument("--output-dir", default="./scan_output", help="Directory to save reports")
    args = parser.parse_args()

    print("=" * 70)
    print(f"  PACKETLENS — Analyzing: {args.pcap_file}")
    print("=" * 70)

    report = analyze_pcap(args.pcap_file)

    output_dir = Path(args.output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)
    file_stem = Path(args.pcap_file).stem

    save_json_report(report, str(output_dir / f"{file_stem}_report.json"))
    save_html_report(report, str(output_dir / f"{file_stem}_report.html"))

    print(f"\n  Total packets   : {report['summary']['total_packets']}")
    print(f"  Findings        : {len(report['findings'])}")
    print(f"  Risk            : {report['risk_level']} ({report['risk_score']}/100)")
    print(f"  Reports saved to: {output_dir}/")
    print("=" * 70)

    for f in report["findings"]:
        print(f"\n  [{f['severity'].upper()}] {f['type']}")
        print(f"    {f['description']}")


if __name__ == "__main__":
    main()
