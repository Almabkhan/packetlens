"""
Plaintext Credential Detection
------------------------------------
Real detection logic: scans TCP payload content on well-known cleartext
protocol ports (FTP=21, Telnet=23, HTTP=80, POP3=110, IMAP=143) for
credential-like patterns (USER/PASS commands, HTTP Basic Auth headers,
etc.) — a genuinely common, real-world finding in packet captures.
"""

import re
import base64


CLEARTEXT_PROTOCOL_PORTS = {21: "FTP", 23: "Telnet", 80: "HTTP", 110: "POP3", 143: "IMAP"}

FTP_USER_RE = re.compile(rb"USER\s+(\S+)", re.IGNORECASE)
FTP_PASS_RE = re.compile(rb"PASS\s+(\S+)", re.IGNORECASE)
HTTP_BASIC_AUTH_RE = re.compile(rb"Authorization:\s*Basic\s+(\S+)", re.IGNORECASE)
POP3_USER_RE = re.compile(rb"USER\s+(\S+)", re.IGNORECASE)
POP3_PASS_RE = re.compile(rb"PASS\s+(\S+)", re.IGNORECASE)


def detect_plaintext_credentials(packets: list) -> list:
    """Scan packets on cleartext protocol ports for credential patterns."""
    findings = []

    for p in packets:
        if p["protocol"] != "TCP" or not p.get("payload"):
            continue

        port = p.get("dst_port") if p.get("dst_port") in CLEARTEXT_PROTOCOL_PORTS else p.get("src_port")
        if port not in CLEARTEXT_PROTOCOL_PORTS:
            continue

        protocol_name = CLEARTEXT_PROTOCOL_PORTS[port]
        payload = p["payload"]

        if protocol_name in ("FTP", "POP3"):
            user_match = FTP_USER_RE.search(payload)
            pass_match = FTP_PASS_RE.search(payload)
            if user_match:
                findings.append({
                    "type": "plaintext_credential", "severity": "critical",
                    "protocol": protocol_name, "field": "username",
                    "value": user_match.group(1).decode(errors="ignore"),
                    "src_ip": p["src_ip"], "dst_ip": p["dst_ip"], "packet_index": p["index"],
                    "description": f"{protocol_name} username sent in cleartext",
                })
            if pass_match:
                findings.append({
                    "type": "plaintext_credential", "severity": "critical",
                    "protocol": protocol_name, "field": "password",
                    "value": pass_match.group(1).decode(errors="ignore"),
                    "src_ip": p["src_ip"], "dst_ip": p["dst_ip"], "packet_index": p["index"],
                    "description": f"{protocol_name} password sent in cleartext",
                })

        elif protocol_name == "HTTP":
            auth_match = HTTP_BASIC_AUTH_RE.search(payload)
            if auth_match:
                try:
                    decoded = base64.b64decode(auth_match.group(1)).decode(errors="ignore")
                except Exception:
                    decoded = "<could not decode>"
                findings.append({
                    "type": "plaintext_credential", "severity": "critical",
                    "protocol": "HTTP", "field": "basic_auth",
                    "value": decoded,
                    "src_ip": p["src_ip"], "dst_ip": p["dst_ip"], "packet_index": p["index"],
                    "description": "HTTP Basic Authentication credentials sent in cleartext (base64 is not encryption)",
                })

    return findings
