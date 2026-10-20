
"""Tests for PacketLens HTML report generation."""

import tempfile
import unittest
from pathlib import Path

from reports.generator import save_html_report


class TestHtmlReportGenerator(unittest.TestCase):

    def make_report(self, finding):
        return {
            "file": "sample.pcap",
            "analyzed_at": "2026-10-20T12:00:00Z",
            "risk_level": "High",
            "risk_score": 80,
            "summary": {
                "total_packets": 10,
                "unique_hosts": 2,
                "duration_seconds": 5,
            },
            "findings": [finding],
        }

    def generate_html(self, report):
        temp_file = tempfile.NamedTemporaryFile(
            suffix=".html", delete=False
        )
        temp_file.close()
        path = Path(temp_file.name)

        try:
            save_html_report(report, str(path))
            return path.read_text(encoding="utf-8")
        finally:
            path.unlink(missing_ok=True)

    def test_generates_html_report(self):
        report = self.make_report({
            "type": "port_scan",
            "severity": "high",
            "description": "Suspicious port scan detected",
        })

        html = self.generate_html(report)

        self.assertIn("Suspicious port scan detected", html)
        self.assertIn("sample.pcap", html)

    def test_escapes_script_in_description(self):
        payload = '<script>alert("XSS")</script>'
        report = self.make_report({
            "type": "test",
            "severity": "high",
            "description": payload,
        })

        html = self.generate_html(report)

        self.assertNotIn(payload, html)
        self.assertIn("&lt;script&gt;", html)

    def test_escapes_html_in_finding_details(self):
        payload = '<img src=x onerror="alert(1)">'
        report = self.make_report({
            "type": "test",
            "severity": "medium",
            "description": "Test finding",
            "details": payload,
        })

        html = self.generate_html(report)

        self.assertNotIn(payload, html)
        self.assertIn("&lt;img", html)

    def test_escapes_html_in_report_filename(self):
        payload = '<script>alert(1)</script>.pcap'
        report = self.make_report({
            "type": "test",
            "severity": "low",
            "description": "Test",
        })
        report["file"] = payload

        html = self.generate_html(report)

        self.assertNotIn(payload, html)
        self.assertIn("&lt;script&gt;", html)

    def test_empty_findings(self):
        report = self.make_report({})
        report["findings"] = []

        html = self.generate_html(report)

        self.assertIn("No findings.", html)


if __name__ == "__main__":
    unittest.main()
