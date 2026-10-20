"""Report generation and risk scoring for PacketLens."""

import json
from datetime import datetime, timezone


SEVERITY_WEIGHTS = {"critical": 10, "high": 7, "medium": 4, "low": 2, "info": 0}


def compute_risk(findings: list) -> dict:
    total_weight = sum(SEVERITY_WEIGHTS.get(f.get("severity", "info"), 0) for f in findings)
    max_reasonable = 40
    score = min(100, round((total_weight / max_reasonable) * 100)) if max_reasonable else 0

    if score >= 70:
        level = "Critical"
    elif score >= 40:
        level = "High"
    elif score >= 15:
        level = "Medium"
    else:
        level = "Low"

    return {"score": score, "level": level}


def build_report(file_path: str, summary: dict, findings: list, dns_result: dict) -> dict:
    risk = compute_risk(findings)
    return {
        "file": file_path,
        "analyzed_at": datetime.now(timezone.utc).isoformat(),
        "summary": summary,
        "dns_queries": dns_result.get("unique_domains", []),
        "findings": findings,
        "risk_score": risk["score"],
        "risk_level": risk["level"],
    }


def save_json_report(report: dict, path: str):
    with open(path, "w", encoding="utf-8") as f:
        json.dump(report, f, indent=2, default=str)


HTML_TEMPLATE = """<!DOCTYPE html>
<html><head><meta charset="UTF-8"><title>PacketLens Report: {file}</title>
<style>
body {{ font-family: -apple-system, Segoe UI, Roboto, sans-serif; background:#0d1117; color:#c9d1d9; max-width:900px; margin:40px auto; padding:0 20px; }}
h1 {{ color:#58a6ff; border-bottom:2px solid #30363d; padding-bottom:10px; }}
.risk-badge {{ display:inline-block; padding:6px 16px; border-radius:6px; font-weight:bold; }}
.risk-Critical {{ background:#f85149; color:white; }}
.risk-High {{ background:#db6d28; color:white; }}
.risk-Medium {{ background:#d29922; color:black; }}
.risk-Low {{ background:#3fb950; color:black; }}
table {{ border-collapse:collapse; width:100%; margin:15px 0; }}
th, td {{ border:1px solid #30363d; padding:8px 12px; text-align:left; }}
th {{ background:#161b22; }}
.finding {{ background:#161b22; border-left:4px solid #30363d; padding:12px 16px; margin:12px 0; border-radius:4px; }}
.sev-critical {{ border-left-color:#f85149; }}
.sev-high {{ border-left-color:#db6d28; }}
.sev-medium {{ border-left-color:#d29922; }}
</style></head><body>
<h1>PacketLens Analysis Report</h1>
<p>File: <strong>{file}</strong> | Analyzed: {timestamp}</p>
<h2>Risk Assessment</h2>
<span class="risk-badge risk-{risk_level}">{risk_level} — {risk_score}/100</span>
<h2>Capture Summary</h2>
<table>
<tr><th>Metric</th><th>Value</th></tr>
<tr><td>Total packets</td><td>{total_packets}</td></tr>
<tr><td>Unique hosts</td><td>{unique_hosts}</td></tr>
<tr><td>Duration (s)</td><td>{duration}</td></tr>
</table>
<h2>Findings</h2>
{findings_html}
</body></html>"""


def save_html_report(report: dict, path: str):
    parts = []
    for f in report["findings"]:
        details = "".join(f"<div><strong>{k}:</strong> {v}</div>" for k, v in f.items()
                           if k not in ("type", "severity", "description"))
        parts.append(
            f'<div class="finding sev-{f["severity"]}"><strong>[{f["severity"].upper()}] '
            f'{f["type"].replace("_", " ")}</strong><div>{f["description"]}</div>{details}</div>'
        )

    html = HTML_TEMPLATE.format(
        file=report["file"], timestamp=report["analyzed_at"],
        risk_level=report["risk_level"], risk_score=report["risk_score"],
        total_packets=report["summary"].get("total_packets", 0),
        unique_hosts=report["summary"].get("unique_hosts", 0),
        duration=report["summary"].get("duration_seconds", 0),
        findings_html="\n".join(parts) if parts else "<p>No findings.</p>",
    )
    with open(path, "w", encoding="utf-8") as f:
        f.write(html)
