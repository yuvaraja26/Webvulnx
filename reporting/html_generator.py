from datetime import datetime, timezone
from markupsafe import escape

SEVERITY_ORDER = ["Critical", "High", "Medium", "Low", "Informational"]
STATUS_ORDER = ["New", "Needs Validation", "Confirmed", "False Positive", "Fixed", "Retested"]


def generate_html_report(assessment, target, findings, transaction_count: int) -> str:
    """Generates a standalone, dark-themed HTML VAPT report with severity, validation, and category summaries."""
    now_str = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")

    sev_counts = {sev: 0 for sev in SEVERITY_ORDER}
    status_counts = {st: 0 for st in STATUS_ORDER}
    category_counts = {}

    for f in findings:
        if f.severity in sev_counts:
            sev_counts[f.severity] += 1
        st = f.validation_status or "New"
        status_counts[st] = status_counts.get(st, 0) + 1
        cat = f.category or "Uncategorized"
        category_counts[cat] = category_counts.get(cat, 0) + 1

    ordered_statuses = list(STATUS_ORDER) + [k for k in status_counts.keys() if k not in STATUS_ORDER]
    status_cards_html = "".join(
        f'<div class="summary-item"><span>{escape(st)}</span><strong>{status_counts.get(st, 0)}</strong></div>'
        for st in ordered_statuses
    )

    if category_counts:
        category_rows_html = "".join(
            f"<tr><td>{escape(cat)}</td><td class=\"num-col\">{cnt}</td></tr>"
            for cat, cnt in sorted(category_counts.items(), key=lambda x: (-x[1], x[0]))
        )
    else:
        category_rows_html = '<tr><td colspan="2" style="color:#9ca3af;">No vulnerability categories recorded.</td></tr>'

    findings_html = ""
    if not findings:
        findings_html = "<p style='color:#9ca3af;'>No vulnerability findings were recorded for this assessment.</p>"
    else:
        for idx, f in enumerate(findings, start=1):
            evidence_block = ""
            if f.response_evidence:
                evidence_block = f"""
                <div class="label">Captured Evidence</div>
                <pre>{escape(f.response_evidence[:1500])}</pre>
                """
            findings_html += f"""
            <div class="finding-card">
                <div class="finding-header">
                    <span class="badge sev-{f.severity.lower()}">{escape(f.severity)}</span>
                    <span class="badge status">{escape(f.validation_status)}</span>
                    <h3>{idx}. {escape(f.title)}</h3>
                </div>
                <div class="endpoint">{escape(f.http_method)} {escape(f.affected_url)}</div>
                <p><strong>Category:</strong> {escape(f.category)} | <strong>Confidence:</strong> {escape(f.confidence)}</p>
                <p><strong>Description:</strong> {escape(f.description)}</p>
                <p><strong>Detection Explanation:</strong> {escape(f.detection_explanation)}</p>
                <p><strong>Impact:</strong> {escape(f.impact or 'N/A')}</p>
                <div class="remediation"><strong>Remediation:</strong> {escape(f.remediation)}</div>
                {evidence_block}
            </div>
            """

    return f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<title>WebVulnX VAPT Report - {escape(assessment.title)}</title>
<style>
    body {{ font-family: system-ui, -apple-system, sans-serif; background: #09090d; color: #f3f4f6; margin: 0; padding: 40px; line-height: 1.6; }}
    .container {{ max-width: 960px; margin: 0 auto; }}
    .header {{ border-bottom: 2px solid #ff1e42; padding-bottom: 20px; margin-bottom: 30px; }}
    h1 {{ color: #ff1e42; margin: 0 0 8px 0; }}
    h2 {{ color: #f87171; border-left: 4px solid #ff1e42; padding-left: 12px; margin-top: 32px; }}
    .meta-grid {{ display: grid; grid-template-columns: repeat(2, 1fr); gap: 12px; background: #14141c; padding: 20px; border-radius: 8px; border: 1px solid #272736; }}
    .sev-grid {{ display: grid; grid-template-columns: repeat(5, 1fr); gap: 12px; margin: 20px 0; }}
    .sev-box {{ background: #14141c; border: 1px solid #272736; border-radius: 8px; padding: 14px; text-align: center; }}
    .sev-box .num {{ font-size: 1.8rem; font-weight: bold; color: #ff1e42; }}
    .status-grid {{ display: grid; grid-template-columns: repeat(3, 1fr); gap: 12px; margin: 16px 0; }}
    .summary-item {{ display: flex; justify-content: space-between; align-items: center; background: #14141c; border: 1px solid #272736; border-radius: 8px; padding: 12px 16px; }}
    .summary-item strong {{ font-family: monospace; font-size: 1.15rem; color: #ff4d6a; }}
    table.cat-table {{ width: 100%; border-collapse: collapse; background: #14141c; border: 1px solid #272736; border-radius: 8px; overflow: hidden; margin-top: 12px; }}
    table.cat-table th, table.cat-table td {{ padding: 11px 16px; border-bottom: 1px solid #272736; text-align: left; }}
    table.cat-table th {{ background: #1b1b26; color: #f87171; font-size: 0.85rem; text-transform: uppercase; }}
    table.cat-table td.num-col {{ text-align: right; font-family: monospace; font-weight: bold; color: #ff4d6a; }}
    .finding-card {{ background: #14141c; border: 1px solid #272736; border-radius: 8px; padding: 20px; margin-bottom: 18px; }}
    .finding-header h3 {{ margin: 8px 0 4px 0; }}
    .endpoint {{ font-family: monospace; color: #ff4d6a; font-size: 0.9rem; margin-bottom: 10px; word-break: break-all; }}
    .badge {{ display: inline-block; padding: 3px 10px; border-radius: 4px; font-size: 0.78rem; font-weight: bold; margin-right: 6px; }}
    .sev-critical {{ background: #ff1e42; color: #fff; }}
    .sev-high {{ background: #ea580c; color: #fff; }}
    .sev-medium {{ background: #d97706; color: #fff; }}
    .sev-low {{ background: #16a34a; color: #fff; }}
    .sev-informational {{ background: #0284c7; color: #fff; }}
    .status {{ background: #374151; color: #e5e7eb; }}
    .remediation {{ background: rgba(255, 30, 66, 0.1); border-left: 3px solid #ff1e42; padding: 10px 14px; margin: 10px 0; }}
    pre {{ background: #050507; padding: 12px; border-radius: 6px; overflow-x: auto; font-size: 0.82rem; border: 1px solid #272736; }}
</style>
</head>
<body>
<div class="container">
    <div class="header">
        <h1>WebVulnX VAPT Assessment Report</h1>
        <div>Automated Web Application Vulnerability Assessment &amp; Reporting Platform</div>
    </div>

    <div class="meta-grid">
        <div><strong>Assessment:</strong> {escape(assessment.title)}</div>
        <div><strong>Target:</strong> {escape(target.name)} ({escape(target.base_url)})</div>
        <div><strong>Environment:</strong> {escape(target.environment or 'Local Lab')}</div>
        <div><strong>Generated:</strong> {now_str}</div>
        <div><strong>HTTP Requests Analysed:</strong> {transaction_count}</div>
        <div><strong>Total Findings:</strong> {len(findings)}</div>
    </div>

    <h2>1. Risk Summary by Severity</h2>
    <div class="sev-grid">
        <div class="sev-box"><div>Critical</div><div class="num">{sev_counts['Critical']}</div></div>
        <div class="sev-box"><div>High</div><div class="num">{sev_counts['High']}</div></div>
        <div class="sev-box"><div>Medium</div><div class="num">{sev_counts['Medium']}</div></div>
        <div class="sev-box"><div>Low</div><div class="num">{sev_counts['Low']}</div></div>
        <div class="sev-box"><div>Info</div><div class="num">{sev_counts['Informational']}</div></div>
    </div>

    <h2>2. Validation Status Summary</h2>
    <div class="status-grid">
        {status_cards_html}
    </div>

    <h2>3. Findings by Category</h2>
    <table class="cat-table">
        <thead>
            <tr><th>Vulnerability Category</th><th style="text-align:right;">Count</th></tr>
        </thead>
        <tbody>
            {category_rows_html}
        </tbody>
    </table>

    <h2>4. Detailed Vulnerability Findings</h2>
    {findings_html}
</div>
</body>
</html>"""
