import io
from datetime import datetime, timezone
from reportlab.lib import colors
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, PageBreak


SEVERITY_ORDER = ["Critical", "High", "Medium", "Low", "Informational"]
STATUS_ORDER = ["New", "Needs Validation", "Confirmed", "False Positive", "Fixed", "Retested"]


def generate_pdf_report(assessment, target, findings, transaction_count: int) -> bytes:
    """Generates a professional VAPT PDF report in memory and returns raw PDF bytes."""
    buffer = io.BytesIO()
    doc = SimpleDocTemplate(
        buffer,
        pagesize=A4,
        rightMargin=45,
        leftMargin=45,
        topMargin=50,
        bottomMargin=50,
        title=f"WebVulnX VAPT Report - {assessment.title}",
    )

    styles = getSampleStyleSheet()
    title_style = ParagraphStyle(
        "CoverTitle",
        parent=styles["Title"],
        fontSize=24,
        textColor=colors.HexColor("#b91c1c"),
        spaceAfter=14,
    )
    h1_style = ParagraphStyle(
        "SectionH1",
        parent=styles["Heading1"],
        fontSize=15,
        textColor=colors.HexColor("#991b1b"),
        spaceBefore=14,
        spaceAfter=8,
    )
    h2_style = ParagraphStyle(
        "FindingH2",
        parent=styles["Heading2"],
        fontSize=12,
        textColor=colors.HexColor("#111827"),
        spaceBefore=10,
        spaceAfter=4,
    )
    body_style = styles["BodyText"]
    code_style = ParagraphStyle(
        "CodeBlock",
        parent=styles["Code"],
        fontSize=8,
        leading=10,
        backColor=colors.HexColor("#f3f4f6"),
        borderPadding=6,
    )

    story = []
    now_str = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")

    # 1. Cover Page
    story.append(Spacer(1, 60))
    story.append(Paragraph("WebVulnX", title_style))
    story.append(Paragraph("Web Application Vulnerability Assessment & Reporting Platform", styles["Heading2"]))
    story.append(Spacer(1, 24))

    meta_data = [
        ["Assessment Title", assessment.title],
        ["Target Application", f"{target.name} ({target.base_url})"],
        ["Environment", target.environment or "Local Lab"],
        ["Assessment Status", assessment.status],
        ["HTTP Transactions Analysed", str(transaction_count)],
        ["Report Generated", now_str],
        ["Report Version", "1.1"],
    ]
    meta_table = Table(meta_data, colWidths=[160, 340])
    meta_table.setStyle(
        TableStyle(
            [
                ("BACKGROUND", (0, 0), (0, -1), colors.HexColor("#1f2937")),
                ("TEXTCOLOR", (0, 0), (0, -1), colors.white),
                ("BACKGROUND", (1, 0), (1, -1), colors.HexColor("#f9fafb")),
                ("GRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#d1d5db")),
                ("FONTNAME", (0, 0), (0, -1), "Helvetica-Bold"),
                ("PADDING", (0, 0), (-1, -1), 8),
            ]
        )
    )
    story.append(meta_table)
    story.append(PageBreak())

    # 2. Executive Summary
    story.append(Paragraph("1. Executive Summary", h1_style))
    story.append(
        Paragraph(
            f"This report presents the results of the security assessment conducted against "
            f"<b>{target.name}</b> (<code>{target.base_url}</code>) using WebVulnX integrated with "
            f"Burp Suite Community Edition. A total of <b>{transaction_count}</b> HTTP transactions were "
            f"captured and analysed, resulting in <b>{len(findings)}</b> recorded finding(s).",
            body_style,
        )
    )
    story.append(Spacer(1, 12))

    # 3. Severity Breakdown
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

    story.append(Paragraph("2. Vulnerability Summary by Severity", h1_style))
    sev_rows = [["Severity", "Count"]] + [[sev, str(sev_counts[sev])] for sev in SEVERITY_ORDER]
    sev_table = Table(sev_rows, colWidths=[250, 250])
    sev_table.setStyle(
        TableStyle(
            [
                ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#991b1b")),
                ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
                ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
                ("GRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#d1d5db")),
                ("PADDING", (0, 0), (-1, -1), 7),
            ]
        )
    )
    story.append(sev_table)
    story.append(Spacer(1, 12))

    # 4. Validation Status Summary
    story.append(Paragraph("3. Validation Status Summary", h1_style))
    ordered_statuses = list(STATUS_ORDER) + [k for k in status_counts.keys() if k not in STATUS_ORDER]
    status_rows = [["Validation Status", "Count"]] + [[st, str(status_counts.get(st, 0))] for st in ordered_statuses]
    status_table = Table(status_rows, colWidths=[250, 250])
    status_table.setStyle(
        TableStyle(
            [
                ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#1f2937")),
                ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
                ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
                ("GRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#d1d5db")),
                ("PADDING", (0, 0), (-1, -1), 7),
            ]
        )
    )
    story.append(status_table)
    story.append(Spacer(1, 12))

    # 5. Category Breakdown
    story.append(Paragraph("4. Findings by Vulnerability Category", h1_style))
    if category_counts:
        cat_rows = [["Category", "Findings"]] + [
            [cat, str(cnt)] for cat, cnt in sorted(category_counts.items(), key=lambda x: (-x[1], x[0]))
        ]
    else:
        cat_rows = [["Category", "Findings"], ["None Recorded", "0"]]
    cat_table = Table(cat_rows, colWidths=[350, 150])
    cat_table.setStyle(
        TableStyle(
            [
                ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#991b1b")),
                ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
                ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
                ("GRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#d1d5db")),
                ("PADDING", (0, 0), (-1, -1), 7),
            ]
        )
    )
    story.append(cat_table)
    story.append(Spacer(1, 14))

    # 6. Scope & Methodology
    story.append(Paragraph("5. Assessment Scope & Methodology", h1_style))
    story.append(
        Paragraph(
            f"Testing was strictly restricted to the authorized scope prefix <code>{target.scope_prefix}</code>. "
            f"HTTP traffic was intercepted via Burp Suite Community Edition, sanitized to redact sensitive "
            f"credentials/cookies, and analysed by the WebVulnX Python detection engine. Findings require "
            f"analyst review to distinguish automated detections from manually confirmed vulnerabilities.",
            body_style,
        )
    )
    story.append(Spacer(1, 14))

    # 7. Detailed Findings
    story.append(Paragraph("6. Detailed Vulnerability Findings", h1_style))
    if not findings:
        story.append(Paragraph("No vulnerability findings were recorded for this assessment.", body_style))
    else:
        for idx, f in enumerate(findings, start=1):
            story.append(Paragraph(f"6.{idx} [{f.severity}] {f.title}", h2_style))
            detail_rows = [
                ["Affected Endpoint", f"{f.http_method} {f.affected_url}"],
                ["Category", f.category],
                ["Confidence", f.confidence],
                ["Validation Status", f.validation_status],
            ]
            dt = Table(detail_rows, colWidths=[130, 370])
            dt.setStyle(
                TableStyle(
                    [
                        ("BACKGROUND", (0, 0), (0, -1), colors.HexColor("#f3f4f6")),
                        ("FONTNAME", (0, 0), (0, -1), "Helvetica-Bold"),
                        ("GRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#e5e7eb")),
                        ("PADDING", (0, 0), (-1, -1), 5),
                    ]
                )
            )
            story.append(dt)
            story.append(Spacer(1, 6))
            story.append(Paragraph(f"<b>Description:</b> {_escape(f.description)}", body_style))
            story.append(Paragraph(f"<b>Detection Explanation:</b> {_escape(f.detection_explanation)}", body_style))
            story.append(Paragraph(f"<b>Impact:</b> {_escape(f.impact or 'N/A')}", body_style))
            story.append(Paragraph(f"<b>Remediation:</b> {_escape(f.remediation)}", body_style))
            if f.response_evidence:
                snippet = _escape(f.response_evidence[:800]).replace("\n", "<br/>")
                story.append(Spacer(1, 4))
                story.append(Paragraph("<b>Evidence Snippet:</b>", body_style))
                story.append(Paragraph(snippet, code_style))
            story.append(Spacer(1, 12))

    doc.build(story)
    pdf_bytes = buffer.getvalue()
    buffer.close()
    return pdf_bytes


def _escape(text: str) -> str:
    if not text:
        return ""
    return (
        str(text)
        .replace("&", "&amp;")
        .replace("<", "&lt;")
        .replace(">", "&gt;")
    )
