from reportlab.lib import colors
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.enums import TA_CENTER
from reportlab.lib.units import mm
from reportlab.platypus import (
    SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle,
    PageBreak, KeepTogether, HRFlowable
)
from xml.sax.saxutils import escape


PAGE_W, PAGE_H = A4
LEFT = 18 * mm
RIGHT = 18 * mm
TOP = 16 * mm
BOTTOM = 17 * mm
CONTENT_W = PAGE_W - LEFT - RIGHT


def safe(value):
    return escape(str(value if value is not None else ""))


def score_text(value):
    return "N/A" if value is None else f"{value}/100"


def build_styles():
    styles = getSampleStyleSheet()

    styles.add(ParagraphStyle(
        name="WS_Title",
        parent=styles["Title"],
        fontSize=22,
        leading=27,
        alignment=TA_CENTER,
        spaceAfter=6,
    ))
    styles.add(ParagraphStyle(
        name="WS_Subtitle",
        parent=styles["BodyText"],
        fontSize=10,
        leading=14,
        alignment=TA_CENTER,
        textColor=colors.HexColor("#52636F"),
        spaceAfter=14,
    ))
    styles.add(ParagraphStyle(
        name="WS_H1",
        parent=styles["Heading1"],
        fontSize=16,
        leading=20,
        spaceBefore=10,
        spaceAfter=8,
    ))
    styles.add(ParagraphStyle(
        name="WS_H2",
        parent=styles["Heading2"],
        fontSize=12.5,
        leading=16,
        spaceBefore=8,
        spaceAfter=5,
    ))
    styles.add(ParagraphStyle(
        name="WS_Body",
        parent=styles["BodyText"],
        fontSize=9.3,
        leading=13.4,
        spaceAfter=5,
    ))
    styles.add(ParagraphStyle(
        name="WS_Small",
        parent=styles["BodyText"],
        fontSize=8,
        leading=11,
        textColor=colors.HexColor("#52636F"),
        spaceAfter=4,
    ))
    styles.add(ParagraphStyle(
        name="WS_Callout",
        parent=styles["BodyText"],
        fontSize=9,
        leading=13,
        backColor=colors.HexColor("#F2F7FA"),
        borderColor=colors.HexColor("#D5E4EC"),
        borderWidth=0.5,
        borderPadding=8,
        spaceBefore=5,
        spaceAfter=9,
    ))
    styles.add(ParagraphStyle(
        name="WS_Score",
        parent=styles["Heading1"],
        fontSize=26,
        leading=30,
        alignment=TA_CENTER,
        textColor=colors.HexColor("#0C6E62"),
        spaceAfter=4,
    ))
    return styles


def kv_table(rows, styles, key_width=42*mm):
    body = styles["WS_Body"]
    data = []
    for key, value in rows:
        data.append([
            Paragraph(f"<b>{safe(key)}</b>", body),
            Paragraph(safe(value), body),
        ])

    table = Table(
        data,
        colWidths=[key_width, CONTENT_W - key_width],
        hAlign="LEFT",
        repeatRows=0,
    )
    table.setStyle(TableStyle([
        ("VALIGN", (0,0), (-1,-1), "TOP"),
        ("LEFTPADDING", (0,0), (-1,-1), 5),
        ("RIGHTPADDING", (0,0), (-1,-1), 5),
        ("TOPPADDING", (0,0), (-1,-1), 5),
        ("BOTTOMPADDING", (0,0), (-1,-1), 5),
        ("LINEBELOW", (0,0), (-1,-1), 0.25, colors.HexColor("#DCE5EA")),
    ]))
    return table


def bullet_list(items, styles, empty_text):
    story = []
    if not items:
        story.append(Paragraph(safe(empty_text), styles["WS_Body"]))
        return story
    for item in items:
        story.append(Paragraph("• " + safe(item), styles["WS_Body"]))
    return story


def add_page_number(canvas, doc):
    canvas.saveState()
    canvas.setFont("Helvetica", 8)
    canvas.setFillColor(colors.HexColor("#6B7C87"))
    canvas.drawRightString(PAGE_W - RIGHT, 9*mm, f"Page {doc.page}")
    canvas.drawString(LEFT, 9*mm, "WebShield Final - Evidence-Based Security Assessment")
    canvas.restoreState()


def build_pdf_report(result, output_path):
    styles = build_styles()

    doc = SimpleDocTemplate(
        str(output_path),
        pagesize=A4,
        leftMargin=LEFT,
        rightMargin=RIGHT,
        topMargin=TOP,
        bottomMargin=BOTTOM,
        title="WebShield Security Report",
        author="WebShield",
    )

    story = []

    # Cover
    story.append(Paragraph("WebShield Security Report", styles["WS_Title"]))
    story.append(Paragraph(
        "Passive Website Configuration Assessment - beginner-friendly and evidence-aware",
        styles["WS_Subtitle"]
    ))
    story.append(kv_table([
        ("Website", result.get("final_url", "")),
        ("Scan date", result.get("created_at", "")),
        ("WebShield version", result.get("version", "4.0")),
    ], styles))
    story.append(Spacer(1, 10))

    story.append(Paragraph(score_text(result.get("score")), styles["WS_Score"]))
    story.append(Paragraph(
        f"<b>{safe(result.get('posture', ''))}</b><br/>{safe(result.get('posture_text', ''))}",
        styles["WS_Callout"]
    ))

    coverage = result.get("coverage_percent", 0)
    evaluated = result.get("evaluated_count", 0)
    total = result.get("total_categories", 0)

    story.append(Paragraph("What this number means", styles["WS_H1"]))
    story.append(Paragraph(
        "This is an <b>WebShield Observed Security Posture</b> score. It is calculated only from passive security "
        "categories that WebShield had enough evidence to evaluate. It is <b>not</b> a hackability score, "
        "penetration-test result, or guarantee that the website is secure.",
        styles["WS_Body"]
    ))
    story.append(Paragraph(
        f"<b>Evaluation coverage:</b> {safe(coverage)}% of weighted passive categories "
        f"({safe(evaluated)} of {safe(total)} categories received numeric scores). "
        "Other categories are marked N/A or Limited rather than receiving an unsupported 100/100.",
        styles["WS_Callout"]
    ))

    # Beginner summary
    summary = result.get("beginner_summary", {})
    story.append(Paragraph("Beginner-Friendly Summary", styles["WS_H1"]))
    story.append(Paragraph(safe(summary.get("headline", "")), styles["WS_H2"]))

    story.append(Paragraph("What looks good", styles["WS_H2"]))
    story.extend(bullet_list(
        summary.get("good_news", []), styles,
        "No positive control was highlighted in this scan."
    ))

    story.append(Paragraph("What should be improved", styles["WS_H2"]))
    story.extend(bullet_list(
        summary.get("improvements", []), styles,
        "No confirmed configuration improvement was highlighted."
    ))

    story.append(Paragraph("What needs manual review", styles["WS_H2"]))
    story.extend(bullet_list(
        summary.get("manual_review", []), styles,
        "No manual-review item was highlighted."
    ))

    story.append(Paragraph(
        "<b>Important:</b> " + safe(summary.get("important_note", "")),
        styles["WS_Callout"]
    ))

    # Hackability
    story.append(Paragraph("Can WebShield Tell Whether the Website Can Be Hacked?", styles["WS_H1"]))
    hack = result.get("hackability", {})
    story.append(Paragraph(f"<b>{safe(hack.get('level', ''))}</b>", styles["WS_H2"]))
    story.append(Paragraph(safe(hack.get("answer", "")), styles["WS_Body"]))
    story.append(Paragraph(safe(hack.get("message", "")), styles["WS_Callout"]))

    # Category coverage - alignment-safe two-column layout
    story.append(PageBreak())
    story.append(Paragraph("Security Categories and Evidence Coverage", styles["WS_H1"]))
    story.append(Paragraph(
        "A numeric score appears only when WebShield has enough passive evidence for that category. "
        "N/A means the relevant object was not observed. Limited means passive inspection cannot support a trustworthy numeric score.",
        styles["WS_Body"]
    ))

    category_rows = [[
        Paragraph("<b>Category</b>", styles["WS_Body"]),
        Paragraph("<b>Result</b>", styles["WS_Body"]),
    ]]

    for name, item in result.get("categories", {}).items():
        state = item.get("state")
        if state == "evaluated":
            result_text = f"{item.get('score')}/100 - Evaluated"
        elif state == "not_observed":
            result_text = "N/A - Not observed"
        else:
            result_text = "Limited - No numeric score"

        detail = f"<b>{safe(result_text)}</b><br/>{safe(item.get('note', ''))}"
        category_rows.append([
            Paragraph(safe(name), styles["WS_Body"]),
            Paragraph(detail, styles["WS_Body"]),
        ])

    cat_table = Table(
        category_rows,
        colWidths=[55*mm, CONTENT_W - 55*mm],
        repeatRows=1,
        hAlign="LEFT",
    )
    cat_table.setStyle(TableStyle([
        ("BACKGROUND", (0,0), (-1,0), colors.HexColor("#EAF1F5")),
        ("FONTNAME", (0,0), (-1,0), "Helvetica-Bold"),
        ("VALIGN", (0,0), (-1,-1), "TOP"),
        ("GRID", (0,0), (-1,-1), 0.35, colors.HexColor("#CAD7DE")),
        ("LEFTPADDING", (0,0), (-1,-1), 6),
        ("RIGHTPADDING", (0,0), (-1,-1), 6),
        ("TOPPADDING", (0,0), (-1,-1), 6),
        ("BOTTOMPADDING", (0,0), (-1,-1), 6),
    ]))
    story.append(cat_table)

    # CIA qualitative
    story.append(Paragraph("CIA Triad - Qualitative Impact", styles["WS_H1"]))
    story.append(Paragraph(
        "WebShield does not assign CIA percentages because a passive public-page scan cannot measure Confidentiality, "
        "Integrity, or Availability precisely.",
        styles["WS_Body"]
    ))

    for name, item in result.get("cia", {}).items():
        block = [
            Paragraph(f"<b>{safe(name)}</b> - {safe(item.get('level', ''))}", styles["WS_H2"]),
            Paragraph(safe(item.get("status", "")), styles["WS_Body"]),
            Paragraph(safe(item.get("explanation", "")), styles["WS_Body"]),
        ]
        related = item.get("related_findings", [])
        if related:
            block.append(Paragraph(
                "<b>Related findings:</b> " + safe("; ".join(related)),
                styles["WS_Small"]
            ))
        block.append(Spacer(1, 4))
        story.append(KeepTogether(block))

    # Action plan
    actionable = [
        f for f in result.get("findings", [])
        if f.get("status") == "Confirmed Configuration Finding"
        and f.get("severity") != "Info"
    ]
    story.append(Paragraph("Practical Action Plan", styles["WS_H1"]))
    if actionable:
        for idx, f in enumerate(actionable[:10], 1):
            story.append(KeepTogether([
                Paragraph(
                    f"{idx}. <b>{safe(f.get('friendly_title') or f.get('title'))}</b>",
                    styles["WS_H2"]
                ),
                Paragraph(
                    "<b>Recommended action:</b> " + safe(f.get("recommendation", "")),
                    styles["WS_Body"]
                ),
                Spacer(1, 3),
            ]))
    else:
        story.append(Paragraph(
            "No confirmed actionable configuration finding was recorded.",
            styles["WS_Body"]
        ))

    story.append(Paragraph(
        "<b>Preserve functionality:</b> Security settings such as CSP, CORS, cookie policies and browser headers "
        "should be tailored to the website's actual scripts, forms, APIs, fonts, analytics, embeds and integrations. "
        "A higher score is not worth breaking a working website.",
        styles["WS_Callout"]
    ))

    # Findings
    story.append(PageBreak())
    story.append(Paragraph("Detailed Findings", styles["WS_H1"]))
    findings = result.get("findings", [])

    if not findings:
        story.append(Paragraph(
            "No finding was recorded by the checks performed.",
            styles["WS_Body"]
        ))
    else:
        for idx, f in enumerate(findings, 1):
            story.append(Paragraph(
                f"{idx}. {safe(f.get('friendly_title') or f.get('title'))}",
                styles["WS_H1"]
            ))
            story.append(kv_table([
                ("Category", f.get("category", "")),
                ("Severity", f.get("severity", "")),
                ("Confidence", f.get("confidence", "")),
                ("Status", f.get("status", "")),
            ], styles, key_width=32*mm))

            story.append(Paragraph("What WebShield observed", styles["WS_H2"]))
            story.append(Paragraph(safe(f.get("what_it_means", "")), styles["WS_Body"]))

            story.append(Paragraph("Why it matters", styles["WS_H2"]))
            story.append(Paragraph(safe(f.get("why_care", "")), styles["WS_Body"]))

            story.append(Paragraph("Does this prove the website is hacked?", styles["WS_H2"]))
            story.append(Paragraph(safe(f.get("does_it_mean_hacked", "")), styles["WS_Body"]))

            story.append(Paragraph("Recommended action", styles["WS_H2"]))
            story.append(Paragraph(safe(f.get("recommendation", "")), styles["WS_Body"]))

            if f.get("evidence"):
                story.append(Paragraph("Technical evidence", styles["WS_H2"]))
                story.append(Paragraph(safe(f.get("evidence", "")), styles["WS_Small"]))

            story.append(Paragraph(
                "<b>Technical finding:</b> " + safe(f.get("title", "")) +
                "<br/><b>Technical explanation:</b> " + safe(f.get("technical_description", "")) +
                "<br/><b>Finding ID:</b> " + safe(f.get("code", "")),
                styles["WS_Small"]
            ))
            story.append(HRFlowable(
                width="100%", thickness=0.4,
                color=colors.HexColor("#D8E1E6"),
                spaceBefore=6, spaceAfter=8
            ))

    # Technical snapshot
    story.append(PageBreak())
    story.append(Paragraph("Technical Snapshot", styles["WS_H1"]))
    tls = result.get("tls", {})
    story.append(kv_table([
        ("HTTPS enabled", "Yes" if tls.get("enabled") else "No"),
        ("Certificate valid", "Yes" if tls.get("valid") else "No"),
        ("TLS protocol", tls.get("protocol") or "Not available"),
        ("Cipher", tls.get("cipher") or "Not available"),
        ("Certificate subject", tls.get("subject") or "Not available"),
        ("Certificate issuer", tls.get("issuer") or "Not available"),
        ("Days remaining", tls.get("days_remaining") if tls.get("days_remaining") is not None else "Not available"),
        ("Forms observed", len(result.get("forms", []))),
        ("Cookies observed", len(result.get("cookies", []))),
        ("External domains", len(result.get("external_domains", []))),
        ("Mixed-content resources", len(result.get("mixed_content", []))),
        ("Third-party scripts", len(result.get("third_party_scripts", []))),
    ], styles))

    tech = result.get("technologies", [])
    story.append(Paragraph("Observed technology indicators", styles["WS_H2"]))
    story.append(Paragraph(
        safe(", ".join(tech) if tech else "No clear technology signature was detected."),
        styles["WS_Body"]
    ))

    # AI prompt as appendix, not in main report body.
    story.append(PageBreak())
    story.append(Paragraph("Appendix A - AI Remediation Prompt", styles["WS_H1"]))
    story.append(Paragraph(
        "This prompt is optional. It is designed to request feature-preserving remediation guidance. "
        "Any generated change should still be reviewed, tested and deployed carefully.",
        styles["WS_Body"]
    ))
    prompt = result.get("ai_remediation_prompt", "")
    for line in str(prompt).splitlines():
        if not line.strip():
            story.append(Spacer(1, 4))
        else:
            story.append(Paragraph(safe(line), styles["WS_Small"]))

    # Glossary
    story.append(PageBreak())
    story.append(Paragraph("Appendix B - Security Terms Explained", styles["WS_H1"]))
    for term, info in result.get("glossary", {}).items():
        story.append(KeepTogether([
            Paragraph(safe(term), styles["WS_H2"]),
            Paragraph(safe(info.get("simple", "")), styles["WS_Body"]),
            Paragraph(
                "<i>Simple example:</i> " + safe(info.get("analogy", "")),
                styles["WS_Small"]
            ),
            Spacer(1, 4),
        ]))

    story.append(Paragraph(
        "<b>Scope limitation:</b> WebShield performs selected passive checks against publicly observable website behavior. "
        "It does not replace penetration testing, source-code review, authentication and authorization testing, "
        "dependency analysis, server/infrastructure assessment, business-logic testing or availability engineering.",
        styles["WS_Callout"]
    ))

    doc.build(
        story,
        onFirstPage=add_page_number,
        onLaterPages=add_page_number,
    )
