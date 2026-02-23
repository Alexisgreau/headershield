from __future__ import annotations

import csv
import io
from xml.sax.saxutils import escape as xml_escape

from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import getSampleStyleSheet
from reportlab.platypus import Paragraph, SimpleDocTemplate, Spacer

from ..models.finding import CookieFinding, HeaderFinding, HTMLFinding
from ..models.scan import Scan


def export_csv(
    scan: Scan,
    header_findings: list[HeaderFinding],
    cookie_findings: list[CookieFinding],
    html_findings: list[HTMLFinding],
) -> bytes:
    buf = io.StringIO()
    writer = csv.writer(buf)
    writer.writerow([
        "header_name",
        "value",
        "status",
        "score_impact",
        "cookie_name",
        "has_secure",
        "has_httponly",
        "samesite",
        "html_finding_type",
        "html_tag",
        "html_details",
    ])
    for hf in header_findings:
        writer.writerow([hf.header_name, hf.value or "", hf.status, hf.score_impact, "", "", "", "", "", "", ""])
    for cf in cookie_findings:
        writer.writerow(["", "", cf.status, "", cf.cookie_name, cf.has_secure, cf.has_httponly, cf.samesite, "", "", ""])
    for hf in html_findings:
        writer.writerow(["", "", "HTML", hf.score_impact, "", "", "", "", hf.finding_type, hf.tag, hf.details])
    return buf.getvalue().encode("utf-8")


def export_pdf(
    scan: Scan,
    header_findings: list[HeaderFinding],
    cookie_findings: list[CookieFinding],
    html_findings: list[HTMLFinding],
) -> bytes:
    """PDF simple (ReportLab) avec échappement basique."""
    buf = io.BytesIO()
    doc = SimpleDocTemplate(buf, pagesize=A4)
    styles = getSampleStyleSheet()
    elems: list = []

    # Titre + résumé
    elems.append(Paragraph(xml_escape(f"HeaderShield Report - Scan #{scan.id}"), styles["Title"]))
    elems.append(Spacer(1, 12))
    target_label = getattr(getattr(scan, "target", None), "url", scan.target_id)
    elems.append(Paragraph(xml_escape(f"Target: {target_label}"), styles["Normal"]))
    elems.append(Paragraph(xml_escape(f"Score: {scan.score_total}"), styles["Normal"]))
    elems.append(Paragraph(xml_escape(f"Status: {scan.status}"), styles["Normal"]))
    elems.append(Spacer(1, 12))

    # Headers
    elems.append(Paragraph(xml_escape("Security Headers"), styles["Heading2"]))
    for hf in header_findings:
        shown_val = hf.value if (hf.value is not None and hf.value != "") else "N/A"
        elems.append(Paragraph(xml_escape(f"{hf.header_name}: {hf.status} ({shown_val})"), styles["Normal"]))
        if hf.recommendation:
            elems.append(Paragraph(xml_escape(f"Recommendation: {hf.recommendation}"), styles["Code"]))
        elems.append(Spacer(1, 6))

    # Cookies
    elems.append(Spacer(1, 12))
    elems.append(Paragraph(xml_escape("Cookies"), styles["Heading2"]))
    for cf in cookie_findings:
        elems.append(Paragraph(
            xml_escape(f"{cf.cookie_name}: secure={cf.has_secure} httponly={cf.has_httponly} samesite={cf.samesite} ({cf.status})"),
            styles["Normal"],
        ))
        if cf.recommendation:
            elems.append(Paragraph(xml_escape(f"Recommendation: {cf.recommendation}"), styles["Code"]))
        elems.append(Spacer(1, 6))

    # HTML Findings
    elems.append(Spacer(1, 12))
    elems.append(Paragraph(xml_escape("HTML Findings"), styles["Heading2"]))
    if not html_findings:
        elems.append(Paragraph(xml_escape("No HTML findings."), styles["Normal"]))
    for hf in html_findings:
        elems.append(Paragraph(xml_escape(f"{hf.finding_type} on <{hf.tag}>: {hf.details}"), styles["Normal"]))
        if hf.recommendation:
            elems.append(Paragraph(xml_escape(f"Recommendation: {hf.recommendation}"), styles["Code"]))
        elems.append(Spacer(1, 6))

    # Meta brute
    elems.append(Spacer(1, 12))
    elems.append(Paragraph(xml_escape("Meta"), styles["Heading2"]))
    elems.append(Paragraph(xml_escape(str(scan.raw_response_meta)), styles["Code"]))

    doc.build(elems)
    return buf.getvalue()

