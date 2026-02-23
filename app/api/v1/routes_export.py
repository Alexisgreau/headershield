from __future__ import annotations

from fastapi import APIRouter, HTTPException, Response
from sqlmodel import select

from ...core.database import get_session
from ...models.finding import CookieFinding, HeaderFinding, HTMLFinding
from ...models.scan import Scan
from ...services.exports import export_csv, export_pdf

router = APIRouter(prefix="/export", tags=["export"])


@router.get("/csv")
def export_csv_endpoint(scan_id: int):
    with get_session() as session:
        scan = session.get(Scan, scan_id)
        if not scan:
            raise HTTPException(status_code=404, detail={"error": "Scan not found"})
        header_findings = list(session.exec(select(HeaderFinding).where(HeaderFinding.scan_id == scan.id)).all())
        cookie_findings = list(session.exec(select(CookieFinding).where(CookieFinding.scan_id == scan.id)).all())
        html_findings = list(session.exec(select(HTMLFinding).where(HTMLFinding.scan_id == scan.id)).all())
        content = export_csv(scan, list(header_findings), list(cookie_findings), list(html_findings))
        return Response(content, media_type="text/csv", headers={"Content-Disposition": f"attachment; filename=scan_{scan_id}.csv"})


@router.get("/pdf")
def export_pdf_endpoint(scan_id: int):
    with get_session() as session:
        scan = session.get(Scan, scan_id)
        if not scan:
            raise HTTPException(status_code=404, detail={"error": "Scan not found"})
        header_findings = list(session.exec(select(HeaderFinding).where(HeaderFinding.scan_id == scan.id)).all())
        cookie_findings = list(session.exec(select(CookieFinding).where(CookieFinding.scan_id == scan.id)).all())
        html_findings = list(session.exec(select(HTMLFinding).where(HTMLFinding.scan_id == scan.id)).all())
        content = export_pdf(scan, list(header_findings), list(cookie_findings), list(html_findings))
        return Response(content, media_type="application/pdf", headers={"Content-Disposition": f"attachment; filename=scan_{scan_id}.pdf"})
