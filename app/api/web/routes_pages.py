from __future__ import annotations

from fastapi import APIRouter, Form, HTTPException, Request
from fastapi.responses import HTMLResponse, RedirectResponse
from fastapi.templating import Jinja2Templates
from sqlalchemy import desc
from sqlmodel import select

from ...core.database import get_session
from ...models.finding import CookieFinding, HeaderFinding
from ...models.scan import Scan
from ...models.target import Target
from ...services.scanner import scan_urls

router = APIRouter()
templates = Jinja2Templates(directory="app/web/templates")


@router.get("/", response_class=HTMLResponse)
def index(request: Request):
    return templates.TemplateResponse("index.html", {"request": request})


@router.post("/scan", response_class=HTMLResponse)
async def scan_submit(request: Request, urls: str = Form("")):
    arr = [u.strip() for u in urls.splitlines() if u.strip()]
    if not arr:
        raise HTTPException(status_code=400, detail="Provide at least one URL")
    await scan_urls(arr)
    return RedirectResponse(url="/results", status_code=303)


@router.get("/results", response_class=HTMLResponse)
def results(request: Request, min_score: int | None = None, status: str | None = None):
    with get_session() as session:
        stmt = select(Scan).order_by(desc(Scan.started_at))
        scans = session.exec(stmt).all()
        if min_score is not None:
            scans = [s for s in scans if s.score_total >= min_score]
        if status:
            scans = [s for s in scans if s.status == status]
        # on affiche l'URL de la cible: on précharge les Target nécessaires
        target_ids_raw = {s.target_id for s in scans}
        target_ids = [tid for tid in target_ids_raw if tid is not None]
        targets = session.exec(select(Target).where(Target.id.in_(target_ids))).all() if target_ids else []
        targets_by_id = {t.id: t.url for t in targets}
        # on compte quelques métriques utiles (missing/weak/cookies)
        issues_by_scan: dict[int, dict[str, int]] = {}
        for s in scans:
            hfs = session.exec(select(HeaderFinding).where(HeaderFinding.scan_id == s.id)).all()
            cfs = session.exec(select(CookieFinding).where(CookieFinding.scan_id == s.id)).all()
            headers_missing = sum(1 for f in hfs if f.status == "MISSING")
            headers_weak = sum(1 for f in hfs if f.status == "WEAK")
            cookies_weak = sum(1 for f in cfs if f.status != "OK")
            total_issues = headers_missing + headers_weak + cookies_weak
            issues_by_scan[int(s.id)] = {
                "headers_missing": headers_missing,
                "headers_weak": headers_weak,
                "cookies_weak": cookies_weak,
                "total": total_issues,
            }
        return templates.TemplateResponse(
            "results.html",
            {
                "request": request,
                "scans": scans,
                "targets_by_id": targets_by_id,
                "issues_by_scan": issues_by_scan,
            },
        )


@router.get("/scan/{scan_id}", response_class=HTMLResponse)
def scan_detail(request: Request, scan_id: int):
    with get_session() as session:
        scan = session.get(Scan, scan_id)
        if not scan:
            raise HTTPException(status_code=404, detail="Scan not found")
        from ...models.finding import CookieFinding, HeaderFinding
        header_findings = session.exec(select(HeaderFinding).where(HeaderFinding.scan_id == scan.id)).all()
        cookie_findings = session.exec(select(CookieFinding).where(CookieFinding.scan_id == scan.id)).all()
        target = session.get(Target, scan.target_id)
        target_url = target.url if target else scan.target_id
        return templates.TemplateResponse(
            "scan_detail.html",
            {
                "request": request,
                "scan": scan,
                "header_findings": header_findings,
                "cookie_findings": cookie_findings,
                "target_url": target_url,
                "raw_meta": scan.raw_response_meta or {},
            },
        )
