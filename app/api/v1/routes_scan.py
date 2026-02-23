from __future__ import annotations

from fastapi import APIRouter, HTTPException
from sqlmodel import select

from ...core.database import get_session
from ...models.finding import CookieFinding, HeaderFinding, HTMLFinding
from ...models.scan import Scan
from ...schemas.scan import ScanRequest
from ...services.scanner import scan_urls

router = APIRouter(tags=["scan"])  # Regroupe les routes liées au scan


# Lance un scan direct (await) sur une liste d'URLs
@router.post("/scan")
async def post_scan(payload: ScanRequest) -> dict:
    # un peu de garde-fous côté API (même si validé côté schéma)
    if not payload.urls:
        raise HTTPException(status_code=400, detail={"error": "No URLs provided"})
    if len(payload.urls) > 100:
        raise HTTPException(status_code=400, detail={"error": "Too many URLs (max 100)"})

    # on lance le scan (async httpx, pas de file/queue ici)
    results = await scan_urls(payload.urls)

    # simple retour: pas de job manager, juste un résumé immédiat
    return {"job_id": 0, "summary": results}


# Récupère le détail d'un scan (score, findings, cookies, méta)
@router.get("/scan/{scan_id}")
def get_scan(scan_id: int):
    with get_session() as session:
        # on charge le scan, 404 si inconnu
        scan = session.get(Scan, scan_id)
        if not scan:
            raise HTTPException(status_code=404, detail={"error": "Scan not found"})

        # findings chargés explicitement (pas de relationship auto pour éviter les soucis SQLAlchemy 2.x)
        header_findings = session.exec(select(HeaderFinding).where(HeaderFinding.scan_id == scan.id)).all()
        cookie_findings = session.exec(select(CookieFinding).where(CookieFinding.scan_id == scan.id)).all()
        html_findings = session.exec(select(HTMLFinding).where(HTMLFinding.scan_id == scan.id)).all()
        # on renvoie une structure prête à consommer côté UI/API
        return {
            "id": scan.id,
            "target_id": scan.target_id,  # cible associée
            "score_total": scan.score_total,  # score global 0–100
            "issues_count": scan.issues_count,  # nb d'issues agrégées
            "tls_enforced": scan.tls_enforced,  # HTTPS dispo
            "http_to_https_redirect": scan.http_to_https_redirect,  # redirection HTTP→HTTPS
            "status": scan.status,
            "started_at": scan.started_at,
            "finished_at": scan.finished_at,
            "header_findings": [
                {
                    "header_name": hf.header_name,
                    "value": hf.value,
                    "status": hf.status,  # MISSING | WEAK | OK
                    "score_impact": hf.score_impact,  # pénalité appliquée
                    "recommendation": hf.recommendation,  # snippet/config utile
                }
                for hf in header_findings
            ],
            "cookie_findings": [
                {
                    "cookie_name": cf.cookie_name,
                    "has_secure": cf.has_secure,
                    "has_httponly": cf.has_httponly,
                    "samesite": cf.samesite,
                    "status": cf.status,  # OK | WEAK
                    "recommendation": cf.recommendation,
                }
                for cf in cookie_findings
            ],
            "html_findings": [
                {
                    "finding_type": hf.finding_type,
                    "tag": hf.tag,
                    "details": hf.details,
                    "score_impact": hf.score_impact,
                    "recommendation": hf.recommendation,
                }
                for hf in html_findings
            ],
            "raw_response_meta": scan.raw_response_meta,  # infos brutes (headers, history, tls, ...)
        }
