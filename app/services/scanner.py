from __future__ import annotations

import asyncio
from datetime import datetime
import logging
from http.cookies import SimpleCookie

from sqlalchemy.exc import IntegrityError
from sqlmodel import select

from ..core.database import get_session
from ..models.finding import CookieFinding, HeaderFinding, HTMLFinding
from ..models.scan import Scan
from ..models.target import Target
from .http_client import HTTPService
from .html_parser import analyze_html
from .recommendations import recommendation_for, recommendation_for_html
from .scoring import RULES, clamp, evaluate_header
from .utils import sanitize_url

SECURITY_HEADERS = [
    "Content-Security-Policy",
    "Strict-Transport-Security",
    "X-Frame-Options",
    "X-Content-Type-Options",
    "Referrer-Policy",
    "Permissions-Policy",
    "Cross-Origin-Opener-Policy",
    "Cross-Origin-Embedder-Policy",
    "Cross-Origin-Resource-Policy",
    "Server",
    "X-Powered-By",
    "X-Permitted-Cross-Domain-Policies",
    "Clear-Site-Data",
]

logger = logging.getLogger(__name__)


def _get_or_create_target_id(session, url: str) -> int:
    """Resolve a target id in a concurrency-safe way.

    This function avoids relying on ORM instances outside of the transaction scope
    and gracefully handles duplicate insert races.
    """
    target_id = session.exec(select(Target.id).where(Target.url == url)).first()
    if target_id is not None:
        return target_id

    try:
        target_obj = Target(url=url)
        session.add(target_obj)
        session.commit()
        session.refresh(target_obj)
        assert target_obj.id is not None
        return target_obj.id
    except IntegrityError:
        session.rollback()
        existing_id = session.exec(select(Target.id).where(Target.url == url)).first()
        if existing_id is None:
            raise
        return existing_id


async def _scan_one_url(url: str, http: HTTPService) -> tuple[str, int]:
    with get_session() as session:
        target_id = _get_or_create_target_id(session, url)

        scan_obj = Scan(target_id=target_id, status="RUNNING")
        session.add(scan_obj)
        session.commit()
        session.refresh(scan_obj)
        assert scan_obj.id is not None
        scan_id = scan_obj.id

    http_url = url.replace("https://", "http://") if url.startswith("https://") else url
    https_url = url if url.startswith("https://") else url.replace("http://", "https://")

    resp_https = None
    resp_http = None
    header_values: dict[str, str | None] = {}
    cookie_headers: list[str] = []
    http_redirects_to_https = False
    tls_ok = False
    raw_meta: dict[str, object] = {}

    try:
        resp_https, history_https, tls_version = await http.fetch(https_url)
        tls_ok = resp_https is not None and resp_https.status_code < 599
        raw_meta["https"] = {
            "status": getattr(resp_https, "status_code", None),
            "final_url": str(getattr(resp_https, "url", https_url)),
            "history": history_https,
            "tls_version": tls_version,
            "headers": dict(getattr(resp_https, "headers", {})),
        }
        if resp_https is not None:
            for h in SECURITY_HEADERS:
                header_values[h] = resp_https.headers.get(h)
            cookie_headers.extend(resp_https.headers.get_list("set-cookie"))
    except Exception as exc:
        raw_meta["https_error"] = f"Failed to fetch {https_url}: {exc}"
        logger.warning("HTTPS fetch failed for %s: %s", https_url, exc)

    try:
        resp_http, history_http, _ = await http.fetch(http_url)
        raw_meta["http"] = {
            "status": getattr(resp_http, "status_code", None),
            "final_url": str(getattr(resp_http, "url", http_url)),
            "history": history_http,
            "headers": dict(getattr(resp_http, "headers", {})),
        }
        if resp_http is not None and str(resp_http.url).startswith("https://"):
            http_redirects_to_https = True
    except Exception as exc:
        raw_meta["http_error"] = f"Failed to fetch {http_url}: {exc}"
        logger.warning("HTTP fetch failed for %s: %s", http_url, exc)

    score = 100
    issues = 0
    header_findings: list[HeaderFinding] = []
    html_findings: list[HTMLFinding] = []

    if resp_https and "text/html" in resp_https.headers.get("Content-Type", ""):
        html_body = resp_https.text
        html_issues = analyze_html(html_body, str(resp_https.url))
        for f_type, tag, details in html_issues:
            penalty = int(RULES["HTML"][f_type])
            score -= penalty
            issues += 1
            rec = recommendation_for_html(f_type)
            html_findings.append(
                HTMLFinding(
                    finding_type=f_type,
                    tag=tag,
                    details=details,
                    score_impact=penalty,
                    recommendation=rec,
                )
            )

    for h in SECURITY_HEADERS:
        status, penalty, details = evaluate_header(h, header_values.get(h))
        if penalty > 0:
            issues += 1

        rec = recommendation_for(h) if status != "OK" else ""
        full_rec = f"{rec}\nDETAILS: {' '.join(details)}".strip() if details else rec

        header_findings.append(
            HeaderFinding(
                header_name=h,
                value=header_values.get(h),
                status=status,
                score_impact=penalty,
                recommendation=full_rec,
            )
        )
        score -= penalty

    iso_ok = all(
        (header_values.get(h) is not None)
        for h in (
            "Cross-Origin-Opener-Policy",
            "Cross-Origin-Embedder-Policy",
            "Cross-Origin-Resource-Policy",
        )
    )
    if iso_ok:
        score += int(RULES["Isolation"]["bonus_trio"])

    hsts_val = (header_values.get("Strict-Transport-Security") or "").lower()
    if "includesubdomains" in hsts_val and "preload" in hsts_val:
        score += int(RULES["HSTS"]["bonus_full"])

    if not http_redirects_to_https:
        score -= int(RULES["Redirect"]["no_https"])
        issues += 1

    cookie_findings: list[CookieFinding] = []
    insecure_secure = 0
    insecure_httponly = 0
    for line in cookie_headers:
        cookie = SimpleCookie()
        try:
            cookie.load(line)
        except Exception:
            continue

        parts = [part.strip() for part in line.split(";")]
        attrs = {part.split("=", 1)[0].lower() for part in parts[1:] if part}
        samesite = "Unknown"
        for part in parts:
            if part.lower().startswith("samesite="):
                samesite = part.split("=", 1)[1].strip()
                break

        for name, _morsel in cookie.items():
            has_secure = "secure" in attrs
            has_httponly = "httponly" in attrs

            status = "OK"
            rec = ""
            if tls_ok and not has_secure:
                insecure_secure += 1
                status = "WEAK"
                rec += "Set 'Secure' for cookies on HTTPS. "
            if not has_httponly:
                insecure_httponly += 1
                status = "WEAK"
                rec += "Set 'HttpOnly' to mitigate XSS. "
            if samesite.lower() == "none" and not has_secure:
                status = "WEAK"
                rec += "SameSite=None requires Secure. "

            cookie_findings.append(
                CookieFinding(
                    cookie_name=name,
                    has_secure=has_secure,
                    has_httponly=has_httponly,
                    samesite=samesite or "Unknown",
                    status=status,
                    recommendation=rec.strip(),
                )
            )

    score -= min(insecure_secure * int(RULES["Cookies"]["no_secure"]), int(RULES["Cookies"]["cap_secure"]))
    score -= min(
        insecure_httponly * int(RULES["Cookies"]["no_httponly"]),
        int(RULES["Cookies"]["cap_httponly"]),
    )

    score = clamp(score)

    with get_session() as session:
        target_db = session.get(Target, target_id)
        assert target_db is not None
        scan_db = session.get(Scan, scan_id)
        assert scan_db is not None
        scan_db.score_total = score
        scan_db.issues_count = issues
        scan_db.tls_enforced = bool(tls_ok)
        scan_db.http_to_https_redirect = bool(http_redirects_to_https)
        if not raw_meta.get("https") and not raw_meta.get("http"):
            scan_db.status = "FAIL"
        elif not raw_meta.get("https"):
            scan_db.status = "PARTIAL"
        else:
            scan_db.status = "SUCCESS"
        scan_db.finished_at = datetime.utcnow()
        raw_meta["score_breakdown"] = {
            "final_score": score,
            "issues_count": issues,
            "cookie_flags_missing_secure": insecure_secure,
            "cookie_flags_missing_httponly": insecure_httponly,
        }
        scan_db.raw_response_meta = raw_meta

        for hf in header_findings:
            hf.scan_id = scan_db.id  # type: ignore[arg-type]
            session.add(hf)
        for cf in cookie_findings:
            cf.scan_id = scan_db.id  # type: ignore[arg-type]
            session.add(cf)
        for html_f in html_findings:
            html_f.scan_id = scan_db.id  # type: ignore[arg-type]
            session.add(html_f)

        target_db.last_scanned_at = scan_db.finished_at
        session.add(target_db)
        session.add(scan_db)
        session.commit()

    return url, score


async def scan_urls(urls: list[str]) -> dict[str, int]:
    clean_urls = [u for u in (sanitize_url(u) for u in urls) if u]
    if not clean_urls:
        return {}

    http = HTTPService()
    semaphore = asyncio.Semaphore(5)

    async def _bounded_scan(url: str) -> tuple[str, int]:
        async with semaphore:
            return await _scan_one_url(url, http)

    results = await asyncio.gather(*(_bounded_scan(url) for url in clean_urls))
    return {url: score for url, score in results}
