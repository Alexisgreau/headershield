from __future__ import annotations

from datetime import datetime
from http.cookies import SimpleCookie

from sqlmodel import select

from ..core.database import get_session
from ..models.finding import CookieFinding, HeaderFinding
from ..models.scan import Scan
from ..models.target import Target
from .http_client import HTTPService
from .recommendations import recommendation_for
from .scoring import RULES, clamp, evaluate_header
from .utils import sanitize_url

# headers que l'on suit + informational
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
]


async def scan_urls(urls: list[str]) -> dict[str, int]:
    # pipeline simple: normalise -> fetch http/https -> score -> persist
    clean_urls = [u for u in (sanitize_url(u) for u in urls) if u]
    http = HTTPService()
    results: dict[str, int] = {}
    for url in clean_urls:
        # find or create Target
        with get_session() as session:
            target_obj = session.exec(select(Target).where(Target.url == url)).first()
            if not target_obj:
                target_obj = Target(url=url)
                session.add(target_obj)
                session.commit()
                session.refresh(target_obj)

            assert target_obj.id is not None
            target_id = target_obj.id

            scan_obj = Scan(target_id=target_id, status="RUNNING")
            session.add(scan_obj)
            session.commit()
            session.refresh(scan_obj)
            assert scan_obj.id is not None
            scan_id = scan_obj.id

        # Perform HTTP(S) checks (on tente https + http pour la redirection)
        http_url = url.replace("https://", "http://") if url.startswith("https://") else url
        https_url = url if url.startswith("https://") else url.replace("http://", "https://")

        header_values: dict[str, str | None] = {}
        cookie_headers: list[str] = []
        http_redirects_to_https = False
        tls_ok = False
        raw_meta: dict[str, object] = {}
        try:
            # fetch HTTPS
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
        except Exception:
            raw_meta["https_error"] = f"Failed to fetch {https_url}"

        try:
            # fetch HTTP (to detect redirect)
            resp_http, history_http, _ = await http.fetch(http_url)
            raw_meta["http"] = {
                "status": getattr(resp_http, "status_code", None),
                "final_url": str(getattr(resp_http, "url", http_url)),
                "history": history_http,
                "headers": dict(getattr(resp_http, "headers", {})),
            }
            if resp_http is not None and str(resp_http.url).startswith("https://"):
                http_redirects_to_https = True
        except Exception:
            raw_meta["http_error"] = f"Failed to fetch {http_url}"

        # Scoring (base 100, pénalités, clamped 0–100)
        score = 100
        issues = 0
        header_findings: list[HeaderFinding] = []

        for h in SECURITY_HEADERS:
            status, penalty = evaluate_header(h, header_values.get(h))
            if penalty > 0:
                issues += 1
            rec = recommendation_for(h) if status != "OK" else ""
            header_findings.append(
                HeaderFinding(
                    header_name=h,
                    value=header_values.get(h),
                    status=status,
                    score_impact=penalty,
                    recommendation=rec,
                )
            )
            score -= penalty

        # Isolation trio bonus
        iso_ok = all(
            (header_values.get(h) is not None)
            for h in (
                "Cross-Origin-Opener-Policy",
                "Cross-Origin-Embedder-Policy",
                "Cross-Origin-Resource-Policy",
            )
        )
        if iso_ok:
            score += RULES["Isolation"]["bonus_trio"]

        # HSTS full bonus
        hsts_val = header_values.get("Strict-Transport-Security") or ""
        if "includeSubDomains" in hsts_val and "preload" in hsts_val:
            score += RULES["HSTS"]["bonus_full"]

        # Redirect penalty
        if not http_redirects_to_https:
            score -= RULES["Redirect"]["no_https"]
            issues += 1

        # Parse cookies (flags Secure/HttpOnly/SameSite)
        cookie_findings: list[CookieFinding] = []
        insecure_secure = 0
        insecure_httponly = 0
        for line in cookie_headers:
            cookie = SimpleCookie()
            try:
                cookie.load(line)
            except Exception:
                continue
            for name, morsel in cookie.items():
                attrs = {k.lower(): True for k in line.split(";")[1:]}
                has_secure = "secure" in attrs
                has_httponly = "httponly" in attrs
                samesite = "Unknown"
                for part in line.split(";"):
                    if part.strip().lower().startswith("samesite="):
                        samesite = part.split("=", 1)[1].strip()
                        break
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

        # Cookie penalties with caps
        score -= min(insecure_secure * RULES["Cookies"]["no_secure"], RULES["Cookies"]["cap_secure"])
        score -= min(
            insecure_httponly * RULES["Cookies"]["no_httponly"], RULES["Cookies"]["cap_httponly"]
        )

        score = clamp(score)

        # Save results
        with get_session() as session:
            target_db = session.get(Target, target_id)
            assert target_db is not None
            scan_db = session.get(Scan, scan_id)
            assert scan_db is not None
            scan_db.score_total = score
            scan_db.issues_count = issues
            scan_db.tls_enforced = bool(tls_ok)
            scan_db.http_to_https_redirect = bool(http_redirects_to_https)
            scan_db.status = "SUCCESS"
            scan_db.finished_at = datetime.utcnow()
            scan_db.raw_response_meta = raw_meta

            for hf in header_findings:
                hf.scan_id = scan_db.id  # type: ignore[arg-type]
                session.add(hf)
            for cf in cookie_findings:
                cf.scan_id = scan_db.id  # type: ignore[arg-type]
                session.add(cf)

            target_db.last_scanned_at = scan_db.finished_at
            session.add(target_db)
            session.add(scan_db)
            session.commit()

        results[url] = score
    return results
