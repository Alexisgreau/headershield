from __future__ import annotations

# barème centralisé (facile à ajuster/étendre)
RULES: dict[str, dict[str, int]] = {
    "CSP": {"missing": 25, "weak": 10},
    "HSTS": {"missing": 10, "weak": 10, "bonus_full": 2},
    "XFO": {"missing": 5, "weak": 3},
    "XCTO": {"missing": 5, "weak": 3},
    "Referrer": {"missing": 3, "weak": 1},
    "Permissions": {"missing": 2, "weak": 1},
    "Isolation": {"missing_each": 2, "bonus_trio": 2},
    "Cookies": {"no_secure": 5, "no_httponly": 3, "none_without_secure": 7, "cap_secure": 15, "cap_httponly": 9},
    "Redirect": {"no_https": 10},
}


def clamp(score: int) -> int:
    return max(0, min(100, score))


def is_csp_weak(value: str | None) -> bool:
    # heuristique simple: on traque les patterns risqués
    if not value:
        return True
    v = value.lower()
    if "default-src *" in v:
        return True
    if "unsafe-inline" in v and ("nonce-" not in v and "hash-" not in v):
        return True
    if "unsafe-eval" in v:
        return True
    if "default-src" not in v:
        return True
    return False


def evaluate_header(header: str, value: str | None) -> tuple[str, int]:
    # renvoie (statut, pénalité) pour un header donné
    if header == "Content-Security-Policy":
        if value is None:
            return "MISSING", RULES["CSP"]["missing"]
        if is_csp_weak(value):
            return "WEAK", RULES["CSP"]["weak"]
        return "OK", 0
    if header == "Strict-Transport-Security":
        if value is None:
            return "MISSING", RULES["HSTS"]["missing"]
        v = value.lower()
        try:
            parts = dict(part.split("=") for part in v.split(";") if "=" in part)
            max_age = int(parts.get("max-age", "0"))
        except Exception:
            max_age = 0
        if max_age < 15552000:
            return "WEAK", RULES["HSTS"]["weak"]
        return "OK", 0
    if header == "X-Frame-Options":
        if value is None:
            return "MISSING", RULES["XFO"]["missing"]
        v = value.upper()
        if v not in {"DENY", "SAMEORIGIN"}:
            return "WEAK", RULES["XFO"]["weak"]
        return "OK", 0
    if header == "X-Content-Type-Options":
        if value is None:
            return "MISSING", RULES["XCTO"]["missing"]
        if value.lower().strip() != "nosniff":
            return "WEAK", RULES["XCTO"]["weak"]
        return "OK", 0
    if header == "Referrer-Policy":
        if value is None:
            return "MISSING", RULES["Referrer"]["missing"]
        weak_vals = {"no-referrer-when-downgrade", "unsafe-url"}
        if value.lower().strip() in weak_vals:
            return "WEAK", RULES["Referrer"]["weak"]
        return "OK", 0
    if header == "Permissions-Policy":
        if value is None:
            return "MISSING", RULES["Permissions"]["missing"]
        # heuristic: allowlist empty is good; wildcard or * indicates weak
        if "*" in value:
            return "WEAK", RULES["Permissions"]["weak"]
        return "OK", 0
    if header in {"Cross-Origin-Opener-Policy", "Cross-Origin-Embedder-Policy", "Cross-Origin-Resource-Policy"}:
        if value is None:
            return "MISSING", RULES["Isolation"]["missing_each"]
        return "OK", 0
    # Informational headers: Server, X-Powered-By – no score impact here
    return "OK", 0

