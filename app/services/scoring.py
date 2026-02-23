from __future__ import annotations

# barème centralisé (facile à ajuster/étendre)
RULES: dict[str, dict[str, int | dict[str, int]]] = {
    "CSP": {
        "missing": 25,
        "weaknesses": {
            "script-src-unsafe-inline": 10,
            "unsafe-eval": 8,
            "wildcard": 5,
            "missing-object-src": 3,
            "missing-base-uri": 3,
        },
    },
    "HSTS": {"missing": 10, "weak": 10, "bonus_full": 2},
    "XFO": {"missing": 5, "weak": 3},
    "XCTO": {"missing": 5, "weak": 3},
    "Referrer": {"missing": 3, "weak": 1},
    "Permissions": {"missing": 2, "weak": 1},
    "Isolation": {"missing_each": 2, "bonus_trio": 2},
    "Cookies": {"no_secure": 5, "no_httponly": 3, "none_without_secure": 7, "cap_secure": 15, "cap_httponly": 9},
    "Redirect": {"no_https": 10},
    "InfoLeak": {"present": 2},
    "HTML": {"mixed-content": 4, "sri-missing": 2},
    # Legacy headers are informative by default: they do not penalize if absent,
    # but still penalize weak values when provided.
    "LegacyPolicies": {"weak_x_permitted": 1},
    "LegacyPolicies": {"missing_x_permitted": 1, "weak_x_permitted": 1, "missing_clear_site_data": 1},
}


def clamp(score: int) -> int:
    return max(0, min(100, score))


def evaluate_csp(value: str | None) -> tuple[int, list[str]]:
    """Evaluates a CSP header and returns a penalty score and a list of weaknesses."""
    if not value:
        # CSP is missing, handled by the main function
        return 0, []

    penalty = 0
    weaknesses: list[str] = []

    # Robust parsing: tolerate directives without a value (e.g. "upgrade-insecure-requests").
    directives: dict[str, str] = {}
    for directive in value.split(";"):
        item = directive.strip()
        if not item:
            continue
        parts = item.split(maxsplit=1)
        key = parts[0].lower()
        val = parts[1] if len(parts) > 1 else ""
        directives[key] = val

    script_src = directives.get("script-src", directives.get("default-src", ""))

    # Check for unsafe-inline in script-src
    if "'unsafe-inline'" in script_src and "'nonce-" not in script_src and "'sha" not in script_src:
        penalty += RULES["CSP"]["weaknesses"]["script-src-unsafe-inline"]
        weaknesses.append("script-src allows 'unsafe-inline' without using hashes or nonces, which severely weakens XSS protection.")

    # Check for unsafe-eval in script-src
    if "'unsafe-eval'" in script_src:
        penalty += RULES["CSP"]["weaknesses"]["unsafe-eval"]
        weaknesses.append("script-src allows 'unsafe-eval', which can lead to arbitrary code execution from strings.")

    # Check for wildcard source in script-src
    if "*" in script_src or "http:" in script_src or "https:" in script_src:
        penalty += RULES["CSP"]["weaknesses"]["wildcard"]
        weaknesses.append("script-src is overly permissive. Avoid wildcards (*) and broad schemes (http:, https:).")

    # Check for missing object-src (very important to mitigate plugin-based attacks)
    if "object-src" not in directives:
        penalty += RULES["CSP"]["weaknesses"]["missing-object-src"]
        weaknesses.append("object-src directive is missing. It is highly recommended to set it to 'none' to prevent plugin execution.")
    elif "'none'" not in directives.get("object-src", ""):
        penalty += RULES["CSP"]["weaknesses"]["missing-object-src"]
        weaknesses.append("object-src should be set to 'none' to prevent execution of plugins like Flash.")

    # Check for missing base-uri
    if "base-uri" not in directives:
        penalty += RULES["CSP"]["weaknesses"]["missing-base-uri"]
        weaknesses.append("base-uri directive is missing. Consider setting it to 'self' or a specific origin to prevent base URI hijacking attacks.")

    return penalty, weaknesses


def evaluate_header(header: str, value: str | None) -> tuple[str, int, list[str]]:
    """Returns (status, penalty, details) for a given header."""
    if header == "Content-Security-Policy":
        if not value:
            return "MISSING", RULES["CSP"]["missing"], ["Content-Security-Policy header is missing."]

        penalty, details = evaluate_csp(value)
        if penalty > 0:
            return "WEAK", penalty, details
        return "OK", 0, []

    details: list[str] = []

    if header == "Strict-Transport-Security":
        if value is None:
            return "MISSING", RULES["HSTS"]["missing"], []
        v = value.lower()
        try:
            parts = {p.split("=", 1)[0].strip(): p.split("=", 1)[1].strip() if "=" in p else True for p in v.split(";")}
            max_age = int(parts.get("max-age", "0"))
        except (ValueError, IndexError):
            max_age = 0
        if max_age < 15552000:
            details = [f"HSTS max-age is {max_age}s, which is less than the recommended 6 months (15552000s)."]
            return "WEAK", RULES["HSTS"]["weak"], details
        return "OK", 0, []

    if header == "X-Frame-Options":
        if value is None:
            return "MISSING", RULES["XFO"]["missing"], []
        v = value.upper()
        if v not in {"DENY", "SAMEORIGIN"}:
            details = [f"X-Frame-Options is set to '{value}', which is less secure than 'DENY' or 'SAMEORIGIN'."]
            return "WEAK", RULES["XFO"]["weak"], details
        return "OK", 0, []

    if header == "X-Content-Type-Options":
        if value is None:
            return "MISSING", RULES["XCTO"]["missing"], []
        if value.lower().strip() != "nosniff":
            details = [f"X-Content-Type-Options is '{value}' but should be 'nosniff'."]
            return "WEAK", RULES["XCTO"]["weak"], details
        return "OK", 0, []

    if header == "Referrer-Policy":
        if value is None:
            return "MISSING", RULES["Referrer"]["missing"], []
        weak_vals = {"no-referrer-when-downgrade", "unsafe-url"}
        if value.lower().strip() in weak_vals:
            details = [f"Referrer-Policy '{value}' is considered weak as it can leak information on navigations."]
            return "WEAK", RULES["Referrer"]["weak"], details
        return "OK", 0, []

    if header == "Permissions-Policy":
        if value is None:
            return "MISSING", RULES["Permissions"]["missing"], []
        if "*" in value:
            details = ["Permissions-Policy contains a wildcard '*' which is overly permissive. Define fine-grained policies instead."]
            return "WEAK", RULES["Permissions"]["weak"], details
        return "OK", 0, []

    if header in {"Cross-Origin-Opener-Policy", "Cross-Origin-Embedder-Policy", "Cross-Origin-Resource-Policy"}:
        if value is None:
            return "MISSING", RULES["Isolation"]["missing_each"], [f"The isolation header '{header}' is missing."]
        return "OK", 0, []

    if header in {"Server", "X-Powered-By"}:
        if value is not None:
            details = [f"The '{header}' header reveals potentially sensitive information about the server technology ('{value}')."]
            return "PRESENT", RULES["InfoLeak"]["present"], details
        return "OK", 0, []

    if header == "X-Permitted-Cross-Domain-Policies":
        if value is None:
            return "INFO", 0, []
            return "MISSING", RULES["LegacyPolicies"]["missing_x_permitted"], []
        if value.lower().strip() not in {"none", "master-only"}:
            return (
                "WEAK",
                RULES["LegacyPolicies"]["weak_x_permitted"],
                ["Use 'none' (recommended) or 'master-only' to limit Adobe cross-domain policy exposure."],
                [
                    "Use 'none' (recommended) or 'master-only' to limit Adobe cross-domain policy exposure."
                ],
            )
        return "OK", 0, []

    if header == "Clear-Site-Data":
        # Informative: useful for logout/privacy workflows but not universally required.
        if value is None:
            return "INFO", 0, []
        return "OK", 0, []

        if value is None:
            return "MISSING", RULES["LegacyPolicies"]["missing_clear_site_data"], []
        return "OK", 0, []

    # Fallback for unhandled headers
    return "OK", 0, []
