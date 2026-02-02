from __future__ import annotations

NGINX_SNIPPETS = {
    "csp": "add_header Content-Security-Policy \"default-src 'self'; object-src 'none'; base-uri 'self'; frame-ancestors 'self';\" always;",
    "hsts": "add_header Strict-Transport-Security \"max-age=31536000; includeSubDomains; preload\" always;",
    "xfo": "add_header X-Frame-Options DENY always;",
    "xcto": "add_header X-Content-Type-Options nosniff always;",
    "referrer": "add_header Referrer-Policy no-referrer always;",
    "permissions": "add_header Permissions-Policy \"geolocation=(), microphone=()\" always;",
    "coop": "add_header Cross-Origin-Opener-Policy same-origin always;",
    "coep": "add_header Cross-Origin-Embedder-Policy require-corp always;",
    "corp": "add_header Cross-Origin-Resource-Policy same-site always;",
}

APACHE_SNIPPETS = {
    "csp": "Header always set Content-Security-Policy \"default-src 'self'; object-src 'none'; base-uri 'self'; frame-ancestors 'self';\"",
    "hsts": "Header always set Strict-Transport-Security \"max-age=31536000; includeSubDomains; preload\"",
    "xfo": "Header always set X-Frame-Options DENY",
    "xcto": "Header always set X-Content-Type-Options nosniff",
    "referrer": "Header always set Referrer-Policy no-referrer",
    "permissions": "Header always set Permissions-Policy \"geolocation=(), microphone=()\"",
    "coop": "Header always set Cross-Origin-Opener-Policy same-origin",
    "coep": "Header always set Cross-Origin-Embedder-Policy require-corp",
    "corp": "Header always set Cross-Origin-Resource-Policy same-site",
}


def csp_example() -> str:
    return (
        "Content-Security-Policy: default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-hashes'; "
        "img-src 'self' data:; object-src 'none'; base-uri 'self'; frame-ancestors 'self'"
    )


def recommendation_for(header: str) -> str:
    keymap = {
        "Content-Security-Policy": "csp",
        "Strict-Transport-Security": "hsts",
        "X-Frame-Options": "xfo",
        "X-Content-Type-Options": "xcto",
        "Referrer-Policy": "referrer",
        "Permissions-Policy": "permissions",
        "Cross-Origin-Opener-Policy": "coop",
        "Cross-Origin-Embedder-Policy": "coep",
        "Cross-Origin-Resource-Policy": "corp",
    }
    k = keymap.get(header)
    if not k:
        return ""
    return (
        f"Nginx: {NGINX_SNIPPETS[k]}\n"
        f"Apache: {APACHE_SNIPPETS[k]}\n"
        + ("CSP example: " + csp_example() if k == "csp" else "")
    )

