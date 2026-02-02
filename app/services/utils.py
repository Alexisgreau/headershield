from __future__ import annotations

import ipaddress
import re
import socket
from urllib.parse import urlparse

_SCHEME_RE = re.compile(r"^https?://", re.I)


def _hostname_to_ips(host: str) -> list[str]:
    # on résout le hostname -> IPs (IPv4/IPv6) pour filtrer les réseaux privés
    try:
        infos = socket.getaddrinfo(host, None)
        ips: list[str] = []
        for _family, _type, _proto, _canonname, sockaddr in infos:
            ip: str = str(sockaddr[0])
            ips.append(ip)
        return list(sorted(set(ips)))
    except Exception:
        return []


def _is_ip_safe(ip: str) -> bool:
    # on refuse private/loopback/link-local/etc. pour éviter SSRF
    try:
        addr = ipaddress.ip_address(ip)
        if addr.is_private or addr.is_loopback or addr.is_link_local or addr.is_multicast or addr.is_reserved or addr.is_unspecified:
            return False
        return True
    except ValueError:
        return False


def sanitize_url(raw: str) -> str | None:
    # normalise et filtre une URL utilisateur (schéma/port/SSRF)
    raw = raw.strip()
    if not raw:
        return None
    if raw.lower().startswith(("file://", "ftp://")):
        return None
    if not _SCHEME_RE.match(raw):
        raw = "https://" + raw
    parsed = urlparse(raw)
    if not parsed.netloc:
        return None
    # restrict to allowed ports 80/443 only
    host = parsed.hostname or ""
    port = parsed.port or (443 if parsed.scheme == "https" else 80)
    if port not in (80, 443):
        return None
    # SSRF protection: block private / loopback / link-local targets
    ips = _hostname_to_ips(host)
    if not ips:
        return None
    if not all(_is_ip_safe(ip) for ip in ips):
        return None
    return f"{parsed.scheme}://{parsed.netloc}{parsed.path or ''}"


def normalize_header_name(name: str) -> str:
    return "-".join(part.capitalize() for part in name.split("-"))
