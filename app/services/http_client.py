from __future__ import annotations

import asyncio
import logging

import httpx

from ..core.config import settings


class HTTPService:
    # petit wrapper httpx: timeouts, retries, UA, redirects
    def __init__(self) -> None:
        self.timeout = settings.request_timeout_seconds
        self.retries = settings.retries
        self.logger = logging.getLogger(__name__)

    async def fetch(self, url: str) -> tuple[httpx.Response | None, list[str], str | None]:
        history: list[str] = []
        tls_version: str | None = None
        last_exc: Exception | None = None
        limits = httpx.Limits(max_connections=10, max_keepalive_connections=5)
        headers = {"User-Agent": "HeaderShield/0.1 (+https://example.local)"}
        async with httpx.AsyncClient(
            follow_redirects=True,
            timeout=self.timeout,
            limits=limits,
            headers=headers,
            max_redirects=10,
        ) as client:
            for attempt in range(self.retries):
                try:
                    resp = await client.get(url)
                    self.logger.info(
                        "Fetched %s -> %s (status=%s, attempt=%s)",
                        url,
                        resp.url,
                        resp.status_code,
                        attempt + 1,
                    )
                    # record history
                    history = [str(r.url) for r in resp.history] + [str(resp.url)]
                    # best-effort TLS version (if https)
                    if resp.url.scheme == "https":
                        try:
                            tls = resp.extensions.get("tls_version")
                            if tls:
                                tls_version = str(tls)
                        except Exception:
                            tls_version = None
                    return resp, history, tls_version
                except Exception as exc:  # network errors
                    last_exc = exc
                    self.logger.warning(
                        "Fetch failed for %s (attempt %s/%s): %s",
                        url,
                        attempt + 1,
                        self.retries,
                        exc,
                    )
                    await asyncio.sleep(0.5 * (2**attempt))
        raise httpx.HTTPError(f"Failed to fetch {url}: {last_exc}")
