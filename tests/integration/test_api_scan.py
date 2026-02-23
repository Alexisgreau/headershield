import asyncio

import httpx

from app.main import create_app


def test_scan_endpoint(monkeypatch):
    async def fake_scan(urls: list[str]) -> dict[str, int]:
        return {u: 88 for u in urls}

    monkeypatch.setattr("app.api.v1.routes_scan.scan_urls", fake_scan)

    async def _run():
        app = create_app()
        transport = httpx.ASGITransport(app=app)
        async with httpx.AsyncClient(transport=transport, base_url="http://test") as client:
            r = await client.post("/api/v1/scan", json={"urls": ["https://example.com/"]})
            assert r.status_code == 200
            data = r.json()
            assert data["summary"]["https://example.com/"] == 88

    asyncio.run(_run())
