import httpx
import pytest
import respx

from app.main import create_app


@pytest.mark.asyncio
async def test_scan_endpoint(monkeypatch):
    app = create_app()
    transport = httpx.ASGITransport(app=app)
    async with httpx.AsyncClient(transport=transport, base_url="http://test") as client:
        with respx.mock(base_url="https://example.com") as mock:
            mock.get("/").respond(
                200,
                headers={
                    "Content-Security-Policy": "default-src 'self'",
                    "Strict-Transport-Security": "max-age=15552000; includeSubDomains; preload",
                    "X-Frame-Options": "DENY",
                    "X-Content-Type-Options": "nosniff",
                    "Referrer-Policy": "no-referrer",
                },
                text="ok",
            )
            # http version redirects to https
            respx.get("http://example.com/").respond(301, headers={"Location": "https://example.com/"})

            r = await client.post("/api/v1/scan", json={"urls": ["https://example.com/"]})
            assert r.status_code == 200
            data = r.json()
            assert "summary" in data
            assert any(v >= 50 for v in data["summary"].values())

