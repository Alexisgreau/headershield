from __future__ import annotations

import asyncio
import json
from pathlib import Path

import typer

from .services.scanner import scan_urls

app = typer.Typer(help="HeaderShield CLI")


@app.command()
def scan(urls: str, output: Path | None = typer.Option(None, help="Write JSON results")) -> None:
    """Scan comma-separated URLs."""
    urls_list = [u.strip() for u in urls.split(",") if u.strip()]

    async def _run() -> None:
        results = await scan_urls(urls_list)
        if output:
            output.write_text(json.dumps(results, indent=2))
        else:
            print(json.dumps(results, indent=2))

    asyncio.run(_run())


if __name__ == "__main__":
    app()
