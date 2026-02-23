from __future__ import annotations

import asyncio
import json
from pathlib import Path
from typing import Optional

import typer
from sqlmodel import select

from .core.database import get_session
from .models.scan import Scan
from .models.target import Target
from .services.scanner import scan_urls
from .services.utils import sanitize_url

app = typer.Typer(help="HeaderShield CLI - Audit HTTP security headers.", no_args_is_help=True)
targets_app = typer.Typer(help="Manage scan targets.", no_args_is_help=True)
scans_app = typer.Typer(help="Run scans and view results.", no_args_is_help=True)

app.add_typer(targets_app, name="targets")
app.add_typer(scans_app, name="scans")


@scans_app.command("run")
def scan_cli(
    urls: str = typer.Argument(..., help="Comma-separated URLs to scan."),
    output: Optional[Path] = typer.Option(None, "--output", "-o", help="Write JSON results to a file."),
) -> None:
    """Scan one or more URLs."""
    urls_list = [u.strip() for u in urls.split(",") if u.strip()]
    print(f"🔬 Starting scan for {len(urls_list)} URL(s)...")

    async def _run() -> None:
        results = await scan_urls(urls_list)
        print("✅ Scan complete.")
        if output:
            output.write_text(json.dumps(results, indent=2))
            print(f"📄 Results written to {output}")
        else:
            print(json.dumps(results, indent=2))

    asyncio.run(_run())


@scans_app.command("history")
def scan_history(
    url: str = typer.Argument(..., help="The URL to retrieve history for.")
) -> None:
    """Show the scan history for a specific URL."""
    clean_url = sanitize_url(url)
    if not clean_url:
        print(f"❌ Invalid URL: {url}")
        raise typer.Exit(code=1)

    with get_session() as session:
        target = session.exec(select(Target).where(Target.url == clean_url)).first()
        if not target:
            print(f"🤷 No target found for URL: {clean_url}")
            raise typer.Exit()

        scans = session.exec(
            select(Scan).where(Scan.target_id == target.id).order_by(Scan.started_at.desc())
        ).all()

        if not scans:
            print(f"No scan history found for {clean_url}.")
            raise typer.Exit()
        
        print(f"📜 Scan history for {clean_url}:")
        for s in scans:
            status = "✅" if s.status == "SUCCESS" else "⚠️"
            finished_at_str = s.finished_at.strftime('%Y-%m-%d %H:%M') if s.finished_at else "N/A"
            print(
                f"  - {status} Scan ID: {s.id} | Score: {s.score_total}/100 | Date: {finished_at_str}"
            )


@targets_app.command("list")
def list_targets() -> None:
    """List all stored targets."""
    with get_session() as session:
        targets = session.exec(select(Target)).all()
        if not targets:
            print("No targets found. Add one with 'targets add <url>'.")
            raise typer.Exit()

        print("🎯 Stored Targets:")
        for t in targets:
            last_scanned = t.last_scanned_at.strftime('%Y-%m-%d %H:%M') if t.last_scanned_at else "Never"
            print(f"  - ID: {t.id} | URL: {t.url} | Last Scanned: {last_scanned}")


@targets_app.command("add")
def add_target(url: str = typer.Argument(..., help="URL to add.")):
    """Add a new target to the database."""
    clean_url = sanitize_url(url)
    if not clean_url:
        print(f"❌ Invalid URL: {url}")
        raise typer.Exit(code=1)
    
    with get_session() as session:
        existing = session.exec(select(Target).where(Target.url == clean_url)).first()
        if existing:
            print(f"☑️ Target already exists: {clean_url} (ID: {existing.id})")
            raise typer.Exit()
        
        new_target = Target(url=clean_url)
        session.add(new_target)
        session.commit()
        print(f"✅ Target added: {clean_url}")


@targets_app.command("remove")
def remove_target(url: str = typer.Argument(..., help="URL to remove.")):
    """Remove a target and its associated scans from the database."""
    clean_url = sanitize_url(url)
    if not clean_url:
        print(f"❌ Invalid URL: {url}")
        raise typer.Exit(code=1)

    with get_session() as session:
        target = session.exec(select(Target).where(Target.url == clean_url)).first()
        if not target:
            print(f"🤷 No target found for URL: {clean_url}")
            raise typer.Exit(code=1)
        
        # Manually delete scans to ensure findings are deleted if cascading is set up from scans to findings.
        # This approach is safer if we are unsure about the full cascade path from Target -> Scan -> Findings.
        scans = session.exec(select(Scan).where(Scan.target_id == target.id)).all()
        if scans:
            print(f"Deleting {len(scans)} associated scan(s)...")
            for s in scans:
                session.delete(s)
        
        session.delete(target)
        session.commit()
        print(f"🗑️ Target and all associated scans removed: {clean_url}")


if __name__ == "__main__":
    app()
