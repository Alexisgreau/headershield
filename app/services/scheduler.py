from __future__ import annotations

from apscheduler.schedulers.asyncio import AsyncIOScheduler
from sqlmodel import select

from ..core.database import get_session
from ..models.schedule import Schedule
from .scanner import scan_urls

# This is the global scheduler instance
scheduler = AsyncIOScheduler()

async def job_scan_target(target_url: str):
    """The job that the scheduler executes."""
    print(f"⏰ Running scheduled scan for {target_url}...")
    await scan_urls([target_url])

def _cron_to_dict(cron_str: str) -> dict[str, str]:
    """Converts a cron string to a dict for APScheduler, handling wildcards."""
    parts = cron_str.split()
    if len(parts) != 5:
        # Fallback to a default if cron is invalid, or raise error
        print(f"⚠️ Invalid cron string '{cron_str}'. Job will not be scheduled.")
        raise ValueError("Cron string must have 5 parts.")
    
    keys = ["minute", "hour", "day", "month", "day_of_week"]
    return {key: val for key, val in zip(keys, parts) if val != '*'}

def load_schedules():
    """Load schedules from the database and add them to the scheduler."""
    print("🔄 Loading schedules from database...")
    try:
        with get_session() as session:
            schedules = session.exec(select(Schedule).where(Schedule.is_active == True)).all()
            for s in schedules:
                try:
                    cron_args = _cron_to_dict(s.cron)
                    scheduler.add_job(
                        job_scan_target,
                        "cron",
                        id=str(s.id),
                        name=f"Scan for {s.target.url}",
                        args=[s.target.url],
                        **cron_args
                    )
                except ValueError as e:
                    print(f"Could not schedule job for target {s.target.url}: {e}")
                except Exception as e:
                    print(f"An unexpected error occurred while scheduling job for {s.target.url}: {e}")
        print(f"✅ Loaded {len(schedules)} schedules.")
    except Exception as e:
        print(f"❌ Could not load schedules from the database: {e}")


def start_scheduler():
    """Starts the scheduler and loads the jobs."""
    if not scheduler.running:
        print("Scheduler starting...")
        scheduler.start()
        load_schedules()

def shutdown_scheduler():
    """Shuts down the scheduler."""
    if scheduler.running:
        print("Scheduler shutting down...")
        scheduler.shutdown()
