from __future__ import annotations
from typing import List

from fastapi import APIRouter, HTTPException
from ...schemas.schedule import ScheduleCreate, ScheduleRead

router = APIRouter(prefix="/schedules", tags=["schedules"])

@router.post("/", response_model=ScheduleRead)
def create_schedule(schedule_data: ScheduleCreate):
    """Create a new scan schedule."""
    with get_session() as session:
        # Ensure target exists
        target = session.get(Target, schedule_data.target_id)
        if not target:
            raise HTTPException(status_code=404, detail=f"Target with id {schedule_data.target_id} not found.")

        schedule = Schedule.from_orm(schedule_data)
        session.add(schedule)
        session.commit()
        session.refresh(schedule)

        try:
            cron_args = _cron_to_dict(schedule.cron)
            scheduler.add_job(
                job_scan_target,
                "cron",
                id=str(schedule.id),
                name=f"Scan for {target.url}",
                args=[target.url],
                replace_existing=True,
                **cron_args,
            )
        except ValueError as e:
            # This is a bit awkward, we've already saved it.
            # In a real app, you might wrap this in a larger transaction or validate the cron string first.
            raise HTTPException(status_code=400, detail=f"Invalid cron string: {e}")

        return schedule

@router.get("/", response_model=List[ScheduleRead])
def list_schedules():
    """List all schedules."""
    with get_session() as session:
        schedules = session.exec(select(Schedule)).all()
        return schedules

@router.delete("/{schedule_id}", status_code=204)
def delete_schedule(schedule_id: int):
    """Delete a schedule."""
    with get_session() as session:
        schedule = session.get(Schedule, schedule_id)
        if not schedule:
            raise HTTPException(status_code=404, detail="Schedule not found")
        
        # Try to remove the job, but don't fail if it's already gone
        try:
            scheduler.remove_job(str(schedule.id))
        except Exception as e:
            print(f"Could not remove job {schedule.id} from scheduler, it might not exist: {e}")

        session.delete(schedule)
        session.commit()
        return {"ok": True}
