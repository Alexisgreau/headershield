from __future__ import annotations
from pydantic import BaseModel

class ScheduleBase(BaseModel):
    target_id: int
    cron: str # e.g., "0 2 * * *" for 2 AM daily

class ScheduleCreate(ScheduleBase):
    pass

class ScheduleRead(ScheduleBase):
    id: int

    class Config:
        orm_mode = True
