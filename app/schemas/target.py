from __future__ import annotations
from pydantic import BaseModel, HttpUrl
from datetime import datetime

class TargetBase(BaseModel):
    url: HttpUrl

class TargetCreate(TargetBase):
    pass

class TargetRead(TargetBase):
    id: int
    last_scanned_at: datetime | None = None

    class Config:
        orm_mode = True
