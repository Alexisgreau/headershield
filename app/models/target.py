from typing import List, Optional
from datetime import datetime
from sqlmodel import Field, Relationship, SQLModel

from typing import TYPE_CHECKING
if TYPE_CHECKING:
    from .schedule import Schedule

class Target(SQLModel, table=True):
    __tablename__ = "targets"

    id: Optional[int] = Field(default=None, primary_key=True)
    url: str = Field(index=True, unique=True)
    created_at: datetime = Field(default_factory=datetime.utcnow)
    last_scanned_at: Optional[datetime] = None

    schedules: List["Schedule"] = Relationship(back_populates="target")