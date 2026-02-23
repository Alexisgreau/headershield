from typing import Optional
from sqlmodel import Field, Relationship, SQLModel

from typing import TYPE_CHECKING
if TYPE_CHECKING:
    from .target import Target

class Schedule(SQLModel, table=True):
    __tablename__ = "schedules"

    id: Optional[int] = Field(default=None, primary_key=True)
    target_id: int = Field(foreign_key="targets.id")
    cron: str
    is_active: bool = Field(default=True)

    target: Optional["Target"] = Relationship(back_populates="schedules")