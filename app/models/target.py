from __future__ import annotations

from datetime import datetime
from typing import TYPE_CHECKING

from sqlmodel import Field, SQLModel, UniqueConstraint


class Target(SQLModel, table=True):
    __tablename__ = "targets"
    __table_args__ = (UniqueConstraint("url", name="uq_target_url"),)

    id: int | None = Field(default=None, primary_key=True)
    url: str = Field(index=True)
    last_scanned_at: datetime | None = Field(default=None, index=True)

    # relationship removed to avoid registry resolution issues; access via explicit queries


if TYPE_CHECKING:  # only for type hints
    from .scan import Scan  # noqa: F401
