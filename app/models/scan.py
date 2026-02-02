from __future__ import annotations

from datetime import datetime
from typing import TYPE_CHECKING

from sqlmodel import JSON, Column, Field, SQLModel


class Scan(SQLModel, table=True):
    __tablename__ = "scans"

    id: int | None = Field(default=None, primary_key=True)
    target_id: int = Field(foreign_key="targets.id", index=True)
    started_at: datetime = Field(default_factory=datetime.utcnow, index=True)
    finished_at: datetime | None = Field(default=None, index=True)
    score_total: int = Field(default=0, index=True)
    issues_count: int = Field(default=0)
    tls_enforced: bool = Field(default=False)
    http_to_https_redirect: bool = Field(default=False)
    status: str = Field(default="PENDING", index=True)
    raw_response_meta: dict = Field(sa_column=Column(JSON), default={})

    # relationship to Target removed; use target_id for joins
    # relationships to findings are queried explicitly to avoid registry issues


if TYPE_CHECKING:  # only for type hints, avoids circular imports at runtime
    from .finding import CookieFinding, HeaderFinding  # noqa: F401
    from .target import Target  # noqa: F401
