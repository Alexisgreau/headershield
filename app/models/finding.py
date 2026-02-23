from __future__ import annotations

from typing import TYPE_CHECKING

from sqlmodel import Field, SQLModel


class HeaderFinding(SQLModel, table=True):
    __tablename__ = "header_findings"

    id: int | None = Field(default=None, primary_key=True)
    scan_id: int = Field(foreign_key="scans.id", index=True)
    header_name: str = Field(index=True)
    value: str | None = Field(default=None)
    status: str = Field(index=True)  # MISSING|WEAK|OK
    score_impact: int = Field(default=0)
    recommendation: str = Field(default="")

    # child side relationship not required; parent (Scan) keeps the collection


class CookieFinding(SQLModel, table=True):
    __tablename__ = "cookie_findings"

    id: int | None = Field(default=None, primary_key=True)
    scan_id: int = Field(foreign_key="scans.id", index=True)
    cookie_name: str = Field(index=True)
    has_secure: bool = Field(default=False)
    has_httponly: bool = Field(default=False)
    samesite: str = Field(default="Unknown")  # None|Lax|Strict|Unknown
    status: str = Field(index=True)
    recommendation: str = Field(default="")

    # child side relationship not required; parent (Scan) keeps the collection


class HTMLFinding(SQLModel, table=True):
    __tablename__ = "html_findings"

    id: int | None = Field(default=None, primary_key=True)
    scan_id: int = Field(foreign_key="scans.id", index=True)
    finding_type: str = Field(index=True)  # e.g., 'mixed-content', 'sri-missing'
    tag: str
    details: str
    score_impact: int = Field(default=0)
    recommendation: str = Field(default="")


if TYPE_CHECKING:  # only for type hints
    from .scan import Scan  # noqa: F401
