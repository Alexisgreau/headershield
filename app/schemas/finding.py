from __future__ import annotations
from pydantic import BaseModel

# Schemas for HeaderFinding
class HeaderFindingBase(BaseModel):
    header_name: str
    value: str | None = None
    status: str
    score_impact: int = 0
    recommendation: str = ""

class HeaderFindingCreate(HeaderFindingBase):
    pass

class HeaderFindingRead(HeaderFindingBase):
    id: int
    scan_id: int

    class Config:
        orm_mode = True

# Schemas for CookieFinding
class CookieFindingBase(BaseModel):
    cookie_name: str
    has_secure: bool = False
    has_httponly: bool = False
    samesite: str = "Unknown"
    status: str
    recommendation: str = ""

class CookieFindingCreate(CookieFindingBase):
    pass

class CookieFindingRead(CookieFindingBase):
    id: int
    scan_id: int

    class Config:
        orm_mode = True

# Schemas for HTMLFinding
class HTMLFindingBase(BaseModel):
    finding_type: str
    tag: str
    details: str
    score_impact: int = 0
    recommendation: str = ""

class HTMLFindingCreate(HTMLFindingBase):
    pass

class HTMLFindingRead(HTMLFindingBase):
    id: int
    scan_id: int

    class Config:
        orm_mode = True
