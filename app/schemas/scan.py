from __future__ import annotations

from datetime import datetime

from pydantic import BaseModel, field_validator


class ScanRequest(BaseModel):
    urls: list[str]

    @field_validator("urls")
    @classmethod
    def validate_urls_len(cls, v: list[str]) -> list[str]:
        if not v:
            raise ValueError("urls cannot be empty")
        if len(v) > 100:
            raise ValueError("maximum 100 URLs per request")
        return v


class HeaderFindingOut(BaseModel):
    header_name: str
    value: str | None
    status: str
    score_impact: int
    recommendation: str


class CookieFindingOut(BaseModel):
    cookie_name: str
    has_secure: bool
    has_httponly: bool
    samesite: str
    status: str
    recommendation: str




class HTMLFindingOut(BaseModel):
    finding_type: str
    tag: str
    details: str
    score_impact: int
    recommendation: str


class ScanOut(BaseModel):
    id: int
    target_url: str
    started_at: datetime
    finished_at: datetime | None
    score_total: int
    issues_count: int
    tls_enforced: bool
    http_to_https_redirect: bool
    status: str
    header_findings: list[HeaderFindingOut]
    cookie_findings: list[CookieFindingOut]
    html_findings: list[HTMLFindingOut]
    raw_response_meta: dict
