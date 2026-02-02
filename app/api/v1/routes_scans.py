from __future__ import annotations

from datetime import datetime

from fastapi import APIRouter, Query
from sqlmodel import select

from ...core.database import get_session
from ...models.scan import Scan

router = APIRouter(prefix="/scans", tags=["scans"])


@router.get("")
def list_scans(
    status: str | None = Query(default=None),
    min_score: int | None = Query(default=None),
    max_score: int | None = Query(default=None),
    date_from: str | None = Query(default=None),
    date_to: str | None = Query(default=None),
    limit: int = 50,
    offset: int = 0,
):
    with get_session() as session:
        stmt = select(Scan)
        if status:
            stmt = stmt.where(Scan.status == status)
        if min_score is not None:
            stmt = stmt.where(Scan.score_total >= min_score)
        if max_score is not None:
            stmt = stmt.where(Scan.score_total <= max_score)
        scans = session.exec(stmt).all()
        # naive date filter
        def in_range(s: Scan) -> bool:
            if date_from:
                try:
                    if s.started_at < datetime.fromisoformat(date_from):
                        return False
                except Exception:
                    pass
            if date_to:
                try:
                    if s.started_at > datetime.fromisoformat(date_to):
                        return False
                except Exception:
                    pass
            return True

        scans = [s for s in scans if in_range(s)]
        total = len(scans)
        items = scans[offset : offset + limit]
        return {
            "total": total,
            "items": [
                {
                    "id": s.id,
                    "target_id": s.target_id,
                    "score_total": s.score_total,
                    "status": s.status,
                    "started_at": s.started_at,
                    "finished_at": s.finished_at,
                }
                for s in items
            ],
        }


 
