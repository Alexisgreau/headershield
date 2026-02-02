from __future__ import annotations

from fastapi import APIRouter, Query
from sqlmodel import select

from ...core.database import get_session
from ...models.target import Target

router = APIRouter(prefix="/targets", tags=["targets"])


@router.get("")
def list_targets(
    q: str | None = Query(default=None),
    limit: int = 50,
    offset: int = 0,
):
    with get_session() as session:
        statement = select(Target)
        if q:
            statement = statement.where(Target.url.like(f"%{q}%"))
        all_items = session.exec(statement).all()
        total = len(all_items)
        items = all_items[offset : offset + limit]
        return {"total": total, "items": [t.model_dump() for t in items]}
