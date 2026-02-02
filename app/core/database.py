from __future__ import annotations

from collections.abc import Iterator
from contextlib import contextmanager
from pathlib import Path

from sqlmodel import Session, SQLModel, create_engine

from .config import settings

connect_args = {"check_same_thread": False} if settings.database_url.startswith("sqlite") else {}
engine = create_engine(settings.database_url, echo=False, connect_args=connect_args)


def init_db() -> None:
    # on importe les modèles avant create_all (évite les surprises)
    try:
        from ..models import finding as _m_finding  # noqa: F401
        from ..models import scan as _m_scan  # noqa: F401
        from ..models import target as _m_target  # noqa: F401
    except Exception:
        pass
    # SQLite: on crée le dossier de la DB si besoin
    if settings.database_url.startswith("sqlite:///"):
        raw_path = settings.database_url.replace("sqlite:///", "", 1)
        # If path is relative, convert to absolute for mkdir
        path = Path(raw_path)
        if not path.is_absolute():
            path = Path.cwd() / path
        path.parent.mkdir(parents=True, exist_ok=True)
    SQLModel.metadata.create_all(engine)


@contextmanager
def get_session() -> Iterator[Session]:
    with Session(engine) as session:
        yield session
